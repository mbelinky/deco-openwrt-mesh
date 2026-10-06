// SPDX-License-Identifier: MIT
// Compile fresh observations into a client-list snapshot, or a Wi-Fi incremental
// update. OEM incremental updates do not replace existing wired records.
// The optional prior observation must be the last acknowledged report,
// not merely the last collected snapshot. This CLI sends nothing and advances
// no delivery state. Wired presence means recent forwarding activity, not a
// guarantee that a silent device remains attached. Registration stays separate.
import * as fs from 'fs';

const owner='520C7831F7302242F81407BC050E7E7C4B5C697F';
function read(path, fresh) {
    let data=fs.readfile(path);
    if (!data || length(data)>1048576) die('client observation unavailable');
    let snapshot=json(data);
    let physical=snapshot?.scope=='wired-switch';
    let wired=physical || snapshot?.scope=='wired-forwarding';
    if ((!wired && snapshot?.scope!='wifi-associations') || snapshot.device_id!=owner
        || type(snapshot.observed_at)!='int' || snapshot.observed_at>time()
        || (fresh && time()-snapshot.observed_at>30)
        || type(snapshot.clients)!='array' || length(snapshot.clients)>2048
        || type(snapshot.interfaces)!='array'
        || (!length(snapshot.interfaces) && (!wired || physical || length(snapshot.clients))))
        die('invalid or stale client observation');
    if (wired && !physical && (type(snapshot.bridge)!='string'
        || !match(snapshot.bridge,/^[A-Za-z0-9_.-]{1,15}$/))) die('invalid wired observation bridge');
    let client_ports={};
    if (physical) {
        if (snapshot.switch!='rtl8367d' || length(snapshot.interfaces)!=1 || snapshot.interfaces[0]!='eth0'
            || type(snapshot.client_ports)!='array' || length(snapshot.client_ports)>3)
            die('invalid physical observation coverage');
        for (let port in snapshot.client_ports) {
            if (type(port)!='int' || port<0 || port>2 || client_ports[port]) die('invalid physical client port');
            client_ports[port]=true;
        }
    }
    let interfaces={}, clients={};
    for (let interface in snapshot.interfaces) {
        if (type(interface)!='string' || !match(interface,/^[A-Za-z0-9_.-]{1,15}$/)
            || interfaces[interface]) die('invalid observation interfaces');
        interfaces[interface]=true;
    }
    for (let row in snapshot.clients) {
        if (type(row)!='object' || type(row.mac)!='string'
            || !match(row.mac,/^[0-9A-F][02468ACE](-[0-9A-F]{2}){5}$/)
            || clients[row.mac] || row.device_id!=owner
            || !interfaces[row.interface]
            || (row.network_type!==0 && row.network_type!==1 && row.network_type!==2)
            || row.is_guest!==(row.network_type==1 ? 1 : 0)) die('invalid observed client');
        if (wired) {
            if (row.wire_type!='wired' || row.connection_type!='wired'
                || (!physical && row.bridge!=snapshot.bridge) || row.presence!='recent-traffic'
                || (physical && (!client_ports[row.physical_port] || row.network_type!==0)))
                die('invalid observed wired client');
        } else if (row.wire_type!='wireless' || type(row.association_id)!='string'
            || !length(row.association_id)
            || (row.connection_type!='band2_4' && row.connection_type!='band5'
                && row.connection_type!='band6')) die('invalid observed wireless client');
        if (row.ip!=null) {
            if (type(row.ip)!='string' || !match(row.ip,/^[0-9]{1,3}(\.[0-9]{1,3}){3}$/))
                die('invalid observed address');
            let octets=split(row.ip,'.');
            for (let octet in octets) if (+octet>255) die('invalid observed address');
            if (+octets[0]==0 || +octets[0]==127 || +octets[0]>=224
                || (+octets[0]==169 && +octets[1]==254)) die('unusable observed address');
        }
        clients[row.mac]=row;
    }
    return {snapshot,interfaces,clients};
}
let envelope=ARGV[0]=='--envelope';
let snapshot_mode=ARGV[0]=='--snapshot';
if (!ARGV[0] || length(ARGV)>2 || ((envelope || snapshot_mode) && !ARGV[1]))
    die('expected current and optional previous observation, or --envelope/--snapshot current');
let current=read(ARGV[envelope || snapshot_mode ? 1 : 0],true);
if (current.snapshot.scope!='wifi-associations' && !snapshot_mode)
    die('wired clients require full snapshots; OEM incremental updates duplicate wired records');
let previous=!envelope && !snapshot_mode && ARGV[1] ? read(ARGV[1],false) : null;
if (previous) {
    if (previous.snapshot.scope!=current.snapshot.scope
        || previous.snapshot.bridge!=current.snapshot.bridge) die('client observation scope changed');
    if (previous.snapshot.observed_at>current.snapshot.observed_at)
        die('client observation moved backwards');
    if (length(previous.interfaces)!=length(current.interfaces)) die('client observation scope changed');
    for (let interface in keys(previous.interfaces))
        if (!current.interfaces[interface]) die('client observation scope changed');
}
let conn_list=[], disconn_list=[];
for (let mac,row in current.clients) {
    // Omit unknown values instead of inventing a hostname, signal or IP. The
    // stock receiver clears the preceding IP when an update omits that field.
    let report={mac,device_id:owner,wire_type:row.wire_type,
        connection_type:row.connection_type,is_guest:row.is_guest,network_type:row.network_type};
    if (row.ip && !row.address_conflict && type(row.address_seen_at)=='int'
        && row.address_seen_at<=current.snapshot.observed_at
        && time()-row.address_seen_at<=300) report.ip=row.ip;
    push(conn_list,report);
}
for (let mac,row in previous?.clients ?? {})
    if (!current.clients[mac]) push(disconn_list,{mac,device_id:owner});
let params={conn_list,disconn_list};
print(sprintf('%J\n',snapshot_mode ? {scope:current.snapshot.scope,device_id:owner,
    observed_at:current.snapshot.observed_at,interfaces:current.snapshot.interfaces,client_list:conn_list}
    : envelope ? {scope:current.snapshot.scope,device_id:owner,
    observed_at:current.snapshot.observed_at,interfaces:current.snapshot.interfaces,params} : params));

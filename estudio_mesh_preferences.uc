// SPDX-License-Identifier: MIT
// Reconcile manual Deco connection preferences with native hostapd admission.
// Input is an owner-written settings/peer snapshot, never a controller command.
// The native supervisor must re-run this on peer/config/radio changes and expiry.
// This CLI is not installed as a service or advertised as a complete capability.
import * as fs from 'fs';
import { storage_ok } from './estudio_mesh_storage.uc';
import * as ubus from 'ubus';
import * as uci from 'uci';

function require_ok(ok, message) { if (!ok) die(message); }
function read_json(path) {
    let data=fs.readfile(path);
    require_ok(data && length(data)<=131072, 'preference input unavailable');
    let value=json(data);
    require_ok(type(value)=='object', 'invalid preference input');
    return value;
}
function device(value) {
    require_ok(type(value)=='string' && match(value,/^[0-9A-Fa-f]{40}$/), 'invalid preferred device');
    return value;
}
function address(value) {
    require_ok(type(value)=='string' && match(value,/^[0-9a-f][02468ace](:[0-9a-f]{2}){5}$/), 'invalid preference MAC');
    return value;
}
function addresses(values) {
    require_ok(type(values)=='array' && length(values)<=1024, 'invalid preference address list');
    let out=[], seen={};
    for (let value in values) {
        address(value);
        require_ok(!seen[value], 'duplicate preference MAC');
        seen[value]=true; push(out,value);
    }
    sort(out); return out;
}
require_ok(length(ARGV)>=1 && length(ARGV)<=2, 'usage: preferences.uc INPUT [AP_CONTEXT]');
let input=read_json(ARGV[0]), local_id=device(input.device_id);
require_ok(type(input.client_preferences)=='array' && length(input.client_preferences)<=1024,
    'invalid client preferences');
require_ok(type(input.online_nodes)=='array' && length(input.online_nodes)<=512
    && type(input.online_nodes_expires)=='int' && input.online_nodes_expires<=time()+300,
    'invalid peer availability');
let peers={};
for (let value in input.online_nodes) peers[device(value)]=true;
let fresh=input.online_nodes_expires>time(), clients={};
for (let row in input.client_preferences) {
    require_ok(type(row)=='object', 'invalid client preference');
    let mac=address(row.mac);
    require_ok(!clients[mac] && type(row.mesh_enabled)=='bool', 'invalid duplicate/mesh preference');
    if (row.preferred_node!=null) device(row.preferred_node);
    require_ok(row.preferred_band==null || index(['band2_4','band5','band6'],row.preferred_band)>=0,
        'invalid preferred band');
    clients[mac]=row;
}
let bus=ubus.connect();
require_ok(bus, 'native preference bus unavailable');
let context;
if (ARGV[1]) context=read_json(ARGV[1]);
else {
    require_ok(trim(fs.readfile('/sys/class/net/eth0/address') ?? '')=='02:00:00:00:00:19'
        && local_id=='520C7831F7302242F81407BC050E7E7C4B5C697F'
        && storage_ok(), 'unexpected preference device');
    let config=uci.cursor('/etc/config').get_all('wireless');
    let runtime=bus.call('network.wireless','status',{});
    require_ok(type(config)=='object' && type(runtime)=='object', 'wireless state unavailable');
    let sections=['default_radio0','test5','default_radio2','dec_iso2','dec_iso5','dec_iso6',
        'deco_iot2','deco_iot5','dec_ioti2','dec_ioti5','deco_guest2','deco_guest5','deco_guest6'];
    context={control_path:'/var/run/hostapd',aps:[]};
    for (let name in sections) {
        let ap=config[name];
        if (!ap || ap.disabled=='1' || config[ap.device]?.disabled=='1') continue;
        require_ok(ap.mode=='ap' && ap['.type']=='wifi-iface', 'unexpected preference AP');
        let radio=runtime[ap.device], interface;
        require_ok(radio?.up && !radio.pending, 'wireless transition in progress');
        for (let candidate in radio.interfaces ?? []) if (candidate.section==name) {
            require_ok(!interface, 'ambiguous preference AP'); interface=candidate.ifname;
        }
        require_ok(interface && !ap.macfile, 'preference AP unavailable or unmanaged access file');
        push(context.aps,{interface,macfilter:ap.macfilter ?? 'deny',maclist:ap.maclist ?? []});
    }
}
require_ok(type(context.aps)=='array' && length(context.aps)>0 && length(context.aps)<=16
    && type(context.control_path)=='string' && length(context.control_path)<=200
    && match(context.control_path,/^\/[A-Za-z0-9_./-]+$/), 'invalid preference AP context');
let path=context.control_path;
function control(iface, command) {
    // Interface/path and all command components are independently constrained.
    let pipe=fs.popen('/usr/sbin/wpa_cli -p '+path+' -i '+iface+' raw '+command, 'r');
    require_ok(pipe, 'hostapd preference control unavailable');
    let data=trim(pipe.read('all') ?? ''), code=pipe.close();
    require_ok(code==0 && !match(data,/(^|\n)(FAIL|UNKNOWN COMMAND|Could not connect)/), 'hostapd preference command failed');
    return data;
}
function acl(iface, kind) {
    let rows=[];
    for (let line in split(control(iface,kind+' SHOW'),'\n')) {
        if (!length(line)) continue;
        let parsed=match(line,/^([0-9a-f]{2}(:[0-9a-f]{2}){5})( VLAN_ID=0)?$/);
        require_ok(parsed, 'unsupported hostapd admission entry'); push(rows,parsed[1]);
    }
    return addresses(rows);
}
function reconcile(iface, kind, desired) {
    let current=acl(iface,kind);
    for (let mac in current) if (index(desired,mac)<0)
        require_ok(control(iface,kind+' DEL_MAC '+mac)=='OK', 'hostapd admission delete failed');
    for (let mac in desired) if (index(current,mac)<0)
        require_ok(control(iface,kind+' ADD_MAC '+mac)=='OK', 'hostapd admission add failed');
    require_ok(sprintf('%J',acl(iface,kind))==sprintf('%J',desired), 'hostapd admission verification failed');
}
// Validate every AP and snapshot both lists before the first mutation. Keep the
// configured isolation lists; preferences can only further restrict admission.
let operations=[], interfaces={};
for (let ap in context.aps) {
    require_ok(type(ap)=='object' && type(ap.interface)=='string'
        && match(ap.interface,/^[A-Za-z0-9_.-]{1,15}$/) && !interfaces[ap.interface]
        && index(['allow','deny'],ap.macfilter)>=0, 'invalid preference AP');
    interfaces[ap.interface]=true;
    let baseline=addresses(ap.maclist);
    let status=bus.call('hostapd.'+ap.interface,'get_status',{});
    require_ok(status?.status=='ENABLED' && type(status.freq)=='int', 'preference AP not ready');
    let band=status.freq>=2412 && status.freq<=2484 ? 'band2_4'
        : status.freq>=5180 && status.freq<=5885 ? 'band5'
        : status.freq>=5955 && status.freq<=7115 ? 'band6' : null;
    require_ok(band, 'unsupported preference frequency');
    let blocked=[];
    for (let mac,row in clients) {
        let remote=row.preferred_node!=null && row.preferred_node!=local_id;
        // Verified against the original NRD policy: a missing preferred remote
        // node suspends its band preference as well. Mesh-off still allows
        // explicit manual restrictions; it excludes automatic steering only.
        if (remote && (!fresh || !peers[row.preferred_node])) continue;
        if (remote || (row.preferred_band!=null && row.preferred_band!=band)) push(blocked,mac);
    }
    let allow=[],deny=[];
    for (let mac in baseline) {
        if (ap.macfilter=='deny') push(deny,mac);
        else if (index(blocked,mac)<0) push(allow,mac);
    }
    for (let mac in blocked) if (index(deny,mac)<0) push(deny,mac);
    sort(allow); sort(deny);
    push(operations,{interface:ap.interface,allow,deny,blocked,
        before_allow:acl(ap.interface,'ACCEPT_ACL'),before_deny:acl(ap.interface,'DENY_ACL')});
}
try {
    for (let op in operations) {
        reconcile(op.interface,'ACCEPT_ACL',op.allow);
        reconcile(op.interface,'DENY_ACL',op.deny);
        let stations=bus.call('hostapd.'+op.interface,'get_clients',{});
        require_ok(type(stations?.clients)=='object', 'preference station state unavailable');
        for (let mac in op.blocked) if (stations.clients[mac])
            require_ok(control(op.interface,'DEAUTHENTICATE '+mac)=='OK', 'preference disconnect failed');
    }
} catch (error) {
    let restored=true;
    for (let op in operations) try {
        reconcile(op.interface,'ACCEPT_ACL',op.before_allow);
        reconcile(op.interface,'DENY_ACL',op.before_deny);
    } catch (restore_error) { restored=false; }
    die('preference reconciliation failed; admission restored='+restored+': '+error);
}
printf('%J\n',{ap_count:length(operations),peer_snapshot_current:fresh,manual_preferences_reconciled:true});

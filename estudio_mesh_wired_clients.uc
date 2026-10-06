// SPDX-License-Identifier: MIT
// Read bridge forwarding evidence only on explicitly classified client ports.
// A learned MAC is evidence of recent traffic, not proof that a quiet device is
// still connected. This is not yet a complete wired-presence/controller report.
import * as fs from 'fs';
import * as rtnl from 'rtnl';
import { observe } from './estudio_mesh_client_addresses.uc';

let raw=ARGV[0] ? fs.readfile(ARGV[0]) : null;
if (!raw || length(raw)>65536) die('wired port context unavailable');
let context=json(raw), ports={};
function hardware_clients(context) {
    if (context.device_id!='520C7831F7302242F81407BC050E7E7C4B5C697F'
        || context.switch!='rtl8367d' || context.interface!='eth0' || context.network_type!==0
        || type(context.ports)!='array' || length(context.ports)!=4
        || (ARGV[1] && ARGV[1]!='observe') || length(ARGV)>2
        || trim(fs.readfile('/sys/class/net/eth0/address') ?? '')!='02:00:00:00:00:19')
        die('invalid physical switch context');
    let roles={}, client_ports=[];
    for (let port in context.ports) {
        if (type(port?.port)!='int' || (port.port!=0 && port.port!=1 && port.port!=2 && port.port!=6)
            || roles[port.port] || (port.port==6 ? port.role!='cpu'
                : (port.role!='client' && port.role!='uplink'))) die('invalid physical port role');
        roles[port.port]=port.role;
        if (port.role=='client') push(client_ports,port.port);
    }
    let boot=trim(fs.readfile('/proc/sys/kernel/random/boot_id') ?? '');
    if (!length(boot)) die('physical switch boot identity unavailable');
    function inventory() {
        let data=fs.readfile('/sys/kernel/debug/estudio_switch_observe/snapshot');
        if (!data || length(data)>32768) die('physical switch observation unavailable');
        let state=json(data), links={}, clients={}, local_macs={}, generations={};
        if (state?.version!==1 || state.chip_id!==0x6642 || state.complete!==true
            || type(state.observed_at)!='int' || state.observed_at>time() || time()-state.observed_at>5
            || type(state.ports)!='array' || length(state.ports)!=4
            || type(state.entries)!='array' || length(state.entries)>64)
            die('invalid or incomplete physical switch observation');
        let index=trim(fs.readfile('/sys/class/net/eth0/ifindex') ?? '');
        if (!length(index)) die('physical CPU interface unavailable');
        generations.eth0=boot+':'+index;
        for (let port in state.ports) {
            if (!roles[port.id] || links[port.id] || type(port.link)!='bool') die('unexpected physical port');
            links[port.id]=port;
            generations['port'+port.id]=boot+':'+index+':'+roles[port.id]+':'+port.link;
        }
        if (!links[6]?.link) die('physical CPU link unavailable');
        for (let name in fs.lsdir('/sys/class/net')) {
            let mac=fs.readfile('/sys/class/net/'+name+'/address');
            if (mac) local_macs[uc(replace(trim(mac),':','-'))]=true;
        }
        for (let entry in state.entries) {
            if (type(entry.mac)!='string' || !match(entry.mac,/^[0-9a-f][02468ace](:[0-9a-f]{2}){5}$/)
                || type(entry.port)!='int' || !roles[entry.port] || type(entry.static)!='bool'
                || type(entry.age)!='int' || entry.age<0 || entry.age>7)
                die('invalid physical forwarding entry');
            let mac=uc(replace(entry.mac,':','-'));
            if (local_macs[mac] || roles[entry.port]!='client' || !links[entry.port].link
                || entry.static || !entry.age) continue;
            // Only the observed bootloader's untagged forwarding domain is
            // supported. VLAN membership/control must precede guest claims.
            if (entry.ivl!==false || entry.vid_fid!==0) die('unsupported physical client VLAN');
            if (clients[mac]) die('ambiguous physical client location');
            clients[mac]={mac,device_id:context.device_id,interface:'eth0',physical_port:entry.port,
                wire_type:'wired',connection_type:'wired',network_type:0,is_guest:0,
                ip:null,presence:'recent-traffic'};
        }
        return {clients,generations};
    }
    let first=inventory();
    if (ARGV[1]=='observe') {
        let authorized={};
        for (let mac in keys(first.clients)) authorized[mac]=true;
        let addresses=observe('eth0',authorized);
        for (let mac,row in first.clients) if (addresses[mac]) {
            row.address_conflict=addresses[mac].conflict;
            if (!row.address_conflict) { row.ip=addresses[mac].ip; row.address_seen_at=time(); }
        }
    }
    let last=inventory();
    if (length(first.clients)!=length(last.clients)) die('physical clients changed during observation');
    for (let mac,row in first.clients)
        if (last.clients[mac]?.physical_port!=row.physical_port) die('physical client moved during observation');
    for (let port,generation in first.generations)
        if (last.generations[port]!=generation) die('physical port changed during observation');
    return {scope:'wired-switch',switch:'rtl8367d',device_id:context.device_id,interfaces:['eth0'],
        client_ports,port_generations:first.generations,observed_at:time(),ready_for_controller:false,
        pending:['quiet-client-presence','physical-switch-port-control'],clients:values(first.clients)};
}
if (context?.switch) {
    print(sprintf('%J\n',hardware_clients(context)));
    exit(0);
}
if (context?.device_id!='520C7831F7302242F81407BC050E7E7C4B5C697F'
    || type(context.bridge)!='string' || !match(context.bridge,/^[A-Za-z0-9_.-]{1,15}$/)
    || type(context.ports)!='array' || !length(context.ports) || length(context.ports)>32
    || (context.network_type!==0 && context.network_type!==1 && context.network_type!==2)
    || (ARGV[1] && ARGV[1]!='observe') || length(ARGV)>2) die('invalid wired port context');
for (let port in context.ports) {
    if (type(port?.interface)!='string' || !match(port.interface,/^[A-Za-z0-9_.-]{1,15}$/)
        || ports[port.interface] || (port.role!='client' && port.role!='uplink' && port.role!='wifi' && port.role!='management'))
        die('invalid wired port role');
    ports[port.interface]=port;
}
function dump(op, data) {
    let rows=rtnl.request(op,rtnl.const.NLM_F_DUMP,data), error=rtnl.error();
    if (rows==null && error==null) return [];
    if (type(rows)!='array' || error!=null) die('bridge observation unavailable');
    return rows;
}
function inventory() {
    let links={}, local_macs={}, generations={};
    for (let link in dump(rtnl.const.RTM_GETLINK,{})) {
        links[link.dev]=link;
        if (link.address) local_macs[uc(replace(link.address,':','-'))]=true;
    }
    let bridge=links[context.bridge];
    if (bridge?.linkinfo?.type!='bridge' || !(bridge.flags & 1)) die('client bridge unavailable');
    if (bridge.linkinfo.vlan_filtering!==0) die('VLAN-filtered wired collection not implemented');
    for (let name,port in ports) {
        if (links[name]?.master!=context.bridge) die('bridge membership changed');
        let index=fs.readfile('/sys/class/net/'+name+'/ifindex');
        if (!index) die('wired port generation unavailable');
        generations[name]=trim(index);
    }
    for (let name,link in links)
        if (link.master==context.bridge && !ports[name]) die('unclassified bridge port');
    let learned={};
    for (let row in dump(rtnl.const.RTM_GETNEIGH,{family:rtnl.const.AF_BRIDGE})) {
        if (row.master!=context.bridge || !ports[row.dev] || row.flags & rtnl.const.NTF_SELF
            || row.state & (rtnl.const.NUD_PERMANENT | rtnl.const.NUD_NOARP)
            || row.state!=rtnl.const.NUD_REACHABLE || type(row.lladdr)!='string') continue;
        let mac=uc(replace(row.lladdr,':','-'));
        if (!match(mac,/^[0-9A-F][02468ACE](-[0-9A-F]{2}){5}$/) || local_macs[mac]) continue;
        if (row.vlan && row.vlan!=bridge.linkinfo.vlan_default_pvid)
            die('unexpected client forwarding VLAN');
        if (learned[mac] && learned[mac]!=row.dev) die('ambiguous wired client location');
        learned[mac]=row.dev;
    }
    let clients={};
    for (let mac,interface in learned) {
        let link=links[interface];
        if (ports[interface].role!='client' || !link.carrier || !(link.flags & 1)) continue;
        clients[mac]={mac,device_id:context.device_id,interface,bridge:context.bridge,
            wire_type:'wired',connection_type:'wired',network_type:context.network_type,
            is_guest:context.network_type==1 ? 1 : 0,ip:null,presence:'recent-traffic'};
    }
    return {clients,links,generations};
}
let first=inventory();
if (ARGV[1]=='observe') {
    for (let name,port in ports) {
        if (port.role!='client') continue;
        let authorized={};
        for (let mac,row in first.clients) if (row.interface==name) authorized[mac]=true;
        let addresses=observe(name,authorized);
        for (let mac,row in first.clients) {
            if (row.interface!=name || !addresses[mac]) continue;
            row.address_conflict=addresses[mac].conflict;
            if (!row.address_conflict) { row.ip=addresses[mac].ip; row.address_seen_at=time(); }
        }
    }
}
let last=inventory();
for (let name,generation in first.generations)
    if (last.generations[name]!=generation) die('wired port replaced during observation');
if (length(first.clients)!=length(last.clients)) die('wired clients changed during observation');
for (let mac,row in first.clients) {
    if (last.clients[mac]?.interface!=row.interface
        || first.links[row.interface].address!=last.links[row.interface].address)
        die('wired client moved during observation');
}
let interfaces=[];
for (let name,port in ports) if (port.role=='client') push(interfaces,name);
sort(interfaces);
print(sprintf('%J\n',{scope:'wired-forwarding',device_id:context.device_id,interfaces,port_generations:first.generations,
    observed_at:time(),bridge:context.bridge,ready_for_controller:false,
    pending:['quiet-client-presence','physical-switch-port-control','wired-controller-reporting'],
    clients:values(first.clients)}));

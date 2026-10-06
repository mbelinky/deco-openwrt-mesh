// SPDX-License-Identifier: MIT
// Classify the active mesh bridge from native state. The existing Ethernet
// recovery network and the node's management endpoint are not mesh clients.
import * as fs from 'fs';
import { storage_ok } from './estudio_mesh_storage.uc';
import * as uci from 'uci';
function need(value,message) { if (!value) die(message); }
need(trim(fs.readfile('/sys/class/net/eth0/address'))=='02:00:00:00:00:19','wrong spare');
need(storage_ok(),'flash is accessible');
need(length(ARGV)==2,'expected Wi-Fi context and wired context destination');
let wifi=json(fs.readfile(ARGV[0]));
need(wifi.device_id=='520C7831F7302242F81407BC050E7E7C4B5C697F','wrong client owner');
let aps={};
for (let ap in wifi.aps) aps[ap.interface]=true;
let config=uci.cursor('/etc/config');
function uplink(name) {
    let section=name=='sixbh.1' ? 'sixbh_vlan' : name=='standby.1' ? 'sixdual_vlan' : null;
    if (!section) return false;
    let device=name=='sixbh.1' ? 'deco-sixsta' : 'deco-standby';
    let vlan=config.get_all('network',section);
    need(vlan?.['.type']=='device' && vlan.type=='8021q' && vlan.name==name
        && vlan.ifname==device && vlan.vid=='1'
        && fs.stat('/sys/class/net/'+name+'/lower_'+device),'invalid native mesh uplink');
    if (name=='standby.1') need(config.get('wireless','deco_backhaul','deco_multilink')=='1'
        && config.get('network','sixdual','proto')=='none'
        && config.get('network','sixdual','device')==name,'secondary link is not native-owned');
    return true;
}
function relay(name) {
    if (name!='decorelay.1') return false;
    need(fs.stat('/sys/class/net/br-decorelay/bridge')
        && !fs.stat('/sys/class/net/br-decorelay/master'),'invalid native relay bridge');
    for (let vid in [1,2]) {
        let port='decorelay.'+vid, bridge=vid==1 ? 'br-sixbh' : 'br-sixguest';
        let layout=fs.readfile('/proc/net/vlan/'+port) ?? '';
        let tag=match(layout,/VID: *([0-9]+)\s/);
        need(tag && int(tag[1])==vid
            && fs.stat('/sys/class/net/'+port+'/lower_br-decorelay')
            && fs.stat('/sys/class/net/'+bridge+'/brif/'+port),'invalid native relay VLAN');
    }
    // The collector's uplink role means mesh transport, excluded from this
    // node's own clients. Its learned devices belong to the downstream Deco.
    return true;
}
let ports=[];
for (let name in fs.lsdir('/sys/class/net/br-sixbh/brif') ?? []) {
    let role=aps[name] ? 'wifi' : uplink(name) || relay(name) ? 'uplink'
        : name=='sixbh-client' ? 'management' : null;
    if (name=='mesh-report') {
        need(fs.stat('/tmp/codex-mesh-join/private/report-client-owned')
            && fs.stat('/var/run/netns/codex-mesh-report'),'report client is not runtime-owned');
        role='client';
    }
    need(role,'unclassified mesh bridge port');
    push(ports,{interface:name,role});
}
need(length(ports)>=3,'mesh bridge incomplete');
need(fs.readlink('/sys/class/net/eth0/master')!='/sys/devices/virtual/net/br-sixbh'
    && !fs.stat('/sys/class/net/br-sixbh/brif/eth0'),'recovery Ethernet joined mesh');
need(fs.writefile(ARGV[1],sprintf('%J',{device_id:wifi.device_id,
    bridge:'br-sixbh',network_type:0,ports})),'cannot publish wired context');

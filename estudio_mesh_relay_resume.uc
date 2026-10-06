// SPDX-License-Identifier: MIT
// Bounded resumption of an already admitted relay, under the backhaul owner.
// No discovery, credentials, foreign interfaces or stock settings are changed.
import * as fs from 'fs';
import { storage_ok } from './estudio_mesh_storage.uc';
import * as ubus from 'ubus';
import * as uci from 'uci';
import * as rtnl from 'rtnl';
let root='/tmp/estudio-mesh-relay';
let retry_path='/tmp/estudio-mesh-resident/control/relay-retry.json';
let inputs=['ap.conf','ap2.conf','allow','allow2'];
function require_ok(value, reason) { if(!value) die(reason); }
function safe(path, kind) {
    let st=fs.lstat(path);
    require_ok(st?.type==kind && st.uid==0 && !st.perm.group_write && !st.perm.other_write,
        'unsafe relay input');
    return st;
}
function read(path) { safe(path,'file'); return fs.readfile(path); }
function run(command) {
    let p=fs.popen(command+' 2>/dev/null'); require_ok(p,'relay command unavailable');
    let output=p.read('all'); require_ok(p.close()==0,'relay command failed');
    return output;
}
function index(name) { return int(trim(fs.readfile('/sys/class/net/'+name+'/ifindex') ?? '0')); }
function config(name) {
    let conf={};
    for(let line in split(read(root+'/'+name),'\n')) {
        let m=match(line,/^([^=]+)=(.*)$/); if(!m)continue;
        require_ok(!(m[1] in conf),'duplicate relay setting');conf[m[1]]=m[2];
    }
    return conf;
}
function station(iface) {
    iface=iface ?? 'deco-sixsta';
    require_ok(iface=='deco-sixsta' || iface=='deco-standby','unsupported relay station');
    let state={};
    for(let line in split(run('wpa_cli -p /var/run/wpa_supplicant -i '+iface+' status'),'\n')) {
        let m=match(line,/^(bssid|freq|wpa_state|key_mgmt)=(.*)$/);if(m)state[m[1]]=m[2];
    }
    return state;
}
function admitted() {
    safe(root,'directory');
    let owner=json(read(root+'/owner.json'));let token=trim(read(root+'/owner'));
    require_ok(owner.version==2 && match(token,/^[0-9a-f]{32}$/) && owner.token==token
        && owner.boot_id==trim(fs.readfile('/proc/sys/kernel/random/boot_id'))
        && owner.ap_bssid=='02:00:00:00:00:21' && owner.ap2_bssid=='02:00:00:00:00:20'
        && owner.parent_bssid=='02:00:00:00:00:15','relay identity differs');
    require_ok(type(owner.original_main_mask)=='int' && owner.original_main_mask>=0
        && owner.original_main_mask<=65535 && owner.interfaces.upstream==index('br-sixbh')
        && index('br-sixguest')>0,'relay upstream changed');
    let ssid=trim(run('uci -q get wireless.deco_backhaul.ssid'));let hex='';
    for(let i=0;i<length(ssid);i++)hex+=sprintf('%02x',ord(substr(ssid,i,1)));
    let key=trim(run('uci -q get wireless.deco_backhaul.key'));
    let five=config('ap.conf'),two=config('ap2.conf');
    let base={driver:'nl80211',ctrl_interface:'/var/run/hostapd',country_code:'ES',
        wpa:'2',wpa_key_mgmt:'WPA-PSK',rsn_pairwise:'CCMP',wds_sta:'1',
        bridge:'br-decorelay',wds_bridge:'br-decorelay',macaddr_acl:'1',
        ignore_broadcast_ssid:'1',ssid2:hex,wpa_passphrase:key};
    for(let field in base)require_ok(five[field]==base[field] && two[field]==base[field],
        'relay credentials or security changed');
    require_ok(length(ssid)>0 && length(key)>=8 && length(key)<=63
        && five.interface=='deco-r5' && five.bssid==owner.ap_bssid && five.hw_mode=='a' && five.channel=='48'
        && two.interface=='deco-r2' && two.bssid==owner.ap2_bssid && two.hw_mode=='g'
        && two.channel==trim(run('uci -q get wireless.radio0.channel'))
        && int(two.channel)>=1 && int(two.channel)<=13
        && trim(run('uci -q get wireless.radio0.country'))=='ES'
        && trim(run('uci -q get wireless.radio1.country'))=='ES'
        && trim(run('uci -q get wireless.radio1.txpower'))=='10'
        && five.accept_mac_file==root+'/allow' && two.accept_mac_file==root+'/allow2'
        && trim(read(root+'/allow'))=='02:00:00:00:00:22'
        && trim(read(root+'/allow2'))=='02:00:00:00:00:23','relay radio or admission changed');
    let ie=five.vendor_elements;
    let group=substr(run('printf %s "$(jsonfilter -i /tmp/oem-mesh-peer/private/group-info -e @.gid)" | md5sum'),0,32);
    require_ok(match(ie,/^[0-9a-f]{120}$/)
        && two.vendor_elements==substr(ie,0,76)+'0000'+substr(ie,80)
        && five.assocresp_elements==ie && two.assocresp_elements==two.vendor_elements
        && substr(ie,72,4)=='010a'
        && int(substr(ie,76,2),16)+256*int(substr(ie,78,2),16)>0
        && substr(ie,0,12)=='dd3a001d0f01' && substr(ie,16,2)=='01'
        && substr(ie,18,12)=='020000000013' && substr(ie,30,32)==group
        && substr(ie,104,12)=='020000000019','relay mesh identity changed');
    return owner;
}
function hashes() {
    let result={};for(let name in inputs)result[name]=substr(run('sha256sum '+root+'/'+name),0,64);
    return result;
}
function store(name,value) {
    require_ok(!fs.lstat(root+'/'+name+'.new'),'foreign relay checkpoint');
    require_ok(fs.writefile(root+'/'+name+'.new',sprintf('%J',value)),'relay checkpoint failed');
    require_ok(fs.chmod(root+'/'+name+'.new',0600) && fs.rename(root+'/'+name+'.new',root+'/'+name),
        'relay checkpoint commit failed');
}
function reconcile_child_path(owner,permitted) {
    // Mesh control can relay a node's source MAC through Main. An actually
    // authorized child has a stronger location than that indirect learning.
    let mac='02:00:00:00:00:18',port='decorelay.1';
    let c=uci.cursor('/tmp/codex-mesh-join/private/adapter-decoded/config');
    let selected=permitted!==false && c.get('device_prefer','5355353F82EA7AF944FFF5582BFE58BA00CA10BF','prefer_connect_device')
        =='520C7831F7302242F81407BC050E7E7C4B5C697F';
    let authorized=false,bus=ubus.connect();
    for(let ap in ['deco-r5','deco-r2']) {
        let peer=ap=='deco-r5' ? '02:00:00:00:00:22' : '02:00:00:00:00:23';
        let row=bus.call('hostapd.'+ap,'get_clients',{})?.clients?.[peer];
        if(!row?.authorized || !row?.wds)continue;
        for(let name in fs.lsdir('/sys/class/net/br-decorelay/brif')??[]) {
            if(!match(name,ap=='deco-r5' ? /^deco-r5\.sta[0-9]{1,4}$/ : /^deco-r2\.sta[0-9]{1,4}$/))continue;
            require_ok(trim(fs.readfile('/sys/class/net/'+name+'/address'))==(ap=='deco-r5' ? owner.ap_bssid : owner.ap2_bssid)
                && match(run('iw dev '+name+' info'),/type AP\/VLAN\n/),'child VLAN identity changed');
            authorized=true;
        }
    }
    let rows=rtnl.request(rtnl.const.RTM_GETNEIGH,rtnl.const.NLM_F_DUMP,{family:rtnl.const.AF_BRIDGE});
    require_ok(rtnl.error()==null && (rows==null || type(rows)=='array'),'child forwarding read unavailable');
    let owned=false;
    for(let row in rows??[]) {
        if(row.master!='br-sixbh' || lc(row.lladdr??'')!=mac)continue;
        if(row.state==rtnl.const.NUD_NOARP && row.dev==port && !(row.flags & rtnl.const.NTF_SELF))owned=true;
        else require_ok(!(row.state & (rtnl.const.NUD_NOARP|rtnl.const.NUD_PERMANENT)),'foreign child forwarding entry');
    }
    let bind=selected && authorized;
    if(bind==owned)return;
    require_ok(index(port)==owner.interfaces.main,'child trunk generation changed');
    rtnl.request(bind ? rtnl.const.RTM_NEWNEIGH : rtnl.const.RTM_DELNEIGH,
        bind ? rtnl.const.NLM_F_CREATE|rtnl.const.NLM_F_REPLACE : 0,
        {family:rtnl.const.AF_BRIDGE,dev:port,master:'br-sixbh',lladdr:mac,
            flags:rtnl.const.NTF_MASTER,state:rtnl.const.NUD_NOARP});
    require_ok(rtnl.error()==null,'child forwarding update failed');
}
function clear_retry() {
    if(!fs.lstat(retry_path))return;
    let value=json(read(retry_path));
    require_ok(value.owner=='520C7831F7302242F81407BC050E7E7C4B5C697F'
        && value.boot_id==trim(fs.readfile('/proc/sys/kernel/random/boot_id')),
        'foreign controller retry');
    require_ok(fs.unlink(retry_path),'cannot withdraw controller retry');
}
function publish_retry(owner,lease) {
    let initial=owner.mode=='service' && owner.generation==0 && owner.provisioning==false && owner.created_at>0;
    let ready=initial ? time()-owner.created_at>=45
        : owner.generation>0 && owner.recovered_at>0 && time()-owner.recovered_at>=30;
    if(!ready) {
        clear_retry();return;
    }
    let bus=ubus.connect();require_ok(bus,'relay stations unavailable');
    let five=bus.call('hostapd.deco-r5','get_clients',{});
    let two=bus.call('hostapd.deco-r2','get_clients',{});
    require_ok(type(five?.clients)=='object' && type(two?.clients)=='object','relay stations unreadable');
    let a=five.clients['02:00:00:00:00:22'],b=two.clients['02:00:00:00:00:23'];
    if((a?.authorized && a?.wds) || (b?.authorized && b?.wds)) { clear_retry();return; }
    let configuration_version;
    if(initial) {
        let runtime='/tmp/codex-mesh-join/private';
        let committed=json(read(runtime+'/adapter-committed.json'));
        let staged=json(read(runtime+'/adapter-staged.json'));
        let node=json(read(runtime+'/node-state.json'));
        let preferred=uci.cursor(runtime+'/adapter-decoded/config').get('device_prefer',
            '5355353F82EA7AF944FFF5582BFE58BA00CA10BF','prefer_connect_device');
        if(!committed.configuration_stored || !committed.wireless_applied
            || committed.version!=staged.version
            || type(committed.version)!='string' || !match(committed.version,/^[0-9.]{1,64}$/)
            || !node.configuration_verified || !node.mesh_connected || !node.internet_online
            || node.device_id!='520C7831F7302242F81407BC050E7E7C4B5C697F' || node.boot_id!=owner.boot_id
            || type(node.observed_at)!='int'
            || node.observed_at>time() || time()-node.observed_at>15
            || preferred!='520C7831F7302242F81407BC050E7E7C4B5C697F') {
            clear_retry();return;
        }
        configuration_version=committed.version;
    }
    safe('/tmp/estudio-mesh-resident/control','directory');
    let ticket={version:1,owner:'520C7831F7302242F81407BC050E7E7C4B5C697F',
        target:'5355353F82EA7AF944FFF5582BFE58BA00CA10BF',token:owner.token,
        generation:owner.generation,kind:initial ? 'initial' : 'recovery',
        configuration_version,nonce:owner.token+':'+owner.generation,
        boot_id:owner.boot_id,expires_at:lease.expires_at,updated_at:time()};
    require_ok(!fs.lstat(retry_path+'.new'),'foreign controller checkpoint');
    require_ok(fs.writefile(retry_path+'.new',sprintf('%J',ticket))
        && fs.chmod(retry_path+'.new',0600) && fs.rename(retry_path+'.new',retry_path),
        'controller retry checkpoint failed');
}
require_ok(trim(fs.readfile('/sys/class/net/eth0/address'))=='02:00:00:00:00:19'
    && storage_ok(),'not the RAM spare');
let action=ARGV[0] ?? '';
if(action=='retire' || action=='retire-unarmed' || action=='retire-restored') {
    // Shutdown owns only a closed standalone service registration. The live
    // harness has its own cleanup and must retain its independent deadline.
    require_ok(trim(fs.readfile('/sys/class/net/eth0/address'))=='02:00:00:00:00:19'
        && storage_ok(),'wrong RAM spare');
    if(!fs.lstat(root)) { print('{"retired":false,"absent":true}\n');exit(0); }
    safe(root,'directory');
    let owner=json(read(root+'/owner.json')),token=trim(read(root+'/owner'));
    require_ok(owner.version==2 && owner.mode=='service'
        && owner.boot_id==trim(fs.readfile('/proc/sys/kernel/random/boot_id'))
        && match(token,/^[0-9a-f]{32}$/) && owner.token==token
        && owner.parent_bssid=='02:00:00:00:00:15'
        && owner.ap_bssid=='02:00:00:00:00:21' && owner.ap2_bssid=='02:00:00:00:00:20'
        && type(owner.provisioning)=='bool' && type(owner.generation)=='int'
        && owner.generation>=0 && type(owner.interfaces)=='object'
        && type(owner.original_main_mask)=='int' && owner.original_main_mask>=0
        && owner.original_main_mask<=65535,'foreign relay registration');
    let restored=action=='retire-restored';
    if(restored) {
        require_ok(owner.provisioning==false,'not an interrupted active registration');
        for(let name in ['deco-r5','deco-r2','deco-sixsta','deco-standby','br-sixbh','br-sixguest'])
            require_ok(!fs.lstat('/sys/class/net/'+name),'runtime must restore before interrupted retirement');
        require_ok(!fs.lstat('/tmp/codex-mesh-join')
            && !fs.lstat('/var/run/netns/codex-sixbh-client'),'runtime still exists');
        let baseline=json(read('/tmp/estudio-mesh-resident/baseline.json'));
        require_ok(baseline.boot_id==owner.boot_id,'restored baseline boot differs');
        let paths=['/etc/config/network','/etc/config/wireless','/etc/config/firewall','/etc/config/dhcp',
            '/etc/apk/world','/usr/sbin/wpad','/usr/sbin/wpa_cli','/lib/modules/6.18.52/mac80211.ko'];
        for(let path in paths)require_ok(baseline.files[path]==substr(run('sha256sum '+path),0,64),
            'interrupted retirement requires exact restored baseline');
        let names={trunk:'br-decorelay',main:'decorelay.1',guest:'decorelay.2'};
        for(let role in names) {
            let name=names[role];
            require_ok(type(owner.interfaces[role])=='int' && owner.interfaces[role]>0,'missing owned index');
            if(!index(name))continue;
            require_ok(index(name)==owner.interfaces[role]
                && trim(fs.readfile('/sys/class/net/'+name+'/address'))=='02:00:00:00:00:03'
                && !fs.lstat('/sys/class/net/'+name+'/master'),'restored relay object changed');
            if(role=='trunk') require_ok(fs.stat('/sys/class/net/'+name+'/bridge')
                && length(fs.lsdir('/sys/class/net/'+name+'/brif'))==0,'restored bridge has foreign ports');
            else require_ok(fs.lstat('/sys/class/net/'+name+'/lower_br-decorelay')
                && match(fs.readfile('/proc/net/vlan/'+name),/VID:\s*([12])\b/)[1]==(role=='main'?'1':'2'),
                'restored VLAN changed');
        }
    }
    else {
        require_ok(read(root+'/closed')=='1\n','relay must close before retirement');
        for(let name in ['deco-r5','deco-r2','br-decorelay','decorelay.1','decorelay.2'])
            require_ok(!fs.lstat('/sys/class/net/'+name),'active relay cannot retire');
    }
    if(action=='retire-unarmed') {
        require_ok(owner.provisioning==true && owner.generation==0,'not an unarmed orphan');
        for(let name in ['ap','ap2','trunk','main','guest'])
            require_ok(owner.interfaces[name]==0,'unarmed orphan owned an interface');
        require_ok(!fs.lstat(root+'/resume.json'),'unarmed orphan has a lease');
    }
    if(fs.lstat(root+'/cleanup.sh') || fs.lstat(root+'/watch.sh') || fs.lstat(root+'/watch.pid')) {
        require_ok(action=='retire','fixture is not an unarmed orphan');
        print('{"retired":false,"fixture_owned":true}\n');exit(0);
    }
    let names=['ap.conf','ap2.conf','allow','allow2','owner','owner.json','closed','closing','resume.json'];
    let actual=fs.lsdir(root);
    for(let name in actual) {
        require_ok(index(names,name)>=0,'unknown relay registration file');
        safe(root+'/'+name,'file');
    }
    clear_retry();
    if(restored) {
        for(let name in ['decorelay.2','decorelay.1','br-decorelay'])
            if(index(name))run('ip link del dev '+name);
    }
    for(let name in actual)require_ok(fs.unlink(root+'/'+name),'relay registration retirement failed');
    require_ok(fs.rmdir(root),'relay registration retirement incomplete');
    print('{"retired":true,"radios_enabled":false}\n');exit(0);
}
if(action=='install') {
    let prepared='/tmp/estudio-relay-prepared';
    require_ok(!fs.lstat(root),'relay already registered');
    safe(prepared,'directory');
    let manifest=json(read(prepared+'/manifest.json'));
    let token=trim(read(prepared+'/owner'));
    let boot=trim(fs.readfile('/proc/sys/kernel/random/boot_id'));
    require_ok(manifest.version==2 && manifest.state=='prepared_only' && manifest.boot_id==boot
        && manifest.token==token && match(token,/^[0-9a-f]{32}$/)
        && manifest.parent_bssid=='02:00:00:00:00:15'
        && manifest.bssid=='02:00:00:00:00:21' && manifest.ap2_bssid=='02:00:00:00:00:20'
        && manifest.child_mac=='02:00:00:00:00:22' && manifest.child_mac2=='02:00:00:00:00:23'
        && type(manifest.measured_5g_rate_mbps)=='int'
        && manifest.measured_5g_rate_mbps>=1 && manifest.measured_5g_rate_mbps<=65535,
        'prepared relay identity differs');
    let node=json(read('/tmp/codex-mesh-join/private/node-state.json'));
    let helper=json(read('/tmp/estudio-deco-backhaul-status.json'));
    let primary=station(),secondary=station('deco-standby');
    let uptime=int(split(trim(fs.readfile('/proc/uptime')),' ')[0]);
    require_ok(node.configuration_verified && node.mesh_connected && node.internet_online
        && node.observed_at<=time() && time()-node.observed_at<=15
        && primary.bssid=='02:00:00:00:00:15' && primary.freq=='5240'
        && primary.wpa_state=='COMPLETED' && primary.key_mgmt=='WPA2-PSK'
        && secondary.bssid=='02:00:00:00:00:16' && secondary.freq=='6135'
        && secondary.wpa_state=='COMPLETED'
        && helper.parent_mode=='auto' && helper.parent_path_state=='reachable'
        && helper.parent_path_checked_at<=uptime && uptime-helper.parent_path_checked_at<=10,
        'relay service or upstream is unavailable');
    for(let name in ['deco-r5','deco-r2','br-decorelay','decorelay.1','decorelay.2'])
        require_ok(!fs.lstat('/sys/class/net/'+name),'foreign relay interface exists');
    require_ok(index('br-sixbh')>0 && index('br-sixguest')>0
        && manifest.original_main_mask==int(trim(fs.readfile('/sys/class/net/br-sixbh/bridge/group_fwd_mask')),0),
        'prepared upstream bridge changed');
    let values={};for(let name in inputs)values[name]=read(prepared+'/'+name);
    // Prepared inputs may be reused, but controller retries belong to one
    // installation. Reusing their ownership would also reuse its nonce.
    let random=fs.open('/dev/urandom','r');require_ok(random,'relay ownership entropy unavailable');
    let bytes=random.read(16);random.close();
    require_ok(type(bytes)=='string' && length(bytes)==16,'relay ownership entropy unavailable');
    let installed_token='';for(let i=0;i<16;i++)installed_token+=sprintf('%02x',ord(substr(bytes,i,1)));
    require_ok(match(installed_token,/^[0-9a-f]{32}$/) && installed_token!=token,'relay ownership is not fresh');
    token=installed_token;
    require_ok(fs.mkdir(root,0700),'cannot register relay');
    try {
        for(let name in inputs) {
            let text=values[name];
            if(name=='ap.conf' || name=='ap2.conf')text=replace(text,prepared+'/allow',root+'/allow');
            require_ok(fs.writefile(root+'/'+name,text),'cannot store relay input');
        }
        require_ok(fs.writefile(root+'/owner',token) && fs.chmod(root+'/owner',0600),
            'cannot store relay ownership');
        store('owner.json',{version:2,mode:'service',provisioning:true,token,boot_id:boot,
            parent_bssid:manifest.parent_bssid,ap_bssid:manifest.bssid,ap2_bssid:manifest.ap2_bssid,
            original_main_mask:manifest.original_main_mask,generation:0,
            interfaces:{ap:0,ap2:0,trunk:0,main:0,guest:0,upstream:index('br-sixbh')}});
        require_ok(fs.writefile(root+'/closed','1\n') && fs.chmod(root+'/closed',0600),
            'cannot fence initial relay');
        run('chgrp network '+root+' '+root+'/ap.conf '+root+'/ap2.conf '+root+'/allow '+root+'/allow2');
        run('chmod 750 '+root+'; chmod 640 '+root+'/ap.conf '+root+'/ap2.conf '+root+'/allow '+root+'/allow2');
        admitted();
        let ie=config('ap.conf').vendor_elements;
        require_ok(int(substr(ie,76,2),16)+256*int(substr(ie,78,2),16)==manifest.measured_5g_rate_mbps
            && config('ap2.conf').channel==''+manifest.channel2,'prepared radio metric differs');
        print(sprintf('%J\n',{installed:true,armed:false,radios_enabled:false,
            generation:0,scope:'prepared relay on this RAM boot',metric_semantics_verified:false}));
        exit(0);
    }
    catch(error) {
        for(let name in ['ap.conf','ap2.conf','allow','allow2','owner','owner.json','owner.json.new','closed'])
            if(fs.lstat(root+'/'+name))require_ok(fs.unlink(root+'/'+name),'relay installation rollback failed');
        require_ok(fs.rmdir(root),'relay installation rollback incomplete');
        die('relay installation rejected; no radio enabled');
    }
}
if(action=='disarm') {
    clear_retry();
    if(fs.lstat(root+'/resume.json')) {
        let owner=admitted();let lease=json(read(root+'/resume.json'));
        require_ok(lease.token==owner.token && lease.boot_id==owner.boot_id,'foreign relay lease');
        require_ok(fs.unlink(root+'/resume.json'),'cannot disarm relay');
    }
    print('{"disarmed":true}\n');exit(0);
}
if(action=='arm') {
    let owner=admitted();let seconds=int(ARGV[1] ?? '0');
    require_ok(seconds>=1 && seconds<=600,'relay lease must be 1 to 600 seconds');
    let lease={version:1,token:owner.token,boot_id:owner.boot_id,
        upstream_index:owner.interfaces.upstream,guest_index:index('br-sixguest'),
        expires_at:time()+seconds,inputs:hashes()};
    store('resume.json',lease);
    print(sprintf('%J\n',{armed:true,expires_at:lease.expires_at,
        scope:'existing admitted relay on this boot',metric_semantics_verified:false}));exit(0);
}
require_ok(action=='resume','unknown relay action');
// Withdraw the previous permission before validating this live generation.
// A failed validation must not leave a recently issued write permission.
clear_retry();
if(!fs.lstat(root+'/resume.json')) {
    if(!fs.lstat(root+'/closed'))reconcile_child_path(admitted(),false);
    print('inactive\n');exit(0);
}
let owner=admitted();let lease=json(read(root+'/resume.json'));
require_ok(lease.version==1 && lease.token==owner.token && lease.boot_id==owner.boot_id
    && lease.upstream_index==owner.interfaces.upstream && lease.guest_index==index('br-sixguest'),
    'relay lease identity differs');
if(lease.expires_at<=time()) { clear_retry();print('expired\n');exit(0); }
require_ok(lease.expires_at<=time()+600,'unbounded relay lease');
let actual=hashes();for(let name in inputs)if(actual[name]!=lease.inputs?.[name]) {
    clear_retry();print('template_changed\n');exit(0);
}
if(!fs.lstat(root+'/closed')) {
    // Admission of a fresh generation also acknowledges initial construction.
    // Verify actual objects before the caller clears its closed-traffic gate.
    let names={ap:'deco-r5',ap2:'deco-r2',trunk:'br-decorelay',main:'decorelay.1',guest:'decorelay.2'};
    for(let field in names)require_ok(index(names[field])>0 && index(names[field])==owner.interfaces[field],
        'active relay interface replaced');
    for(let name in ['deco-r5','deco-r2']) {
        require_ok(trim(fs.readfile('/sys/class/net/'+name+'/address'))==(name=='deco-r5' ? owner.ap_bssid : owner.ap2_bssid)
            && trim(run('basename "$(readlink -f /sys/class/net/'+name+'/phy80211)"'))==(name=='deco-r5' ? 'phy1' : 'phy0')
            && trim(run('basename "$(readlink -f /sys/class/net/'+name+'/master)"'))=='br-decorelay',
            'active relay AP identity changed');
        let native=json(run('ubus call hostapd.'+name+' get_status'));
        require_ok(native.status=='ENABLED' && native.ssid==trim(run('uci -q get wireless.deco_backhaul.ssid')),
            'active relay AP security changed');
    }
    require_ok(trim(fs.readfile('/sys/class/net/br-decorelay/address'))=='02:00:00:00:00:03',
        'active relay bridge replaced');
    reconcile_child_path(owner);
    publish_retry(owner,lease);print('active\n');exit(0);
}
clear_retry();
require_ok(trim(read(root+'/closed'))=='1','invalid close checkpoint');
if(fs.lstat(root+'/opening-failed'))die('relay opening rollback needs inspection');
let state=station();
if(state.bssid!='02:00:00:00:00:15' || state.freq!='5240'
    || state.key_mgmt!='WPA2-PSK' || state.wpa_state!='COMPLETED') { print('waiting\n');exit(0); }
let helper=json(read('/tmp/estudio-deco-backhaul-status.json'));
if(helper.parent_path_state!='reachable' || int(split(trim(fs.readfile("/proc/uptime"))," ")[0])-helper.parent_path_checked_at>10) {
    print('waiting\n');exit(0);
}
// Refuse replacement objects, even with the same names. Cleanup owns these
// interfaces by their captured generation; a new generation starts empty.
for(let name in ['deco-r5','deco-r2','br-decorelay','decorelay.1','decorelay.2'])
    require_ok(!fs.lstat('/sys/class/net/'+name),'relay interface already exists');
let original=owner.original_main_mask;
require_ok(int(trim(fs.readfile('/sys/class/net/br-sixbh/bridge/group_fwd_mask')),0)==original,
    'relay bridge mask changed');
let made={};
try {
    run('ip link add br-decorelay type bridge');made.trunk=index('br-decorelay');
    run('ip link set br-decorelay address 02:00:00:00:00:03 type bridge group_fwd_mask 8192');
    run('ip link set br-decorelay up');
    for(let vid in [1,2]) {
        let name='decorelay.'+vid;run('ip link add link br-decorelay name '+name+' type vlan id '+vid);
        made[name]=index(name);run('ip link set '+name+' master '+(vid==1 ? 'br-sixbh' : 'br-sixguest'));
        run('ip link set '+name+' up');
    }
    run('ip link set br-sixbh type bridge group_fwd_mask '+(original|8192));
    for(let radio in [1,0]) {
        let name=radio==1 ? 'deco-r5' : 'deco-r2';
        let conf=radio==1 ? 'ap.conf' : 'ap2.conf';
        // Record creation even when hostapd returns an error after creating
        // an interface, so the rollback can remove only that actual object.
        let p=fs.popen("ubus call hostapd config_add '{\"iface\":\"phy"+radio+"\",\"config\":\""+root+'/'+conf+"\"}' 2>/dev/null");
        require_ok(p,'hostapd add unavailable');p.read('all');let code=p.close();made[name]=index(name);
        require_ok(code==0 && made[name]>0,'hostapd relay add failed');
        require_ok(trim(fs.readfile('/sys/class/net/'+name+'/address'))==(radio==1 ? owner.ap_bssid : owner.ap2_bssid)
            && match(run('iw dev '+name+' info'),/type AP\n/),'relay AP identity differs');
    }
    state=station();require_ok(state.bssid=='02:00:00:00:00:15' && state.wpa_state=='COMPLETED'
        && time()<lease.expires_at,'parent changed during relay creation');
    owner.interfaces={ap:made['deco-r5'],ap2:made['deco-r2'],trunk:made.trunk,
        main:made['decorelay.1'],guest:made['decorelay.2'],upstream:index('br-sixbh')};
    if(owner.provisioning==true) {
        owner.provisioning=false;owner.generation=0;owner.created_at=time();
    } else {
        owner.generation=(owner.generation ?? 0)+1;owner.recovered_at=time();
    }
    store('owner.json',owner);
    if(fs.lstat(root+'/closing'))require_ok(fs.unlink(root+'/closing'),'cannot clear closing checkpoint');
    require_ok(fs.unlink(root+'/closed'),'cannot clear closed checkpoint');
    print('opened\n');
}
catch(error) {
    // Frames remain fenced throughout creation and rollback. A rollback
    // failure permanently blocks automatic retry on this admitted generation.
    try {
        for(let name in ['deco-r2','deco-r5'])if(made[name]>0) {
            require_ok(index(name)==made[name]
                && trim(fs.readfile('/sys/class/net/'+name+'/address'))==(name=='deco-r5' ? owner.ap_bssid : owner.ap2_bssid)
                && trim(run('basename "$(readlink -f /sys/class/net/'+name+'/phy80211)"'))==(name=='deco-r5' ? 'phy1' : 'phy0'),
                'relay rollback interface replaced');
            run("ubus call hostapd config_remove '{\"iface\":\""+name+"\"}'");
            require_ok(!index(name),'relay rollback AP remains');
        }
        for(let name in ['decorelay.2','decorelay.1'])if(made[name]) {
            require_ok(index(name)==made[name],'relay rollback VLAN replaced');run('ip link del '+name);
        }
        if(made.trunk) { require_ok(index('br-decorelay')==made.trunk,'relay rollback bridge replaced');run('ip link del br-decorelay'); }
        run('ip link set br-sixbh type bridge group_fwd_mask '+original);
    }
    catch(rollback) { fs.writefile(root+'/opening-failed','1\n'); }
    die('relay resume failed; traffic remains fenced');
}

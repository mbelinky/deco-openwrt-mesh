// SPDX-License-Identifier: MIT
// Publish actual node state for the mesh management service. No remote
// configuration values are accepted, and no credentials enter this snapshot.
import * as fs from 'fs';
import { storage_ok } from './estudio_mesh_storage.uc';
import * as ubus from 'ubus';
import * as uci from 'uci';
const root='/tmp/codex-mesh-join/private';
function need(value,message) { if (!value) die(message); }
need(trim(fs.readfile('/sys/class/net/eth0/address'))=='02:00:00:00:00:19','wrong spare');
need(storage_ok(),'flash is accessible');
need(fs.stat(root+'/join-ip'),'management service absent');
// DHCP can replace the management address after Main restarts. Publish only
// the actual current lease; cached startup identity is not a live address.
let lease_text=fs.readfile('/tmp/estudio-mesh-dhcp/lease.json');
let lease=lease_text ? json(lease_text) : {};
let address_pipe=fs.popen('/sbin/ip -n codex-sixbh-client -4 -o address show dev br-lan','r');
need(address_pipe,'management namespace unavailable');
let addresses=trim(address_pipe.read('all'));let address_result=address_pipe.close();
let address_match=match(addresses,/^[^\n]* inet (192\.168\.(68|69|70|71)\.[0-9]{1,3})\/22 scope global br-lan[^\n]*$/);
let management_address_valid=address_result==0 && lease.state=='bound'
    && lease.server=='198.18.68.1' && type(lease.expires_at)=='int' && lease.expires_at>time()
    && type(lease.observed_at)=='int' && lease.observed_at<=time()
    && !!address_match && address_match[1]==lease.ip;
if(management_address_valid) {
    need(fs.writefile(root+'/join-ip.new',lease.ip),'cannot publish management address');
    need(fs.rename(root+'/join-ip.new',root+'/join-ip'),'cannot publish management address atomically');
}
let bus=ubus.connect();need(bus,'native state unavailable');
let wireless=bus.call('network.wireless','status',{});
let bssids={};
let backhaul_radio;
const ap_cursor=uci.cursor('/etc/config');
const main5=ap_cursor.get('wireless','test5') ? 'test5' : 'default_radio1';
if (main5=='default_radio1') need(ap_cursor.get('wireless',main5,'device')=='radio1'
    && ap_cursor.get('wireless',main5,'mode')=='ap','Missing native 5 GHz AP');
const names={default_radio0:'bssid_2g',default_radio2:'bssid_6g'};
names[main5]='bssid_5g';
for (let radio,state in wireless) {
    for (let iface in state.interfaces ?? []) {
        // Netifd retains the configured section when a radio is down but
        // removes its live interface name. Keep its profile so the surviving
        // radio can still be observed; never invent an active interface.
        if (iface.section=='deco_backhaul' && (iface.ifname=='deco-sixsta'
            || (state.up==false && !iface.ifname))) backhaul_radio=radio;
        if (!names[iface.section]) continue;
        if (state.up==false && !iface.ifname) continue;
        need(match(iface.ifname,/^[a-zA-Z0-9_.-]{1,15}$/),'invalid interface');
        let mac=trim(fs.readfile('/sys/class/net/'+iface.ifname+'/address') ?? '');
        if (match(mac,/^[0-9a-f]{2}(:[0-9a-f]{2}){5}$/)) bssids[names[iface.section]]=uc(mac);
    }
}
let pipe=fs.popen('/usr/sbin/wpa_cli -p /var/run/wpa_supplicant -i deco-sixsta status 2>/dev/null','r');
need(pipe,'mesh station unavailable');
let text=pipe.read('all');pipe.close();
// These stock parents were authenticated and their live private radio addresses
// read from their native configuration. Unknown radios must not acquire a
// guessed node identity. Extend this lab set only after the same verification.
const six_parents={
    '02:00:00:00:00:16': {device_id:'52AC6DE2B63BB051EB29D46337989727DC28F87A',mac:'02:00:00:00:00:13'},
    '02:00:00:00:00:1a': {device_id:'5355353F82EA7AF944FFF5582BFE58BA00CA10BF',mac:'02:00:00:00:00:18'},
    '02:00:00:00:00:17': {device_id:'6D44C8260C8599BC54A3F345F4494FCF1516ECD4',mac:'02:00:00:00:00:12'}
};
const five_parents={
    '02:00:00:00:00:15': {device_id:'52AC6DE2B63BB051EB29D46337989727DC28F87A',mac:'02:00:00:00:00:13'},
    '02:00:00:00:00:1f': {device_id:'5355353F82EA7AF944FFF5582BFE58BA00CA10BF',mac:'02:00:00:00:00:18'},
    '02:00:00:00:00:11': {device_id:'DDF89F67F85C238B2E57D57FF79A782C67EAED6A',mac:'02:00:00:00:00:10'},
    '02:00:00:00:00:14': {device_id:'6D44C8260C8599BC54A3F345F4494FCF1516ECD4',mac:'02:00:00:00:00:12'}
};
const profiles={radio1:{frequency:'5240',authentication:'WPA2-PSK',band:'band5',parents:five_parents},
    radio2:{frequency:'6135',authentication:'SAE',band:'band6',parents:six_parents}};
let profile=profiles[backhaul_radio];
let parents=profile?.parents ?? {};
let fields={};
for (let line in split(text,'\n')) {
    let pair=match(line,/^([^=]+)=(.*)$/);
    if (pair) fields[pair[1]]=pair[2];
}
let association=match(text,/(^|\n)bssid=([0-9a-f:]{17})(\n|$)/);
let parent=association ? parents[association[2]] : null;
let mesh_connected=!!parent && fields.wpa_state=='COMPLETED'
    && fields.freq==profile.frequency && fields.key_mgmt==profile.authentication;
let applied_text=fs.readfile('/tmp/codex-mesh-apply/status.json');
let applied=applied_text ? json(applied_text) : null;
let verified=applied?.state=='verified' && applied.wireless_applied==true;
let committed_text=fs.readfile(root+'/adapter-committed.json');
let committed=committed_text ? json(committed_text) : null;
let admitted=committed?.configuration_stored==true && committed.wireless_applied==true
    && type(committed.version)=='string' && committed.version!='0'
    && type(committed.request_id)=='string' && match(committed.request_id,/^[0-9a-f]{32}$/)
    && type(committed.time)=='int' && committed.time>0 && committed.time<=time();
let release=match(fs.readfile('/etc/openwrt_release'),/DISTRIB_REVISION='([^']+)'/);
need(release,'OpenWrt version unavailable');
let helper_text=fs.readfile('/tmp/estudio-deco-backhaul-status.json');
let helper=helper_text ? json(helper_text) : null;
let helper_process=bus.call('service','list',{name:'estudio_deco_backhaul'})?.estudio_deco_backhaul?.instances?.adapter;
let backhaul_bands=mesh_connected ? [profile.band] : [];
let control_association=association;
// Link selection is published by the existing native backhaul process, never
// by the controller. Authenticate its generation, actual radios and VLANs
// before describing more than one active band to the app.
if (helper?.multilink_enabled==true && backhaul_radio=='radio1') {
    let owner_ready=helper_process?.running==true && helper_process.pid==helper.pid
        && helper.link_observed_at<=time() && time()-helper.link_observed_at<=5
        && helper.link_primary_index==int(trim(fs.readfile('/sys/class/net/sixbh.1/ifindex') ?? '0'))
        && helper.link_secondary_index==int(trim(fs.readfile('/sys/class/net/standby.1/ifindex') ?? '0'))
        && match(fs.readlink('/sys/class/net/standby.1/master') ?? '',/\/br-sixbh$/);
    let secondary={};
    let extra=fs.popen('/usr/sbin/wpa_cli -p /var/run/wpa_supplicant -i deco-standby status 2>/dev/null','r');
    if (extra) {
        for (let line in split(extra.read('all'),'\n')) {
            let pair=match(line,/^([^=]+)=(.*)$/);
            if (pair) secondary[pair[1]]=pair[2];
        }
        extra.close();
    }
    let six_ready=six_parents[secondary.bssid]!=null && secondary.freq=='6135'
        && secondary.key_mgmt=='SAE' && secondary.wpa_state=='COMPLETED'
        && trim(fs.readfile('/sys/class/net/deco-standby/address') ?? '')=='02:00:00:00:00:07';
    let both=owner_ready && mesh_connected && five_parents[fields.bssid]?.device_id==six_parents[secondary.bssid]?.device_id
        && six_ready && helper.link_data=='standby.1' && helper.link_broadcast=='sixbh.1';
    let only_six=owner_ready && six_ready && helper.link_data=='standby.1'
        && helper.link_broadcast=='standby.1';
    let only_five=owner_ready && mesh_connected && helper.link_data=='sixbh.1'
        && helper.link_broadcast=='sixbh.1';
    backhaul_bands=both ? ['band5','band6'] : only_six ? ['band6'] : only_five ? ['band5'] : [];
    if (both || only_six) {
        parent=six_parents[secondary.bssid];
        association=[null,null,secondary.bssid];
    }
    mesh_connected=length(backhaul_bands)>0;
}
// Probe only the final selected layout. A failed second check must not
// overwrite a fresh success from the same observation cycle.
let internet=false,internet_probe_attempts=0;
// An admitted node can retain internet while a new Wi-Fi configuration is
// being checked. Report the actual fresh probe independently of that check.
// Initial admission, configuration acknowledgment and relay admission still
// depend on verified configuration at their existing owners.
if(mesh_connected && (verified || admitted)) {
    for(let attempt=0;attempt<2;attempt++) {
        internet_probe_attempts++;
        if(system(['/sbin/ip','netns','exec','codex-sixbh-client','ping','-c','1','-W','2','1.1.1.1'])==0) {
            internet=true;break;
        }
    }
}
let backhaul_ifindex=int(trim(fs.readfile('/sys/class/net/deco-sixsta/ifindex') ?? '0'));
let parent_control_ready=helper?.parent_control_version==1 && helper.state=='configured'
    && helper_process?.running==true && helper_process.pid==helper.pid && helper.ifindex==backhaul_ifindex;
let parent_preference=helper?.parent_mode=='auto' ? {auto:true,device_id:''}
    : helper?.parent_mode=='preferred' && parents[helper.parent_preferred]
    ? {auto:false,device_id:parents[helper.parent_preferred].device_id} : null;
parent_control_ready=parent_control_ready && parent_preference!=null && control_association!=null;
let value={version:1,device_id:'520C7831F7302242F81407BC050E7E7C4B5C697F',
    observed_at:time(),boot_id:trim(fs.readfile('/proc/sys/kernel/random/boot_id')),
    ip:management_address_valid ? lease.ip : null,
    management_address_valid,mesh_connected:mesh_connected && management_address_valid,
    internet_online:internet,
    internet_checked_at:time(),internet_probe_attempts,
    configuration_verified:verified,configuration_admitted:admitted,
    parent_control_ready,parent_control_band:profile?.band,
    parent_preference,backhaul_ifindex,software_ver:'OpenWrt '+release[1],bssids,
    backhaul_band:mesh_connected ? (helper?.link_data=='standby.1' ? 'band6' : profile.band) : null,
    backhaul_bands,
    parent:mesh_connected ? {...parent,bssid:association[2]} : null};
// The stock app asks for a scan result, not a guessed signal from topology.
// Scan only our existing backhaul channel, on demand, without changing a network
// setting or claiming that unverified parents are supported by this RAM build.
function read_snapshot(path) {
    let raw=fs.readfile(path);
    if (!raw || length(raw)>8192) return null;
    try { return json(raw); } catch (e) { return null; }
}
function save_snapshot(path,data) {
    need(fs.writefile(path+'.new',sprintf('%J',data)),'signal snapshot write failed');
    need(fs.rename(path+'.new',path),'signal snapshot commit failed');
}
function native_wpa(arguments) {
    let command=fs.popen('/usr/sbin/wpa_cli -p /var/run/wpa_supplicant -i deco-sixsta '+arguments+' 2>/dev/null','r');
    if (!command) return null;
    let output=command.read('all');
    return command.close()==0 ? trim(output) : null;
}
let request=read_snapshot(root+'/node-signal-request.json');
let signals=read_snapshot(root+'/node-parent-signals.json');
if (mesh_connected && verified && parent_control_ready && request?.version==1
    && request.device_id==value.device_id && request.controller=='52AC6DE2B63BB051EB29D46337989727DC28F87A'
    && request.boot_id==value.boot_id && type(request.requested_at)=='int'
    && time()-request.requested_at>=0 && time()-request.requested_at<=15
    && type(request.revision)=='string' && match(request.revision,/^[0-9a-f]{32}$/)
    && (signals?.revision!=request.revision || signals?.ifindex!=backhaul_ifindex)) {
    let pending=read_snapshot(root+'/node-signal-pending.json');
    if (pending?.revision!=request.revision || pending?.ifindex!=backhaul_ifindex) {
        if (native_wpa('scan freq='+profile.frequency)=='OK') {
            pending={revision:request.revision,ifindex:backhaul_ifindex,started_at:time()};
            save_snapshot(root+'/node-signal-pending.json',pending);
        }
    }
    if (pending?.revision==request.revision && pending.ifindex==backhaul_ifindex
        && time()-pending.started_at>=1 && time()-pending.started_at<=12) {
        let observations=[],current_parent_seen=false;
        for (let bssid,identity in parents) {
            let fields={};
            for (let line in split(native_wpa('bss '+bssid) ?? '', '\n')) {
                let pair=match(line,/^([^=]+)=(.*)$/);
                if (pair) fields[pair[1]]=pair[2];
            }
            let fresh=fields.bssid==bssid && fields.freq==profile.frequency
                && match(fields.age ?? '',/^[0-9]+$/) && int(fields.age)<=12
                && int(fields.age)<=time()-pending.started_at+1
                && match(fields.level ?? '',/^-[0-9]{1,3}$/)
                && int(fields.level)>=-127 && int(fields.level)<0;
            let rssi=fresh ? int(fields.level) : null;
            // Verified /etc/config/link_quality on stock XE75 1.5.0 uses
            // -70 and -50 dBm for all three bands, including 6 GHz.
            push(observations,{device_id:identity.device_id,bssid,rssi_dbm:rssi,
                signal_level:fresh ? (rssi<=-70 ? 1 : rssi<=-50 ? 2 : 3) : 0});
            if (fresh && bssid==control_association[2]) current_parent_seen=true;
        }
        if (current_parent_seen) save_snapshot(root+'/node-parent-signals.json',
            {version:1,revision:request.revision,boot_id:value.boot_id,ifindex:backhaul_ifindex,
             observed_at:time(),scan_started_at:pending.started_at,parents:observations});
    }
}
need(fs.writefile(root+'/node-state.json.new',sprintf('%J',value)),'cannot publish node state');
need(fs.rename(root+'/node-state.json.new',root+'/node-state.json'),'cannot publish node state atomically');

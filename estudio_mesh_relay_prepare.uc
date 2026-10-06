// SPDX-License-Identifier: MIT
// Prepare the admitted RAM relay from live native controller/peer/radio reads.
// Invoke under the fixed preparation lock; credentials never leave the spare.
import * as fs from 'fs';
import { storage_ok } from './estudio_mesh_storage.uc';
function run(cmd) {
    let p=fs.popen(cmd);let raw=p.read('all');
    if(p.close()!=0)die('native input read failed');return raw;
}
function station(iface) {
    let result={};for(let line in split(run('wpa_cli -p /var/run/wpa_supplicant -i '+iface+' status'),'\n')) {
        let m=match(line,/^(bssid|freq|wpa_state)=(.*)$/);if(m)result[m[1]]=m[2];
    }return result;
}

let mode=ARGV[0],provision=mode=='provision',dual_band=mode=='dual'||provision;
if((mode!='single'&&mode!='dual'&&mode!='provision')||length(ARGV)!=(provision?2:1))die('invalid native preparation action');
let seconds=provision?int(ARGV[1]):0;
if(provision&&(!match(ARGV[1],/^[0-9]{1,3}$/)||seconds<1||seconds>600))die('invalid bounded provisioning duration');
if(trim(fs.readfile('/sys/class/net/eth0/address')??'')!='02:00:00:00:00:19'
    ||!storage_ok())die('wrong RAM spare');
if(fs.lstat('/tmp/estudio-mesh-relay')||fs.lstat('/tmp/estudio-relay-lab'))die('relay is active');
let admission_cmd='ADAPTER_CONFINED=1 timeout 30 /sbin/ip netns exec codex-sixbh-client /sbin/ujail -E -i -c -p -e ADAPTER_CONFINED '
    +'-C /tmp/codex-mesh-join/adapter-caps.json -R /tmp/codex-mesh-join '
    +'-w /dev/null -r /dev/urandom -V /tmp/codex-mesh-join/tmp:/var '
    +'-V /tmp/estudio-mesh-resident/control:/control '
    +'-n codex-mesh-relay-prepare -- /usr/bin/lua /relay-controller.lua prepare';
let reader=fs.popen(admission_cmd+' 2>/dev/null');if(!reader)die('native preparation reader unavailable');
let receipt=reader.read('all'),code=reader.close();
let envelope=match(receipt,/DECO_CONTROLLER_RESULT ([^\n]+)/);
if(!envelope)die('native preparation admission unavailable');
let report=json(envelope[1]);
if(code!=0||report.received!==true) {
    let stage=report.failure_stage;
    if(type(stage)!='string'||!match(stage,/^(initial_guard|initial_controller_read|initial_health|peer_connect|peer_lan|peer_station5|peer_station2|final_controller_read|final_health|checkpoint)$/))stage='unknown';
    die('native preparation refused at '+stage);
}
let path='/tmp/estudio-mesh-resident/control/relay-preparation.json',st=fs.lstat(path);
if(st?.type!='file'||st.uid!=0||st.perm.group_write||st.perm.other_write)die('unsafe native preparation admission');
let admission=json(fs.readfile(path));
if(admission.version!=1||admission.owner!='520C7831F7302242F81407BC050E7E7C4B5C697F'
    ||admission.target!='5355353F82EA7AF944FFF5582BFE58BA00CA10BF'
    ||admission.main!='52AC6DE2B63BB051EB29D46337989727DC28F87A'
    ||admission.boot_id!=trim(fs.readfile('/proc/sys/kernel/random/boot_id'))
    ||type(admission.observed_at)!='int'||admission.observed_at>time()||time()-admission.observed_at>15
    ||admission.device_count!=14||admission.stock_auto_main!==true
    ||admission.lan!='02:00:00:00:00:18'||admission.station5!='02:00:00:00:00:22'
    ||admission.station2!='02:00:00:00:00:23')die('native preparation admission differs');
let state=json(fs.readfile('/tmp/codex-mesh-join/private/node-state.json')??'{}');
if(!state.configuration_verified||!state.mesh_connected||!state.internet_online
    ||state.observed_at>time()||time()-state.observed_at>15)die('native preparation service unavailable');
let child_mac=admission.station5;
let random=fs.open('/dev/urandom','r');
if(!random)die('native preparation token unavailable');
let bytes=random.read(16);random.close();
if(type(bytes)!='string'||length(bytes)!=16)die('native preparation token unavailable');
let token='';for(let i=0;i<16;i++)token+=sprintf('%02x',ord(substr(bytes,i,1)));
if(!match(token,/^[0-9a-f]{32}$/))die('native preparation token unavailable');

let root='/tmp/estudio-relay-prepared';
if(fs.stat('/tmp/estudio-mesh-relay')||fs.stat('/tmp/estudio-relay-lab'))die('relay is active');
for(let iface in ['deco-r5','deco-r2','br-decorelay','decorelay.1','decorelay.2'])
    if(fs.stat('/sys/class/net/'+iface))die('downstream interface already exists');
let primary=station('deco-sixsta'),secondary=station('deco-standby');
if(primary.bssid!='02:00:00:00:00:15'||primary.wpa_state!='COMPLETED'||primary.freq!='5240')die('unexpected primary parent');
if(secondary.bssid!='02:00:00:00:00:16'||secondary.wpa_state!='COMPLETED'||secondary.freq!='6135')die('unexpected secondary parent');
let policy=json(fs.readfile('/tmp/estudio-deco-backhaul-status.json'));
if(policy.parent_mode!='auto')die('parent is not automatic');
if(trim(run('wpa_cli -p /var/run/wpa_supplicant -i deco-sixsta scan freq=5240'))!='OK')die('root scan unavailable');
run('sleep 3');
let raw=run('wpa_cli -p /var/run/wpa_supplicant -i deco-sixsta bss '+primary.bssid);
let fields={};for(let line in split(raw,'\n')){let m=match(line,/^(bssid|age|freq|ie|beacon_ie)=(.*)$/);if(m)fields[m[1]]=m[2];}
if(!fields.age||int(fields.age)>15||fields.freq!='5240')die('root advertisement is stale');
function mesh_ie(hex) {
    let found=[];
    if(length(hex)%2)die('malformed radio element');
    for(let i=0;i<length(hex);) {
        if(i+4>length(hex))die('truncated radio element');
        let count=2+int(substr(hex,i+2,2),16);
        if(i+2*count>length(hex))die('truncated radio body');
        let item=substr(hex,i,count*2);
        if(substr(item,0,12)=='dd3a001d0f01')push(found,item);
        i+=count*2;
    }
    if(length(found)!=1)die('ambiguous root mesh advertisement');return found[0];
}
let parent=mesh_ie(fields.ie);
if(parent!=mesh_ie(fields.beacon_ie)||length(parent)!=120||substr(parent,16,2)!='00'
    ||substr(parent,18,12)!='020000000013'||substr(parent,104,12)!='020000000013')die('unexpected root identity');
let group=substr(parent,30,32);
let derived=substr(run('printf %s "$(jsonfilter -i /tmp/oem-mesh-peer/private/group-info -e @.gid)" | md5sum'),0,32);
if(group!=derived)die('root mesh identifier differs from saved identity');
let ssid=trim(run('uci -q get wireless.deco_backhaul.ssid'));
let key=trim(run('uci -q get wireless.deco_backhaul.key'));
let original_ssid=trim(run('uci -c /tmp/oem-mesh-peer/private/device-root/config -q get wireless.ath13.ssid'));
let original_key=trim(run('uci -c /tmp/oem-mesh-peer/private/device-root/config -q get wireless.ath13.key'));
if(ssid!=original_ssid||key!=original_key||length(ssid)<1||length(ssid)>32
    ||length(key)<8||length(key)>63||match(key,/[\r\n]/))die('private credentials are inconsistent');
let dump=run('iw dev deco-sixsta station dump');
let tx=match(dump,/tx bitrate:\s*([0-9.]+)/),rx=match(dump,/rx bitrate:\s*([0-9.]+)/);
if(!tx||!rx)die('uplink rate is unavailable');
let measured_rate=int(min(+tx[1],+rx[1]));
if(measured_rate<1||measured_rate>65535)die('unsupported uplink rate');
let rate_hex=sprintf('%02x%02x',measured_rate&255,measured_rate>>8);
// Candidate distance is one hop after Main. The metric is deliberately
// labelled experimental until original candidate selection and RF pass.
let candidate=substr(parent,0,16)+'01'+substr(parent,18,54)+'010a'+rate_hex
    +substr(parent,80,24)+'020000000019'+substr(parent,116,4);
let ssid_hex='';for(let i=0;i<length(ssid);i++)ssid_hex+=sprintf('%02x',ord(substr(ssid,i,1)));
let conf='driver=nl80211\ninterface=deco-r5\nbssid=02:00:00:00:00:21\n'
    +'ctrl_interface=/var/run/hostapd\ncountry_code=ES\nhw_mode=a\nchannel=48\n'
    +'ieee80211n=1\nieee80211ac=1\nieee80211ax=1\nignore_broadcast_ssid=1\n'
    +'wpa=2\nwpa_key_mgmt=WPA-PSK\nrsn_pairwise=CCMP\nwpa_passphrase='+key+'\n'
    +'wds_sta=1\nbridge=br-decorelay\nwds_bridge=br-decorelay\nmacaddr_acl=1\n'
    +'accept_mac_file='+root+'/allow\nssid2='+ssid_hex+'\nvendor_elements='+candidate+'\n'
    +'assocresp_elements='+candidate+'\n';
let manifest={version:1,token:token,prepared_by:'native',target_device_id:admission.target,admission_observed_at:admission.observed_at,boot_id:trim(fs.readfile('/proc/sys/kernel/random/boot_id')),
    state:'prepared_only',parent_bssid:primary.bssid,child_mac:child_mac,
    parent_policy_revision:policy.parent_policy_revision,measured_5g_rate_mbps:measured_rate,
    metric_semantics_verified:false,root_distance:1,original_main_mask:int(trim(fs.readfile('/sys/class/net/br-sixbh/bridge/group_fwd_mask')),0),
    parent_gateway:substr(parent,64,8),interface:'deco-r5',bssid:'02:00:00:00:00:21'};
let conf2=null;
if(dual_band) {
 let channel=int(trim(run('uci -q get wireless.radio0.channel')));
 if(channel<1||channel>13||trim(run('uci -q get wireless.radio0.country'))!='ES')die('unsupported two GHz radio policy');
 conf2=replace(conf,'interface=deco-r5\n','interface=deco-r2\n');
 conf2=replace(conf2,'bssid=02:00:00:00:00:21\n','bssid=02:00:00:00:00:20\n');
 conf2=replace(conf2,'hw_mode=a\nchannel=48\n','hw_mode=g\nchannel='+channel+'\n');
 conf2=replace(conf2,'ieee80211ac=1\n','');
 conf2=replace(conf2,'accept_mac_file='+root+'/allow\n','accept_mac_file='+root+'/allow2\n');
 conf2=replace(conf2,'vendor_elements='+candidate+'\n',
     'vendor_elements='+substr(candidate,0,76)+'0000'+substr(candidate,80)+'\n');
 conf2=replace(conf2,'assocresp_elements='+candidate+'\n',
     'assocresp_elements='+substr(candidate,0,76)+'0000'+substr(candidate,80)+'\n');
 manifest.version=2;manifest.channel2=channel;manifest.ap2_bssid='02:00:00:00:00:20';manifest.child_mac2='02:00:00:00:00:23';
}
let replaced_inactive=false;
if(fs.lstat(root)) {
 let st=fs.lstat(root);
 if(st.type!='directory'||st.uid!=0||st.perm.group_write||st.perm.other_write)die('unsafe existing preparation');
 function owned_file(name) {
  let st=fs.lstat(root+'/'+name);
  if(st?.type!='file'||st.uid!=0||st.perm.group_write||st.perm.other_write)die('unsafe existing preparation input');
  return fs.readfile(root+'/'+name);
 }
 let old=json(owned_file('manifest.json')),old_token=trim(owned_file('owner'));
 if(!match(old_token,/^[0-9a-f]{32}$/)||old.token!=old_token||old.state!='prepared_only'
    ||old.boot_id!=manifest.boot_id||old.parent_bssid!=manifest.parent_bssid
    ||old.child_mac!=manifest.child_mac||(old.version!=1&&old.version!=2)
    ||(old.bssid!='02:00:00:00:00:04'&&old.bssid!='02:00:00:00:00:21')
    ||trim(owned_file('allow'))!=manifest.child_mac)die('existing preparation is foreign');
 owned_file('ap.conf');
 if(old.version==2) {
  if(old.ap2_bssid!='02:00:00:00:00:20'||old.child_mac2!='02:00:00:00:00:23'
     ||trim(owned_file('allow2'))!=old.child_mac2)die('existing second preparation is foreign');
  owned_file('ap2.conf');
 }
 if(old.version!=manifest.version)die('existing preparation uses a different radio count');
 replaced_inactive=true;
} else if(!fs.mkdir(root,0700))die('cannot prepare native directory');
if(!fs.writefile(root+'/ap.conf',conf)||!fs.writefile(root+'/allow',child_mac+'\n')
    ||!fs.writefile(root+'/owner',token)||!fs.writefile(root+'/manifest.json',sprintf('%J',manifest)))die('cannot store native candidate');
if(dual_band) {
 if(!fs.writefile(root+'/ap2.conf',conf2)||!fs.writefile(root+'/allow2',manifest.child_mac2+'\n')
    ||!fs.writefile(root+'/manifest.json',sprintf('%J',manifest)))die('cannot store second candidate');
 run('chmod 600 '+root+'/ap2.conf '+root+'/allow2');
}
run('chmod 600 '+root+'/ap.conf '+root+'/allow '+root+'/owner '+root+'/manifest.json');
let result={state:manifest.state,replaced_inactive,boot_id:manifest.boot_id,root,parent_bssid:primary.bssid,
    child_mac:manifest.child_mac,bssid:manifest.bssid,root_distance:manifest.root_distance,
    version:manifest.version,dual_band:manifest.version==2,channel2:manifest.channel2,
    ap2_bssid:manifest.ap2_bssid,child_mac2:manifest.child_mac2,
    measured_5g_rate_mbps:measured_rate,metric_semantics_verified:false,
    private_credentials_match_saved_stock:true,mesh_identifier_matches_md5_saved_gid:true,
    root_gateway_preserved:true,scan_age_seconds:int(fields.age),radio_enabled:false,
    private_hostapd_configuration_stored:true,admission_list_size:1,
    prepared_config_sha256:substr(run('sha256sum '+root+'/ap.conf'),0,64),
    production_identity_transmitted:false,preparation_native:true,
    original_target_parent:admission.original_target_parent,actual_descendants:admission.actual_descendants};
if(provision) {
    let lease=json(run("flock -x /tmp/estudio-mesh-relay-lifecycle.lock /bin/sh -c 'ucode /tmp/estudio_mesh_relay_resume.uc install >/dev/null && ucode /tmp/estudio_mesh_relay_resume.uc arm "+seconds+"'"));
    lease.provisioned=true;lease.preparation_native=true;lease.stock_command_sent=false;
    print(sprintf('%J\n',lease));
} else print(sprintf('%J\n',result));

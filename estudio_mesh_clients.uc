// SPDX-License-Identifier: MIT
// Read actual authorized Wi-Fi associations, optionally learning IPv4 addresses
// from their traffic. Wired clients and OEM delivery remain incomplete; no
// snapshot is advertised as a complete controller report.
import * as fs from 'fs';
import * as ubus from 'ubus';
import * as uci from 'uci';
import * as nl80211 from 'nl80211';
import { observe } from './estudio_mesh_client_addresses.uc';

let bus = ubus.connect();
if (!bus) die('client observation service unavailable');
let context;
if (ARGV[0] && ARGV[0] != '-') {
    let input = fs.readfile(ARGV[0]);
    if (!input || length(input) > 65536) die('client context unavailable');
    context = json(input);
} else {
    // The current deployment is bound to the single RAM-booted spare. Discover
    // active APs from their native owner; never treat the uplink as a client AP.
    if (trim(fs.readfile('/sys/class/net/eth0/address') ?? '') != '02:00:00:00:00:19')
        die('unexpected client collector device');
    let config = uci.cursor('/etc/config').get_all('wireless');
    let runtime = bus.call('network.wireless', 'status', {});
    if (type(config) != 'object' || type(runtime) != 'object') die('wireless state unavailable');
    let boot=trim(fs.readfile('/proc/sys/kernel/random/boot_id') ?? '');
    if (!length(boot)) die('wireless boot identity unavailable');
    let old_data=fs.readfile('/tmp/codex-mesh-join/private/wifi-context.json');
    let previous=old_data && length(old_data)<=65536 ? json(old_data) : {};
    let radios={};
    if (previous.device_id=='520C7831F7302242F81407BC050E7E7C4B5C697F'
        && previous.boot_id==boot && type(previous.radios)=='object')
        for (let name,index in previous.radios)
            if (config[name]?.['.type']=='wifi-device' && type(index)=='int'
                && index>=0 && index<=65535) radios[name]=index;
    let kernel=nl80211.request(nl80211.const.NL80211_CMD_GET_INTERFACE,
        nl80211.const.NLM_F_DUMP,{}), kernel_error=nl80211.error();
    if (kernel==null && kernel_error==null) kernel=[];
    if (type(kernel)!='array' || kernel_error!=null) die('kernel interface inventory unavailable');
    let native={};
    for (let interface in kernel) {
        if (type(interface.ifname)!='string' || native[interface.ifname])
            die('ambiguous kernel interface');
        native[interface.ifname]=interface;
    }
    let main5 = config.test5 ? 'test5' : 'default_radio1';
    if (main5 == 'default_radio1' && (config[main5]?.['.type'] != 'wifi-iface'
        || config[main5].device != 'radio1' || config[main5].mode != 'ap')) die('Missing native 5 GHz AP');
    let groups = {default_radio0: 0, default_radio2: 0, dec_iso2: 0, dec_iso5: 0, dec_iso6: 0,
        deco_iot2: 2, deco_iot5: 2, dec_ioti2: 2, dec_ioti5: 2,
        deco_guest2: 1, deco_guest5: 1, deco_guest6: 1};
    groups[main5] = 0;
    context = {device_id: '520C7831F7302242F81407BC050E7E7C4B5C697F',
        boot_id:boot,radios,aps: []};
    for (let name, ap in config) {
        if (ap['.type'] != 'wifi-iface' || ap.mode != 'ap' || ap.disabled == '1'
            || config[ap.device]?.disabled == '1') continue;
        if (groups[name] == null) die('unclassified access point');
        let radio = runtime[ap.device];
        if (radio?.up===false && radio.pending===false) {
            // A completed native shutdown is distinct from a missing AP.
            // Verify the previously observed physical radio has no AP left
            // in the kernel before omitting it from current client coverage.
            if (radios[ap.device]==null) die('offline radio identity unavailable');
            for (let interface in kernel)
                if (interface.wiphy==radios[ap.device]
                    && interface.iftype==nl80211.const.NL80211_IFTYPE_AP)
                    die('offline radio still has an access point');
            continue;
        }
        if (radio?.up!==true || radio.pending) die('wireless transition in progress');
        let interface;
        for (let candidate in radio.interfaces ?? []) {
            if (candidate.section == name) {
                if (interface) die('ambiguous access point');
                interface = candidate.ifname;
            }
        }
        if (!interface) die('configured access point unavailable');
        let observed=native[interface];
        if (observed?.iftype!=nl80211.const.NL80211_IFTYPE_AP || type(observed.wiphy)!='int'
            || (radios[ap.device]!=null && radios[ap.device]!=observed.wiphy))
            die('access point radio identity changed');
        radios[ap.device]=observed.wiphy;
        push(context.aps, {interface, network_type: groups[name]});
    }
}
if (type(context) != 'object' || type(context.device_id) != 'string'
    || !match(context.device_id, /^[0-9A-F]{40}$/)
    || type(context.aps) != 'array' || !length(context.aps) || length(context.aps) > 16)
    die('invalid client context');
if (ARGV[1]=='context') { print(sprintf('%J\n',context)); exit(0); }
if (ARGV[1] && ARGV[1] != 'observe' && ARGV[1] != 'snapshot') die('unknown client collection operation');
let boot=trim(fs.readfile('/proc/sys/kernel/random/boot_id') ?? '');
if (!length(boot)) die('boot identity unavailable');
function associations(interface) {
    let rows=nl80211.request(nl80211.const.NL80211_CMD_GET_STATION,
        nl80211.const.NLM_F_DUMP,{dev:interface});
    let error=nl80211.error();
    if (rows==null && error==null) return {};
    if (type(rows)!='array' || error!=null) die('kernel station state unavailable');
    let result={};
    for (let row in rows) result[lc(row.mac)]=row.sta_info;
    return result;
}
let clients = [], seen = {}, interfaces = {}, generations = {};
for (let ap in context.aps) {
    if (type(ap) != 'object' || type(ap.interface) != 'string'
        || !match(ap.interface, /^[A-Za-z0-9_.-]{1,15}$/)
        || (ap.network_type !== 0 && ap.network_type !== 1 && ap.network_type !== 2)
        || interfaces[ap.interface]) die('invalid client access point');
    interfaces[ap.interface] = true;
    generations[ap.interface] = fs.readfile('/sys/class/net/'+ap.interface+'/ifindex');
    let object = 'hostapd.' + ap.interface;
    let status = bus.call(object, 'get_status', {});
    let stations = bus.call(object, 'get_clients', {});
    let driver=associations(ap.interface);
    // A missing/restarting AP must never be interpreted as every client leaving.
    if (status?.status != 'ENABLED' || type(stations?.clients) != 'object'
        || type(status.freq) != 'int') die('access point observation unavailable');
    let freq = status.freq;
    let band = freq >= 2412 && freq <= 2484 ? 'band2_4'
        : freq >= 5180 && freq <= 5885 ? 'band5'
        : freq >= 5955 && freq <= 7115 ? 'band6' : null;
    if (!band) die('unsupported client frequency');
    for (let mac, station in stations.clients) {
        if (!match(mac, /^[0-9a-f][02468ace](:[0-9a-f]{2}){5}$/)
            || type(station) != 'object' || type(station.authorized) != 'bool')
            die('invalid station observation');
        if (!station.authorized) continue;
        let association=driver[mac]?.assoc_at_boottime;
        if (type(association)!='int' || association<=0 || !generations[ap.interface])
            die('client association identity unavailable');
        // A roam during enumeration can briefly appear on two BSSs. Retry the
        // observation rather than reporting contradictory ownership upstream.
        if (seen[mac]) die('client moved during observation');
        seen[mac] = true;
        push(clients, {mac: uc(replace(mac, ':', '-')), device_id: context.device_id,
            interface: ap.interface, wire_type: 'wireless', connection_type: band,
            association_id: sprintf('%s:%s:%d',boot,trim(generations[ap.interface]),association),
            freq, is_guest: ap.network_type == 1 ? 1 : 0,
            network_type: ap.network_type, ip: null});
    }
}
if (ARGV[1] == 'observe') {
    for (let interface in keys(interfaces)) {
        let authorized={};
        for (let row in clients) if (row.interface==interface) authorized[row.mac]=true;
        let addresses=observe(interface,authorized);
        for (let row in clients) {
            if (row.interface!=interface || !addresses[row.mac]) continue;
            row.address_conflict=addresses[row.mac].conflict;
            if (!row.address_conflict) {
                row.ip=addresses[row.mac].ip;
                row.address_seen_at=time();
            }
        }
    }
    // Recheck the station set and interface generation after capture. A radio
    // restart or changed association must not publish stale client ownership.
    for (let interface in keys(interfaces)) {
        let stations=bus.call('hostapd.'+interface,'get_clients',{}), expected={};
        let driver=associations(interface);
        if (type(stations?.clients)!='object' || !generations[interface]
            || fs.readfile('/sys/class/net/'+interface+'/ifindex')!=generations[interface])
            die('access point changed during address observation');
        for (let row in clients) if (row.interface==interface) expected[row.mac]=row.association_id;
        for (let mac, station in stations.clients) {
            if (station.authorized!==true) continue;
            let key=uc(replace(mac,':','-'));
            if (!expected[key]) die('client joined during address observation');
            if (expected[key]!=sprintf('%s:%s:%d',boot,trim(generations[interface]),driver[mac]?.assoc_at_boottime ?? 0))
                die('client reconnected during address observation');
            delete expected[key];
        }
        if (length(expected)) die('client left during address observation');
    }
}
bus.disconnect();
if (ARGV[2]) {
    let data=fs.readfile(ARGV[2]);
    if (data) {
        if (length(data)>1048576) die('client history too large');
        let previous=json(data), cached={};
        if (previous?.scope!='wifi-associations' || type(previous.clients)!='array') die('invalid client history');
        for (let row in previous.clients) {
            if (cached[row.mac]) die('duplicate cached client');
            cached[row.mac]=row;
        }
        for (let row in clients) {
            let old=cached[row.mac];
            if (row.ip || row.address_conflict || !old?.ip || old.address_conflict
                || old.association_id!=row.association_id || old.interface!=row.interface
                || old.network_type!=row.network_type || type(old.address_seen_at)!='int'
                || old.address_seen_at>time() || time()-old.address_seen_at>300) continue;
            row.ip=old.ip;
            row.address_seen_at=old.address_seen_at;
        }
    }
}
let addresses_complete=true;
for (let row in clients) if (!row.ip) addresses_complete=false;
let pending=['wired-clients'];
if (!addresses_complete) push(pending,'bridged-client-addresses');
print(sprintf('%J\n', {scope: 'wifi-associations', device_id: context.device_id, observed_at: time(),
    interfaces: keys(interfaces), ready_for_controller: false,
    wifi_addresses_complete: addresses_complete, pending, clients}));

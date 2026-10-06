// SPDX-License-Identifier: MIT
// Native OpenWrt half of the configuration adapter. OEM code remains confined.
// This transaction applies main Wi-Fi settings, with 6 GHz restricted to the
// demonstrated indoor lab operating point. Physical 6 GHz AP client traffic
// remains unverified. It never reports
// a whole Deco configuration as applied and does not advertise mesh membership.
import * as fs from 'fs';
import { storage_ok } from './estudio_mesh_storage.uc';
import * as uci from 'uci';
import * as ubus from 'ubus';
import { render } from './estudio_mesh_client_policy.uc';

const input = '/tmp/oem-mesh-peer/private/native-apply';
const root = '/tmp/codex-mesh-apply';
const lock = '/tmp/codex-mesh-apply.lock';
const active = '/tmp/codex-mesh-apply-active';
const live = '/etc/config/wireless';
const radios = ['radio0', 'radio1', 'radio2'];
const ap_cursor = uci.cursor('/etc/config');
const main5 = ap_cursor.get('wireless', 'test5') ? 'test5' : 'default_radio1';
if (main5 == 'default_radio1' && (ap_cursor.get('wireless', main5) != 'wifi-iface'
    || ap_cursor.get('wireless', main5, 'device') != 'radio1'
    || ap_cursor.get('wireless', main5, 'mode') != 'ap')) die('Missing native 5 GHz AP');
const aps = ['default_radio0', main5, 'default_radio2'];
const mutable = ['ssid', 'key', 'encryption', 'hidden', 'disabled', 'ieee80211r'];
const roaming_options = { mobility_domain: '5348', nasid: 'r0kh.tp-link.com',
    ft_psk_generate_local: '1', ft_over_ds: '0', reassociation_deadline: '1000' };
const main_ap_mutable = [...mutable, 'wps_pushbutton', 'ieee80211w', 'sae_pwe', 'sae_require_mfp', ...keys(roaming_options)];
const six_ap_mutable = [...mutable, 'wps_pushbutton', 'ieee80211w', 'sae_pwe', 'network', 'macaddr'];
const six_radio_mutable = ['disabled', 'channel', 'htmode', 'txpower', 'reg_power_type'];
const beamforming_options = ['su_beamformer', 'su_beamformee', 'mu_beamformer', 'mu_beamformee',
    'he_su_beamformer', 'he_su_beamformee', 'he_mu_beamformer'];
const six_power = '/sys/kernel/debug/ieee80211/phy2/user_power';
const iot_aps = {
    deco_iot2: { main: 'default_radio0', device: 'radio0', ifname: 'deco-t2', macaddr: '02:00:00:00:00:1d' },
    deco_iot5: { main: main5, device: 'radio1', ifname: 'deco-t5', macaddr: '02:00:00:00:00:0e' }
};
const guest_aps = {
    deco_guest2: { device: 'radio0', ifname: 'deco-g2', macaddr: '02:00:00:00:00:1b' },
    deco_guest5: { device: 'radio1', ifname: 'deco-g5', macaddr: '02:00:00:00:00:08' },
    deco_guest6: { device: 'radio2', ifname: 'deco-g6', macaddr: '02:00:00:00:00:09' }
};
const isolation_options = ['macfilter', 'maclist', 'deco_isolation_owned'];
const isolated_aps = {
    dec_iso2: { main: 'default_radio0', device: 'radio0', ifname: 'deco-i2', macaddr: '02:00:00:00:00:1c' },
    dec_iso5: { main: main5, device: 'radio1', ifname: 'deco-i5', macaddr: '02:00:00:00:00:0a' },
    dec_iso6: { main: 'default_radio2', device: 'radio2', ifname: 'deco-i6', macaddr: '02:00:00:00:00:0b' },
    dec_ioti2: { main: 'deco_iot2', device: 'radio0', ifname: 'deco-ti2', macaddr: '02:00:00:00:00:1e' },
    dec_ioti5: { main: 'deco_iot5', device: 'radio1', ifname: 'deco-ti5', macaddr: '02:00:00:00:00:0f' }
};
let bus = ubus.connect();
let active_request = null;
let policy_transaction = false;
let relay_lock_file = null;
let readiness_failure = null;
let verification_failure = null;

function unready(reason) { readiness_failure = reason; return false; }

function require_ok(value, message) {
    if (!value) die(message);
}
function write(path, data) {
    require_ok(fs.writefile(path + '.new', data) == length(data), 'cannot write transaction file');
    require_ok(fs.chmod(path + '.new', 0600), 'cannot protect transaction file');
    require_ok(fs.rename(path + '.new', path), 'cannot replace transaction file');
}
function diagnostic(error) {
    // Source locations help diagnose failures without logging request values,
    // UCI secrets, or exception context that might contain configuration data.
    for (let frame in error.stacktrace ?? [])
        warn('Native update failure at ', frame.filename, ':', frame.line, '\n');
}
function contains(values, value) {
    for (let item in values) if (item == value) return true;
    return false;
}
function same(a, b) {
    if (type(a) != type(b)) return false;
    if (type(a) != 'object' && type(a) != 'array') return a == b;
    if (length(a) != length(b)) return false;
    if (type(a) == 'array') {
        for (let i = 0; i < length(a); i++) if (!same(a[i], b[i])) return false;
        return true;
    }
    for (let k in keys(a)) if (!same(a[k], b[k])) return false;
    return true;
}
function isolation_valid(config) {
    let clients = config.default_radio0?.deco_isolation_owned == '1' ? config.default_radio0.maclist : [];
    require_ok(type(clients) == 'array', 'invalid isolated client list');
    for (let address in clients)
        require_ok(type(address) == 'string' && match(address, /^[0-9a-f][02468ace](:[0-9a-f]{2}){5}$/),
            'invalid isolated client identity');
    for (let name, definition in isolated_aps) {
        let normal = config[definition.main], group = config[name];
        let enabled = length(clients) && normal && (name != 'dec_iso6' || normal.disabled != '1');
        if (!enabled) {
            require_ok(!group && normal?.deco_isolation_owned != '1', 'unexpected isolation group');
            continue;
        }
        require_ok(normal.deco_isolation_owned == '1' && normal.macfilter == 'deny'
            && same(normal.maclist, clients), 'normal AP isolation list differs');
        require_ok(group && group['.type'] == 'wifi-iface' && group.deco_isolation_owned == '1'
            && group.macfilter == 'allow' && same(group.maclist, clients)
            && group.ifname == definition.ifname && group.macaddr == definition.macaddr && group.isolate == '0',
            'invalid isolated AP attachment');
        let copied = ['device', 'mode', 'network', 'ssid', 'key', 'encryption', 'hidden', 'disabled',
            'ieee80211r', 'ieee80211w', 'sae_pwe', 'sae_require_mfp', ...keys(roaming_options)];
        for (let option in copied)
            require_ok(same(group[option], normal[option]), 'isolated AP differs from normal AP');
        let allowed = [...copied, ...isolation_options, 'ifname', 'macaddr', 'isolate',
            '.type', '.name', '.index', '.anonymous'];
        for (let option in keys(group)) require_ok(contains(allowed, option), 'unexpected isolated AP option');
        require_ok(contains(['wifitest', 'sixbh'], normal.network)
            && normal.network == config.default_radio0.network,
            'isolation groups must share a supported network');
    }
    return clients;
}
function policy_read() {
    let pipe = fs.popen('/usr/sbin/nft list tables', 'r');
    require_ok(pipe, 'cannot inspect firewall tables');
    let tables = pipe.read('all');
    require_ok(pipe.close() == 0, 'cannot inspect firewall tables');
    if (!contains(split(tables, '\n'), 'table bridge deco_clients')) return '';
    pipe = fs.popen('/usr/sbin/nft -s list table bridge deco_clients', 'r');
    require_ok(pipe, 'cannot inspect isolation rules');
    let result = pipe.read('all');
    require_ok(pipe.close() == 0, 'cannot inspect isolation rules');
    return result;
}
function policy_context(config, ports) {
    let shared = config.default_radio0.network == 'sixbh';
    let status = bus.call(shared ? 'network.interface.sixbh' : 'network.interface.wifitest', 'status', {});
    let bridge = shared ? 'br-sixbh' : 'br-wifitest';
    if (!status?.up || status.l3_device != bridge) return null;
    if (shared) {
        if (!config.deco_backhaul
            || !match(fs.readlink('/sys/class/net/sixbh.1/master') ?? '', /\/br-sixbh$/)) return null;
        // This property-specific lab adapter already pins the controller BSSID.
        // Pin its LAN MAC too; the bounded admission probe verifies it by ARP.
        // The bridge has no host IP and its own MAC is not the router's MAC.
        return { bridge, uplink: 'sixbh.1', gateway_mac: '02:00:00:00:00:13', isolated_ports: ports };
    }
    let upstream = bus.call('network.interface.wwan', 'status', {});
    if (upstream?.l3_device != 'phy0-sta0') return null;
    return { bridge, uplink: upstream.l3_device,
        gateway_mac: trim(fs.readfile('/sys/class/net/br-wifitest/address')), isolated_ports: ports };
}
function policy_prepare(clients, config) {
    let before = policy_read();
    if (before != '') {
        let previous = json(fs.readfile(root + '/status.json'));
        let location = previous?.state == 'verified' ? 'candidate' : 'before';
        require_ok(previous?.policy_transaction
            && before == fs.readfile(root + '/' + location + '/isolation.nft'), 'foreign isolation rules present');
    }
    let candidate = '';
    if (length(clients)) {
        let ports = [];
        for (let name, definition in isolated_aps)
            if (config[name] && config[name].disabled != '1') push(ports, definition.ifname);
        let context = policy_context(config, ports);
        require_ok(context, 'isolation bridge or uplink mapping changed');
        write(root + '/candidate/isolation-context.json', sprintf('%J', context));
        write(root + '/policy-staged.nft', render(clients, context));
        // Load only in a fresh network namespace. This checks kernel support and
        // obtains canonical text before the live transaction can be interrupted.
        let pipe = fs.popen("/usr/bin/unshare --net /bin/sh -c '/usr/sbin/nft -f /tmp/codex-mesh-apply/policy-staged.nft && /usr/sbin/nft -s list table bridge deco_clients'", 'r');
        require_ok(pipe, 'cannot validate isolation rules');
        candidate = pipe.read('all');
        require_ok(pipe.close() == 0 && length(candidate), 'isolation rule preflight failed');
    }
    write(root + '/before/isolation.nft', before);
    write(root + '/candidate/isolation.nft', candidate);
    policy_transaction = before != '' || candidate != '';
}
function policy_replace(destination) {
    let before = fs.readfile(root + '/before/isolation.nft');
    let candidate = fs.readfile(root + '/candidate/isolation.nft');
    let current = policy_read();
    require_ok(current == before || current == candidate, 'isolation rules changed outside transaction');
    let desired = destination == 'before' ? before : candidate;
    if (current == desired) return;
    write(root + '/policy-transaction.nft', (current == '' ? '' : 'delete table bridge deco_clients\n') + desired);
    require_ok(system(['/usr/sbin/nft', '-f', root + '/policy-transaction.nft']) == 0
        && policy_read() == desired, 'isolation rule replacement failed');
}
function quiesce(changed) {
    for (let radio in changed)
        require_ok(system(['/bin/ubus', 'call', 'network.wireless', 'down', sprintf('%J', { device: radio })]) == 0,
            'cannot stop radio for isolation update');
    for (let attempt = 0; attempt < 20; attempt++) {
        let status = bus.call('network.wireless', 'status', {}), stopped = true;
        for (let radio in changed) if (!status[radio] || status[radio].up || status[radio].pending) stopped = false;
        if (stopped) return;
        sleep(500);
    }
    die('radios did not stop for isolation update');
}
function package_at(path) {
    let cursor = uci.cursor(path);
    let result = cursor.get_all('wireless');
    require_ok(type(result) == 'object', 'invalid wireless package');
    // Reordering named sections does not change the radio configuration.
    for (let name in keys(result)) delete result[name]['.index'];
    cursor.unload('wireless');
    return result;
}

function backhaul_managed(config) {
    let station = config.deco_backhaul;
    if (!station || station.mode != 'sta'
        || station.ifname != 'deco-sixsta' || station.macaddr != '02:00:00:00:00:06'
        || station.network != 'sixbh_link' || station.wds != '1'
        || config.radio2.country != 'ES' || config.radio2.channel != '37'
        || config.radio2.txpower != '10'
        || trim(fs.readfile('/sys/module/ath11k/parameters/frame_mode')) != '1') return false;
    let six = station.device == 'radio2' && station.bssid == '02:00:00:00:00:16'
        && station.encryption == 'sae' && station.ieee80211w == '2' && station.sae_pwe == '1';
    let five = station.device == 'radio1' && station.bssid == '02:00:00:00:00:15'
        && station.encryption == 'psk2+ccmp' && station.ieee80211w == '0'
        && config.radio1.country == 'ES' && config.radio1.channel == '48' && config.radio1.txpower == '10';
    if (!six && !five) return false;
    let owner = bus.call('service', 'list', { name: 'estudio_deco_backhaul' });
    return same(owner?.estudio_deco_backhaul?.instances?.adapter?.command,
        ['/bin/sh', '/tmp/estudio_deco_backhaul.sh']);
}

function backhaul_ready(config) {
    if (!config.deco_backhaul) return true;
    if (!backhaul_managed(config)) return unready('managed_backhaul');
    let owner = bus.call('service', 'list', { name: 'estudio_deco_backhaul' });
    let process = owner?.estudio_deco_backhaul?.instances?.adapter;
    let status_text = fs.readfile('/tmp/estudio-deco-backhaul-status.json');
    let status = status_text ? json(status_text) : null;
    let index = fs.readfile('/sys/class/net/deco-sixsta/ifindex');
    let bridge = bus.call('network.interface.sixbh', 'status', {});
    if (!process?.running || status?.pid != process.pid) return unready('backhaul_supervisor');
    if (status?.state != 'configured' || !index || status.ifindex != +trim(index))
        return unready('backhaul_interface');
    if (!bridge?.up || bridge.l3_device != 'br-sixbh'
        || !match(fs.readlink('/sys/class/net/sixbh.1/master') ?? '', /\/br-sixbh$/))
        return unready('backhaul_bridge');
    if (trim(fs.readfile(six_power)) != '10') return unready('sixghz_power');
    let pipe = fs.popen('/usr/sbin/wpa_cli -p /var/run/wpa_supplicant -i deco-sixsta status', 'r');
    if (!pipe) return unready('backhaul_station_read');
    let lines = split(pipe.read('all'), '\n');
    let six = config.deco_backhaul.device == 'radio2';
    let connected = pipe.close() == 0 && contains(lines, 'wpa_state=COMPLETED')
        && contains(lines, six ? 'freq=6135' : 'freq=5240')
        && (contains(lines, six ? 'bssid=02:00:00:00:00:16' : 'bssid=02:00:00:00:00:15')
            || contains(lines, six ? 'bssid=02:00:00:00:00:1a' : 'bssid=02:00:00:00:00:1f'))
        && contains(lines, six ? 'key_mgmt=SAE' : 'key_mgmt=WPA2-PSK');
    return connected || unready('backhaul_station');
}

function guest_backhaul_ready(config) {
    if (!backhaul_ready(config) || !config.deco_backhaul || config.default_radio0.network != 'sixbh') return false;
    let cursor = uci.cursor('/etc/config'), network = cursor.get_all('network');
    cursor.unload('network');
    let dual = config.deco_backhaul.deco_multilink == '1';
    if (network?.sixguest?.proto != 'none' || network.sixguest.device != 'br-sixguest'
        || network.sixguest_vlan?.type != '8021q' || network.sixguest_vlan.name != 'sixbh.2'
        || network.sixguest_vlan.ifname != 'deco-sixsta' || network.sixguest_vlan.vid != '2'
        || network.sixguest_bridge?.type != 'bridge' || network.sixguest_bridge.name != 'br-sixguest'
        || !same(network.sixguest_bridge.ports, dual ? ['sixbh.2', 'standby.2'] : ['sixbh.2'])) return false;
    if (dual && (network.sixguest_bridge.ipv6 != '0'
        || trim(fs.readfile('/proc/sys/net/ipv6/conf/br-sixguest/disable_ipv6') ?? '') != '1'
        || network.sixguest_dual_vlan?.type != '8021q'
        || network.sixguest_dual_vlan.name != 'standby.2'
        || network.sixguest_dual_vlan.ifname != 'deco-standby' || network.sixguest_dual_vlan.vid != '2'
        || !match(fs.readlink('/sys/class/net/standby.2/master') ?? '', /\/br-sixguest$/))) return false;
    let bridge = bus.call('network.interface.sixguest', 'status', {});
    return bridge?.up && bridge.l3_device == 'br-sixguest'
        && !length(bridge['ipv4-address'] ?? []) && !length(bridge['ipv6-address'] ?? [])
        && match(fs.readlink('/sys/class/net/sixbh.2/master') ?? '', /\/br-sixguest$/);
}

function guest_wireless_only_ready(config) {
    if (!guest_backhaul_ready(config)) return false;
    // Follow every Ethernet upper (VLANs and bridges included). The management
    // link may keep its own bridge, but no Ethernet path may enter the mesh.
    let pending = ['eth0', 'eth1'], seen = {};
    for (let i = 0; i < length(pending); i++) {
        if (i >= 64) return false;
        let iface = pending[i];
        if (seen[iface]) continue;
        seen[iface] = true;
        if (contains(['br-sixbh', 'br-sixguest'], iface)) return false;
        let entries = fs.lsdir('/sys/class/net/' + iface);
        if (entries == null) {
            if (iface == 'eth1' && !fs.stat('/sys/class/net/eth1')) continue;
            return false;
        }
        for (let name in entries)
            if (substr(name, 0, 6) == 'upper_') push(pending, substr(name, 6));
    }
    return true;
}

function state(name, changed, version, reason) {
    let record = { state: name, radios: changed, version,
        wireless_applied: name == 'verified', full_configuration_applied: false,
        failed_readiness_check: verification_failure,
        policy_transaction,
        request_id: active_request?.request_id, generation: active_request?.generation,
        time: time(), reason };
    write(root + '/status.json', sprintf('%J', record));
    return record;
}
function clean_delta() {
    let pipe = fs.popen('/sbin/uci changes wireless', 'r');
    require_ok(pipe, 'cannot inspect pending edits');
    let result = pipe.read('all');
    require_ok(pipe.close() == 0 && result == '', 'pending wireless edits');
}
function relay_quiesce() {
    if (relay_lock_file) return;
    // Public BSS changes can restart hostapd on the shared PHY. Close the
    // separately admitted relay before netifd removes its interfaces, and
    // prevent the backhaul owner from recreating them during this update.
    if (!fs.lstat('/tmp/estudio-mesh-relay')) return;
    relay_lock_file = fs.open('/tmp/estudio-mesh-relay-lifecycle.lock', 'a', 0600);
    require_ok(relay_lock_file && relay_lock_file.lock('x'), 'relay lifecycle lock unavailable');
    require_ok(system(['/bin/sh', '-c',
        '. /tmp/estudio_mesh_links.sh; '
        + 'link_data=$(jsonfilter -i /tmp/estudio-deco-backhaul-status.json -e "@.link_data"); '
        + 'link_broadcast=$(jsonfilter -i /tmp/estudio-deco-backhaul-status.json -e "@.link_broadcast"); '
        + 'mesh_links_close_relay_locked']) == 0, 'admitted relay could not close');
}
function relay_release() {
    if (relay_lock_file) relay_lock_file.close();
    relay_lock_file = null;
}
function reload(changed) {
    // This OpenWrt version's wifi reload ignores a radio argument and only
    // rereads configuration. Explicitly clear a stopped radio's down state.
    require_ok(system(['/sbin/wifi', 'reload']) == 0, 'wireless reload failed');
    for (let radio in changed)
        require_ok(system(['/bin/ubus', 'call', 'network.wireless', 'up',
            sprintf('%J', { device: radio })]) == 0,
            'radio could not be enabled');
}
function limit_sixghz(changed) {
    if (!contains(changed, 'radio2')) return;
    // Enforce the lab ceiling before netifd can create a transmitting interface.
    require_ok(system(['/usr/sbin/iw', 'phy', 'phy2', 'set', 'txpower', 'limit', '1000']) == 0
        && trim(fs.readfile(six_power)) == '10', '6 GHz power limit failed');
}
function restore_sixghz_power(changed) {
    if (!contains(changed, 'radio2')) return;
    let power = trim(fs.readfile(root + '/sixghz-power-before'));
    require_ok(power == '-2147483648' || (match(power, /^[0-9]+$/) && +power <= 30),
        'invalid saved radio power');
    let command = ['/usr/sbin/iw', 'phy', 'phy2', 'set', 'txpower'];
    if (power == '-2147483648') push(command, 'auto');
    else { push(command, 'limit'); push(command, sprintf('%d', +power * 100)); }
    require_ok(system(command) == 0 && trim(fs.readfile(six_power)) == power,
        'previous radio power did not recover');
}
function sixghz_ready(iface, ap) {
    if (!contains(['phy2-ap0', 'deco-i6', 'deco-g6'], iface) || ap.freq != 6135 || trim(fs.readfile(six_power)) != '10') return false;
    let config = fs.readfile('/var/run/hostapd-phy2.conf');
    if (!config) return false;
    let lines = split(config, '\n');
    for (let line in ['ieee80211w=2', 'sae_pwe=1', 'he_6ghz_reg_pwr_type=0'])
        if (!contains(lines, line)) return false;
    let pipe = fs.popen('/usr/sbin/wpa_cli -p /var/run/hostapd -i ' + iface + ' raw GET_CONFIG', 'r');
    if (!pipe) return false;
    let actual = pipe.read('all');
    if (pipe.close() != 0 || !contains(split(actual, '\n'), 'key_mgmt=SAE')) return false;
    return system('/usr/sbin/iw dev ' + iface + ' info | /bin/grep -q "txpower 10.00 dBm"') == 0;
}
function main_roaming_valid(section) {
    if (section.ieee80211r == null || section.ieee80211r == '0') {
        for (let option in keys(roaming_options)) if (section[option] != null) return false;
        return true;
    }
    if (section.ieee80211r != '1' || section.encryption != 'psk2+ccmp') return false;
    for (let option, value in roaming_options) if (section[option] != value) return false;
    return true;
}
function pairing_valid(name, section) {
    let enabled = section.wps_pushbutton;
    if (enabled == null || enabled == '0') return true;
    return enabled == '1' && contains(['default_radio0', main5], name)
        && section.disabled != '1' && (section.hidden == null || section.hidden == '0')
        && contains(['psk2+ccmp', 'sae-mixed'], section.encryption);
}
function main_security_valid(section) {
    if (!main_roaming_valid(section)) return false;
    if (section.encryption == 'psk2+ccmp')
        return (section.ieee80211w == null || section.ieee80211w == '0')
            && section.sae_pwe == null && section.sae_require_mfp == null;
    let pmf = section.encryption == 'sae' ? '2' : section.encryption == 'sae-mixed' ? '1' : null;
    return pmf && section.ieee80211w == pmf && section.sae_pwe == '2' && section.sae_require_mfp == '1';
}
function main_security_ready(iface, section) {
    // Saved OpenWrt settings may omit the default CCMP cipher suffix.
    // Accept that spelling for recovery; controller candidates stay explicit.
    if (section.encryption == 'psk2') section = { ...section, encryption: 'psk2+ccmp' };
    if (!contains(['phy0-ap0', 'phy1-ap0', 'deco-i2', 'deco-i5', 'deco-g2', 'deco-g5'], iface) || !main_security_valid(section)) return false;
    let pipe = fs.popen('/usr/sbin/wpa_cli -p /var/run/hostapd -i ' + iface + ' raw GET_CONFIG', 'r');
    if (!pipe) return false;
    let text = pipe.read('all');
    if (pipe.close() != 0) return false;
    let actual = {};
    for (let line in split(text, '\n')) {
        let pair = match(line, /^([^=]+)=(.*)$/);
        if (pair) actual[pair[1]] = pair[2];
    }
    // Basic hostapd omits this field entirely. That can prove disabled, but
    // an enabled setting needs evidence from the running full daemon.
    if ((actual.wps_state ?? 'disabled') !=
        (section.wps_pushbutton == '1' ? 'configured' : 'disabled')) return false;
    let methods = split(actual.key_mgmt ?? '', ' ');
    let expected = section.encryption == 'sae' ? ['SAE']
        : section.encryption == 'sae-mixed' ? ['SAE', 'WPA-PSK', 'WPA-PSK-SHA256'] : ['WPA-PSK'];
    if (section.ieee80211r == '1') push(expected, 'FT-PSK');
    sort(methods); sort(expected);
    if (!same(methods, expected) || actual.wpa != '2' || actual.group_cipher != 'CCMP'
        || actual.rsn_pairwise_cipher != 'CCMP') return false;
    let config = fs.readfile(section.device == 'radio0' ? '/var/run/hostapd-phy0.conf' : '/var/run/hostapd-phy1.conf');
    if (!config) return false;
    let selected = false, options = {};
    for (let line in split(config, '\n')) {
        let block = match(line, /^(interface|bss)=(.*)$/);
        if (block) { selected = block[2] == iface; continue; }
        let pair = match(line, /^(ieee80211w|sae_pwe|sae_require_mfp|mobility_domain|nas_identifier|ft_psk_generate_local|ft_over_ds|reassociation_deadline)=(.*)$/);
        if (selected && pair) options[pair[1]] = pair[2];
    }
    if (section.ieee80211r == '1') {
        for (let option, value in roaming_options)
            if (options[option == 'nasid' ? 'nas_identifier' : option] != value) return false;
    }
    if ((options.ieee80211w ?? '0') != (section.ieee80211w ?? '0')) return false;
    return section.encryption == 'psk2+ccmp' || (options.sae_pwe == '2' && options.sae_require_mfp == '1');
}
function iot_valid(section, definition, config) {
    require_ok(section['.type'] == 'wifi-iface' && section.deco_iot_owned == '1',
        'IoT section is not adapter-owned');
    let allowed = [...mutable, ...isolation_options, 'device', 'mode', 'network', 'ifname', 'macaddr', 'deco_iot_owned',
        '.type', '.name', '.index', '.anonymous'];
    for (let key in keys(section)) require_ok(contains(allowed, key), 'unexpected IoT AP option');
    require_ok(section.mode == 'ap' && section.device == definition.device
        && section.ifname == definition.ifname && section.macaddr == definition.macaddr
        && same(section.network, config[definition.main].network), 'unsafe IoT AP attachment');
    require_ok(section.disabled == '0' || section.disabled == '1', 'invalid IoT switch');
    require_ok(section.hidden == '0' && section.ieee80211r == '0', 'unsupported IoT AP behavior');
    require_ok(contains(['psk2+ccmp', 'psk-mixed+tkip+ccmp'], section.encryption),
        'unsupported IoT AP encryption');
    require_ok(type(section.ssid) == 'string' && length(section.ssid) >= 1 && length(section.ssid) <= 32,
        'invalid IoT AP name');
    require_ok(type(section.key) == 'string' && length(section.key) >= 8 && length(section.key) <= 63,
        'invalid IoT AP key');
}
function guest_valid(section, definition, config) {
    require_ok(section['.type'] == 'wifi-iface' && section.deco_guest_owned == '1', 'guest section is not adapter-owned');
    let allowed = [...main_ap_mutable, 'device', 'mode', 'network', 'ifname', 'macaddr', 'isolate', 'deco_guest_owned',
        '.type', '.name', '.index', '.anonymous'];
    for (let option in keys(section)) require_ok(contains(allowed, option), 'unexpected guest AP option');
    require_ok(section.mode == 'ap' && section.device == definition.device && section.ifname == definition.ifname
        && section.macaddr == definition.macaddr && section.network == 'sixguest', 'unsafe guest AP attachment');
    require_ok(section.hidden == '0' && section.ieee80211r == '0' && section.isolate == '1'
        && contains(['0', '1'], section.disabled), 'unsupported guest AP behavior');
    require_ok(type(section.ssid) == 'string' && length(section.ssid) >= 1 && length(section.ssid) <= 32, 'invalid guest AP name');
    require_ok(type(section.key) == 'string' && length(section.key) >= 8 && length(section.key) <= 63, 'invalid guest AP key');
    if (definition.device == 'radio2')
        require_ok(section.encryption == 'sae' && section.ieee80211w == '2' && section.sae_pwe == '1'
            && section.sae_require_mfp == '1' && config.radio2.channel == '37' && config.radio2.htmode == 'HE20'
            && config.radio2.txpower == '10' && config.radio2.reg_power_type == '0', 'unsafe 6 GHz guest settings');
    else require_ok(main_security_valid(section), 'unsupported guest AP encryption');
    require_ok(guest_backhaul_ready(config), 'guest backhaul is unavailable');
}
function guest_ready(iface, section, config) {
    if (!guest_backhaul_ready(config)) return false;
    if (section.device != 'radio2' && !main_security_ready(iface, section)) return false;
    let index = section.device == 'radio0' ? '0' : section.device == 'radio1' ? '1' : '2';
    let text = fs.readfile('/var/run/hostapd-phy' + index + '.conf');
    if (!text) return false;
    let selected = false, isolated = false;
    for (let line in split(text, '\n')) {
        let block = match(line, /^(interface|bss)=(.*)$/);
        if (block) { selected = block[2] == iface; continue; }
        if (selected && line == 'ap_isolate=1') isolated = true;
    }
    return isolated;
}
function iot_ready(iface, section) {
    if (!contains(['deco-t2', 'deco-t5', 'deco-ti2', 'deco-ti5'], iface)) return false;
    let pipe = fs.popen('/usr/sbin/wpa_cli -p /var/run/hostapd -i ' + iface + ' raw GET_CONFIG', 'r');
    if (!pipe) return false;
    let result = pipe.read('all');
    if (pipe.close() != 0) return false;
    let config = {};
    for (let line in split(result, '\n')) {
        let pair = match(line, /^([^=]+)=(.*)$/);
        if (pair) config[pair[1]] = pair[2];
    }
    if (config.key_mgmt != 'WPA-PSK') return false;
    if (section.encryption == 'psk2+ccmp')
        return config.wpa == '2' && config.group_cipher == 'CCMP' && config.rsn_pairwise_cipher == 'CCMP';
    return config.wpa == '3' && config.group_cipher == 'TKIP'
        && contains(split(config.rsn_pairwise_cipher ?? '', ' '), 'CCMP')
        && contains(split(config.wpa_pairwise_cipher ?? '', ' '), 'TKIP');
}
function acl_ready(iface, section) {
    if (section.deco_isolation_owned != '1') return true;
    if (!contains(['phy0-ap0', 'phy1-ap0', 'phy2-ap0', 'deco-t2', 'deco-t5',
        'deco-i2', 'deco-i5', 'deco-i6', 'deco-ti2', 'deco-ti5'], iface)) return false;
    let command = section.macfilter == 'allow' ? 'ACCEPT_ACL' : 'DENY_ACL';
    let pipe = fs.popen('/usr/sbin/wpa_cli -p /var/run/hostapd -i ' + iface + ' raw ' + command + ' SHOW', 'r');
    if (!pipe) return false;
    let result = pipe.read('all'), addresses = [];
    if (pipe.close() != 0) return false;
    for (let line in split(result, '\n')) {
        let address = match(line, /^([0-9a-f]{2}(:[0-9a-f]{2}){5})(\s|$)/);
        if (address) push(addresses, address[1]);
    }
    sort(addresses);
    return same(addresses, section.maclist);
}
function beamforming_ready(radio, section) {
    if (section.he_su_beamformer == null) return true;
    let he = match(section.htmode ?? '', /^HE/);
    let vht = section.band == '5g' && match(section.htmode ?? '', /^(VHT|HE)/);
    if (!he && !vht) return true;
    let config = fs.readfile('/var/run/hostapd-phy' + substr(radio, 5) + '.conf');
    if (!config) return false;
    let actual = {};
    for (let line in split(config, '\n')) {
        if (match(line, /^(interface|bss)=/)) break;
        let pair = match(line, /^([^=]+)=(.*)$/);
        if (pair) actual[pair[1]] = pair[2];
    }
    if (he) {
        // All three guarded XE75 radios advertise SU support. MU support is
        // driver-dependent; never require a flag that its capability mask drops.
        if (actual.ieee80211ax != '1') return false;
        for (let option in ['he_su_beamformer', 'he_su_beamformee'])
            if (actual[option] != section[option]) return false;
        if (section.he_mu_beamformer == '0' && actual.he_mu_beamformer != '0') return false;
    }
    if (vht) {
        for (let option, capability in { su_beamformer: 'SU-BEAMFORMER', su_beamformee: 'SU-BEAMFORMEE',
                mu_beamformer: 'MU-BEAMFORMER', mu_beamformee: 'MU-BEAMFORMEE' }) {
            let advertised = index(actual.vht_capab ?? '', '[' + capability + ']') >= 0;
            if (section[option] == '0' && advertised) return false;
            if (match(option, /^su_/) && section[option] == '1' && !advertised) return false;
        }
    }
    return true;
}
function ready(expected, changed, policy) {
    readiness_failure = null;
    if (!backhaul_ready(expected)) return false;
    if (policy != null && policy_read() != policy) return unready('isolation_policy');
    let bridge = bus.call('network.interface.wifitest', 'status', {});
    if (expected[main5].network == 'wifitest' && (!bridge?.up || bridge.l3_device != 'br-wifitest')) return unready('public_bridge');
    if (policy) {
        let context = json(fs.readfile(root + '/candidate/isolation-context.json'));
        if (!context || !same(context, policy_context(expected, context.isolated_ports))) return unready('isolation_context');
    }
    let status = bus.call('network.wireless', 'status', {});
    if (type(status) != 'object') return unready('wireless_status');
    for (let radio in changed) {
        // A disabled radio is ready when it has stopped, including after an
        // option changes on one of its disabled AP sections.
        if (expected[radio]?.disabled == '1') {
            if (!status[radio]?.disabled || status[radio].up || status[radio].pending
                || length(status[radio].interfaces ?? [])) return unready('disabled_radio_live');
            continue;
        }
        if (!status[radio]?.up || status[radio]?.pending) return unready('radio_not_ready');
        if (!beamforming_ready(radio, expected[radio])) return unready('radio_beamforming');
        for (let entry in status[radio].interfaces)
            if (!expected[entry.section]) return unready('unexpected_ap_section');
        for (let name, definition in iot_aps)
            if (definition.device == radio && (!expected[name] || expected[name].disabled == '1')
                && fs.stat('/sys/class/net/' + definition.ifname)) return unready('disabled_iot_ap_live');
        for (let name, definition in guest_aps)
            if (definition.device == radio && (!expected[name] || expected[name].disabled == '1')
                && fs.stat('/sys/class/net/' + definition.ifname)) return unready('disabled_guest_ap_live');
        for (let name, definition in isolated_aps)
            if (definition.device == radio && (!expected[name] || expected[name].disabled == '1')
                && fs.stat('/sys/class/net/' + definition.ifname)) return unready('disabled_isolation_ap_live');
        for (let name, section in expected) {
            if (section['.type'] != 'wifi-iface' || section.mode != 'ap' || section.device != radio) continue;
            let iface = null;
            for (let entry in status[radio].interfaces)
                if (entry.section == name) iface = entry.ifname;
            if (section.disabled == '1') {
                if (iface) return unready('disabled_ap_live');
                continue;
            }
            if (!iface) return unready('ap_missing');
            if (!contains(['wifitest', 'sixbh', 'sixguest'], section.network)) return unready('ap_network');
            if (section.network == 'sixguest' && !guest_aps[name]) return unready('unowned_guest_ap');
            if (section.network == 'sixbh' && !expected.deco_backhaul) return unready('ap_backhaul_missing');
            let network = bus.call('network.interface.' + section.network, 'status', {});
            let bridge_name = section.network == 'sixbh' ? 'br-sixbh' : section.network == 'sixguest' ? 'br-sixguest' : 'br-wifitest';
            let master = split(fs.readlink('/sys/class/net/' + iface + '/master') ?? '', '/');
            if (!network?.up || network.l3_device != bridge_name || pop(master) != bridge_name) return unready('ap_bridge');
            let ap = bus.call('hostapd.' + iface, 'get_status', {});
            if (ap?.status != 'ENABLED' || ap?.ssid != section.ssid) return unready('ap_state');
            if (radio == 'radio2' && !sixghz_ready(iface, ap)) return unready('sixghz_ap');
            if (contains(['default_radio0', main5, 'dec_iso2', 'dec_iso5'], name)
                && !main_security_ready(iface, section)) return unready('public_ap_security');
            if (iot_aps[name] && !iot_ready(iface, section)) return unready('iot_ap_security');
            if (guest_aps[name] && !guest_ready(iface, section, expected)) return unready('guest_ap_security_bridge');
            if (name == 'dec_ioti2' || name == 'dec_ioti5')
                if (!iot_ready(iface, section)) return unready('isolated_iot_ap_security');
            if (!acl_ready(iface, section)) return unready('ap_access_policy');
        }
    }
    // Managed mesh traffic lives in the retained client namespace. A root
    // management WAN cannot prove that path, and fresh images have none.
    if (expected.deco_backhaul && !fs.stat('/var/run/netns/codex-sixbh-client'))
        return unready('retained_internet');
    let command = expected.deco_backhaul
        ? '/sbin/ip netns exec codex-sixbh-client /bin/ping -q -c 1 -W 1 1.1.1.1 >/dev/null 2>&1'
        : '/bin/ping -q -c 1 -W 1 1.1.1.1 >/dev/null 2>&1';
    return system(command) == 0
        || unready('retained_internet');
}
function radio_setup_complete(expected, changed) {
    let status = bus.call('network.wireless', 'status', {});
    if (type(status) != 'object') return false;
    for (let radio in changed) {
        let actual = status[radio];
        if (!actual || actual.pending) return false;
        if (expected[radio]?.disabled == '1') {
            if (!actual.disabled || actual.up || length(actual.interfaces ?? [])) return false;
            continue;
        }
        if (!actual.up) return false;
        for (let entry in actual.interfaces) if (!expected[entry.section]) return false;
        for (let name, section in expected) {
            if (section['.type'] != 'wifi-iface' || section.mode != 'ap' || section.device != radio) continue;
            let iface = null;
            for (let entry in actual.interfaces) if (entry.section == name) iface = entry.ifname;
            if (section.disabled == '1') { if (iface) return false; continue; }
            if (!iface) return false;
            let ap = bus.call('hostapd.' + iface, 'get_status', {});
            if (ap?.status != 'ENABLED' || ap?.ssid != section.ssid) return false;
        }
        for (let name, definition in guest_aps)
            if (definition.device == radio && (!expected[name] || expected[name].disabled == '1')
                && fs.stat('/sys/class/net/' + definition.ifname)) return false;
    }
    return true;
}
function verify(expected, changed, policy) {
    let stable = 0;
    for (let attempt = 0; attempt < 35; attempt++) {
        // Keep admission closed during netifd's radio work, but let the
        // backhaul helper adopt/recover the new station before checking it.
        if (relay_lock_file && radio_setup_complete(expected, changed)) relay_release();
        stable = ready(expected, changed, policy) ? stable + 1 : 0;
        if (stable >= 5) return true;
        sleep(1000);
    }
    verification_failure = readiness_failure ?? 'insufficient_stable_samples';
    return false;
}
function restore(label, reason) {
    let journal = json(fs.readfile(root + '/status.json'));
    verification_failure = verification_failure ?? journal?.failed_readiness_check;
    let before = fs.readfile(root + '/before/wireless');
    let candidate = fs.readfile(root + '/candidate/wireless');
    require_ok(journal && before && candidate, 'missing recovery data');
    active_request = { request_id: journal.request_id, generation: journal.generation };
    policy_transaction = !!journal.policy_transaction;
    for (let radio in journal.radios) require_ok(contains(radios, radio), 'invalid recovery radio');
    clean_delta();
    let current = fs.readfile(live);
    require_ok(current == before || current == candidate, 'wireless changed outside this transaction');
    state('restoring', journal.radios, journal.version, reason);
    try {
        relay_quiesce();
        if (policy_transaction) {
            quiesce(journal.radios);
            policy_replace('before');
        }
        limit_sixghz(journal.radios);
        write(live, before);
        reload(journal.radios);
        require_ok(verify(package_at(root + '/before'), journal.radios,
            policy_transaction ? fs.readfile(root + '/before/isolation.nft') : null), 'restored radios did not recover');
        require_ok(fs.readfile(live) == before, 'restored wireless changed unexpectedly');
        restore_sixghz_power(journal.radios);
        relay_release();
        return state(label, journal.radios, journal.version, reason);
    }
    catch (error) { relay_release(); die(error.message); }
}

function recover() {
    // The kernel lock proves no native worker still owns this transaction.
    // Stop admissions first; an old request is rejected, never replayed.
    fs.unlink(input + '/service.json');
    let journal = fs.stat(root + '/status.json') ? json(fs.readfile(root + '/status.json')) : null;
    let processing = fs.stat(input + '/processing/request.json')
        ? json(fs.readfile(input + '/processing/request.json')) : null;
    let interrupted = journal && (contains(['prepared', 'applying', 'verifying', 'restoring'], journal.state)
        || (journal.state == 'verified' && processing?.request_id
            && processing.request_id == journal.request_id));
    let result = interrupted ? restore('rolled_back', 'interrupted settings transaction')
        : { state: 'idle', wireless_applied: false, full_configuration_applied: false };
    for (let name in ['preparing', 'pending', 'processing']) {
        let path = input + '/' + name;
        if (!fs.stat(path)) continue;
        let request = fs.stat(path + '/request.json') ? json(fs.readfile(path + '/request.json')) : null;
        if (type(request?.request_id) == 'string' && length(request.request_id) == 32
            && match(request.request_id, /^[0-9a-f]+$/)) {
            write(input + '/receipt.json', sprintf('%J', {
                request_id: request.request_id, generation: request.generation,
                version: request.version, state: 'failed', wireless_applied: false,
                full_configuration_applied: false, reason: 'native worker interrupted', time: time()
            }));
        }
        for (let file in ['before', 'wireless', 'plan.json', 'request.json']) {
            if (fs.stat(path + '/' + file))
                require_ok(fs.unlink(path + '/' + file), 'cannot remove abandoned settings');
        }
        require_ok(fs.rmdir(path), 'unexpected abandoned handoff contents');
    }
    active_request = null;
    return result;
}
function apply(source) {
    verification_failure = null;
    source ??= input;
    clean_delta();
    if (fs.stat(root + '/status.json')) {
        let previous = json(fs.readfile(root + '/status.json'));
        require_ok(contains(['verified', 'restored', 'rolled_back'], previous?.state),
            'previous transaction requires recovery');
    }
    let before = fs.readfile(source + '/before');
    let candidate = fs.readfile(source + '/wireless');
    let plan = json(fs.readfile(source + '/plan.json'));
    require_ok(before && candidate && plan?.validated && plan.applied == false, 'missing validated candidate');
    require_ok(type(plan.unsupported) == 'array' && !length(plan.unsupported), 'unsupported settings remain');
    require_ok(type(plan.isolated_clients) == 'array', 'invalid isolation plan');
    require_ok(type(plan.iot_enabled) == 'bool', 'invalid IoT plan');
    require_ok(type(plan.guest_enabled) == 'bool' && type(plan.guest_6g_enabled) == 'bool', 'invalid guest plan');
    require_ok(fs.readfile(live) == before, 'stale wireless baseline');
    let old = package_at('/etc/config');
    let next = package_at(source);
    if (plan.guest_ethernet_default_retained != null)
        require_ok(type(plan.guest_ethernet_default_retained) == 'bool', 'invalid guest Ethernet retention plan');
    if (plan.guest_ethernet_default_retained)
        require_ok(plan.guest_enabled && guest_wireless_only_ready(old),
            'guest Ethernet metadata requires wireless-only mesh');
    let beamforming_mutable = [];
    if (plan.beamforming != null) {
        require_ok(type(plan.beamforming) == 'bool', 'invalid beamforming plan');
        beamforming_mutable = beamforming_options;
        for (let radio in radios)
            for (let option in beamforming_options)
                require_ok(next[radio]?.[option] == (plan.beamforming ? '1' : '0'),
                    'beamforming plan and radio settings disagree');
    }
    for (let name, section in next)
        if (section['.type'] == 'wifi-iface' && section.mode == 'ap')
            require_ok(pairing_valid(name, section), 'invalid AP pairing setting');
    isolation_valid(old);
    require_ok(same(isolation_valid(next), plan.isolated_clients), 'isolation plan and configuration disagree');
    for (let name in keys(iot_aps))
        require_ok(!!next[name] == plan.iot_enabled, 'IoT plan and configuration disagree');
    for (let name in keys(guest_aps))
        require_ok(!!next[name] == (name == 'deco_guest6' ? plan.guest_6g_enabled : plan.guest_enabled),
            'guest plan and configuration disagree');
    let changed = [];
    let sections = keys(old);
    for (let name in keys(next)) if (!old[name]) push(sections, name);
    for (let name in sections) {
        let section = old[name];
        let target = next[name];
        if (isolated_aps[name]) {
            if (!same(section, target) && !contains(changed, isolated_aps[name].device))
                push(changed, isolated_aps[name].device);
            continue;
        }
        if (iot_aps[name]) {
            if (section) iot_valid(section, iot_aps[name], old);
            if (target) iot_valid(target, iot_aps[name], next);
            if (!same(section, target) && !contains(changed, iot_aps[name].device))
                push(changed, iot_aps[name].device);
            continue;
        }
        if (guest_aps[name]) {
            if (section) guest_valid(section, guest_aps[name], old);
            if (target) guest_valid(target, guest_aps[name], next);
            if (!same(section, target) && !contains(changed, guest_aps[name].device)) push(changed, guest_aps[name].device);
            continue;
        }
        require_ok(section, 'unexpected wireless section added');
        require_ok(target, 'wireless section removed');
        if (same(section, target)) continue;
        require_ok(contains(aps, name) || contains(radios, name), 'non-AP settings changed');
        let options = name == 'radio2' ? [...six_radio_mutable, ...beamforming_mutable]
            : contains(radios, name) ? beamforming_mutable
            : name == 'default_radio2' ? [...six_ap_mutable, ...isolation_options] : [...main_ap_mutable, ...isolation_options];
        if (section.macfilter && section.deco_isolation_owned != '1')
            require_ok(same(section.macfilter, target.macfilter) && same(section.maclist, target.maclist),
                'unowned access policy changed');
        for (let key in keys(section)) {
            if (key == '.index' || contains(options, key)) continue;
            require_ok(same(section[key], target[key]), 'protected AP option changed');
        }
        for (let key in keys(target)) {
            if (key == '.index' || contains(options, key)) continue;
            require_ok(same(section[key], target[key]), 'unexpected AP option');
        }
        if (contains(radios, name)) {
            let only_beamforming = true;
            for (let key in [...keys(section), ...keys(target)])
                if (key != '.index' && !contains(beamforming_mutable, key) && !same(section[key], target[key]))
                    only_beamforming = false;
            if (only_beamforming) {
                require_ok(target['.type'] == 'wifi-device' && target.type == 'mac80211', 'invalid beamforming radio');
                if (!contains(changed, name)) push(changed, name);
                continue;
            }
        }
        if (name == 'radio2') {
            require_ok(target.type == 'mac80211' && target.band == '6g'
                && target.path == 'platform/soc@0/b00b040.wifi'
                && target.disabled == '0' && target.channel == '37' && target.htmode == 'HE20'
                && target.txpower == '10' && target.reg_power_type == '0', 'unsupported 6 GHz radio settings');
            if (!contains(changed, name)) push(changed, name);
            continue;
        }
        require_ok(target.mode == 'ap' && contains(radios, target.device), 'invalid AP target');
        require_ok(target.disabled == '0' || target.disabled == '1', 'invalid AP switch');
        require_ok(name == 'default_radio2'
            ? target.ieee80211r == null || target.ieee80211r == '0'
            : main_roaming_valid(target), 'unsupported roaming settings');
        if (target.disabled != '1') {
            require_ok(type(target.ssid) == 'string' && length(target.ssid) >= 1 && length(target.ssid) <= 32, 'invalid AP name');
            require_ok(type(target.key) == 'string' && length(target.key) >= 8 && length(target.key) <= 63, 'invalid AP key');
            if (name == 'default_radio2') {
                require_ok(target.device == 'radio2' && target.encryption == 'sae'
                    && target.ieee80211w == '2' && target.sae_pwe == '1'
                    && same(target.network, next[main5].network)
                    && target.macaddr == '02:00:00:00:00:05', 'unsafe 6 GHz AP settings');
                require_ok(next.radio2.channel == '37' && next.radio2.htmode == 'HE20'
                    && next.radio2.txpower == '10' && next.radio2.reg_power_type == '0',
                    'unsafe 6 GHz operating point');
            }
            else require_ok(main_security_valid(target), 'unsupported AP encryption');
        }
        if (!contains(changed, target.device)) push(changed, target.device);
    }
    for (let radio in radios) require_ok(next[radio]?.country == 'ES', 'unexpected country');
    if (!length(changed)) {
        // A retry must verify the live state without cycling radios or replacing
        // the last mutation's recovery journal with an empty transaction.
        let actual_policy = policy_read();
        if (length(plan.isolated_clients)) {
            let previous = json(fs.readfile(root + '/status.json'));
            let location = previous?.state == 'verified' ? 'candidate' : 'before';
            require_ok(previous?.policy_transaction && actual_policy != ''
                && actual_policy == fs.readfile(root + '/' + location + '/isolation.nft'),
                'unchanged configuration has different isolation rules');
        }
        else require_ok(actual_policy == '', 'unexpected isolation rules for unchanged settings');
        let enabled_radios = filter(radios, (radio) => next[radio].disabled != '1');
        require_ok(verify(next, enabled_radios, actual_policy), 'unchanged configuration is not operational');
        require_ok(fs.readfile(live) == before, 'wireless changed during unchanged verification');
        return { state: 'verified', version: plan.version, radios: [], no_op: true,
            wireless_applied: true, full_configuration_applied: false };
    }
    fs.mkdir(root, 0700);
    fs.mkdir(root + '/before', 0700);
    fs.mkdir(root + '/candidate', 0700);
    policy_prepare(plan.isolated_clients, next);
    write(root + '/before/wireless', before);
    write(root + '/candidate/wireless', candidate);
    if (contains(changed, 'radio2')) write(root + '/sixghz-power-before', trim(fs.readfile(six_power)));
    state('prepared', changed, plan.version);
    // Recheck immediately before the single file replacement.
    require_ok(fs.readfile(live) == before, 'baseline changed during preparation');
    state('applying', changed, plan.version);
    try {
        relay_quiesce();
        if (policy_transaction) {
            quiesce(changed);
            policy_replace('candidate');
        }
        limit_sixghz(changed);
        write(live, candidate);
        reload(changed);
        state('verifying', changed, plan.version);
        require_ok(verify(next, changed, policy_transaction ? fs.readfile(root + '/candidate/isolation.nft') : null),
            'applied radios did not recover');
        require_ok(fs.readfile(live) == candidate, 'wireless changed during verification');
        relay_release();
        return state('verified', changed, plan.version);
    }
    catch (error) {
        // Error text can contain configuration data; persist only a fixed reason.
        diagnostic(error);
        try { restore('rolled_back', 'wireless application or verification failed'); }
        catch (recovery_error) { relay_release(); die(recovery_error.message); }
        relay_release();
        die('wireless application failed; previous settings restored');
    }
}

function receive(continuous, acknowledge_configuration) {
    clean_delta();
    fs.mkdir(input, 0700);
    for (let name in ['preparing', 'pending', 'processing'])
        require_ok(!fs.stat(input + '/' + name), 'previous handoff requires inspection');
    let generation = trim(fs.readfile('/proc/sys/kernel/random/uuid'));
    let expires = time() + 120;
    let service = { accepting: true, generation, expires, acknowledge_configuration };
    let before_path = '/tmp/oem-mesh-peer/private/openwrt-before';
    fs.mkdir(before_path, 0700);
    write(before_path + '/wireless', fs.readfile(live));
    write(input + '/service.json', sprintf('%J', service));
    let answer;
    try {
        while (continuous || time() < expires) {
            if (fs.stat(input + '/stop')) {
                require_ok(continuous, 'native receiver stopped');
                break;
            }
            // Renew an unused admission only when no producer is preparing it.
            // A queued request always retains its original expiry and identity.
            if (continuous && time() >= expires && !fs.stat(input + '/pending')
                && !fs.stat(input + '/preparing')) {
                clean_delta();
                generation = trim(fs.readfile('/proc/sys/kernel/random/uuid'));
                expires = time() + 120;
                write(before_path + '/wireless', fs.readfile(live));
                service = { accepting: true, generation, expires, acknowledge_configuration };
                write(input + '/service.json', sprintf('%J', service));
            }
            if (!fs.stat(input + '/pending')) { sleep(250); continue; }
            require_ok(fs.rename(input + '/pending', input + '/processing'), 'cannot claim settings');
            service.accepting = false;
            write(input + '/service.json', sprintf('%J', service));
            let path = input + '/processing';
            let request = json(fs.readfile(path + '/request.json'));
            let plan = json(fs.readfile(path + '/plan.json'));
            let admitted = request?.generation == generation && request.expires == expires && time() < expires;
            require_ok(type(request.request_id) == 'string' && length(request.request_id) == 32
                && match(request.request_id, /^[0-9a-f]+$/), 'invalid request identity');
            require_ok(request.version == plan?.version, 'handoff version mismatch');
            if (!admitted) {
                // A producer can queue just as its admission expires. Refuse
                // the settings, then reopen admission instead of stopping the
                // continuous receiver for all subsequent controller updates.
                answer = { state: 'failed', wireless_applied: false,
                    full_configuration_applied: false, version: request.version,
                    reason: 'expired or foreign worker request' };
            }
            else {
                active_request = request;
                try { answer = apply(path); }
                catch (error) {
                    diagnostic(error);
                    answer = { state: 'failed', wireless_applied: false,
                        full_configuration_applied: false, version: request.version,
                        reason: 'native application failed; inspect transaction status' };
                }
            }
            answer.request_id = request.request_id;
            answer.generation = request.generation;
            write(input + '/receipt.json', sprintf('%J', answer));
            for (let name in ['before', 'wireless', 'plan.json', 'request.json'])
                require_ok(fs.unlink(path + '/' + name), 'cannot remove consumed settings');
            require_ok(fs.rmdir(path), 'cannot remove consumed handoff');
            if (!continuous || (admitted && answer.state != 'verified')) break;
            if (!admitted) answer = null;
            active_request = null;
            clean_delta();
            generation = trim(fs.readfile('/proc/sys/kernel/random/uuid'));
            expires = time() + 120;
            write(before_path + '/wireless', fs.readfile(live));
            service = { accepting: true, generation, expires, acknowledge_configuration };
            write(input + '/service.json', sprintf('%J', service));
        }
        require_ok(answer || continuous, 'native receiver timed out');
    }
    catch (error) {
        fs.unlink(input + '/service.json');
        die(error.message);
    }
    fs.unlink(input + '/service.json');
    require_ok(!answer || answer.state == 'verified', 'native settings request failed');
    return answer ?? { state: 'idle', wireless_applied: false, full_configuration_applied: false };
}

let locked = false;
let lock_file = null;
try {
    require_ok(trim(fs.readfile('/sys/class/net/eth0/address')) == '02:00:00:00:00:19', 'wrong hardware');
    require_ok(storage_ok(), 'flash access is enabled');
    let current_config = package_at('/etc/config');
    if (current_config.deco_backhaul)
        require_ok(backhaul_managed(current_config), 'private backhaul is not supervised');
    if (fs.stat('/tmp/codex-sixsta-active'))
        require_ok(backhaul_managed(current_config), 'unmanaged radio experiment is active');
    for (let marker in ['codex-backhaul-probe-active', 'codex-mesh-wifi-apply-active',
        'codex-sixghz-probe-active', 'codex-wifi-policy-active'])
        require_ok(!fs.stat('/tmp/' + marker), 'another radio experiment is active');
    lock_file = fs.open(lock, 'a', 0600);
    require_ok(bus && lock_file && lock_file.lock('xn'), 'another apply transaction is active');
    locked = true;
    // Keep the existing activity marker for operational checks. It is no longer
    // lock authority and is reclaimed only after obtaining the real lock.
    fs.rmdir(active);
    require_ok(fs.mkdir(active, 0700), 'invalid activity marker');
    let result;
    if (ARGV[0] == 'apply') result = apply();
    else if (ARGV[0] == 'restore') result = restore('restored', 'explicit recovery');
    else if (ARGV[0] == 'recover') result = recover();
    else if (contains(['receive', 'serve', 'receive-config', 'serve-config'], ARGV[0])) {
        recover();
        result = receive(contains(['serve', 'serve-config'], ARGV[0]),
            contains(['receive-config', 'serve-config'], ARGV[0]));
    }
    else die('expected apply, receive, serve, receive-config, serve-config, recover or restore');
    fs.rmdir(active);
    lock_file.close();
    print(sprintf('%J\n', result));
}
catch (error) {
    relay_release();
    if (locked) fs.rmdir(active);
    if (lock_file) lock_file.close();
    // These errors contain only the fixed messages above, never configuration.
    warn('Wi-Fi transaction failed: ', error.message, '\n');
    exit(1);
}

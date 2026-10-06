// SPDX-License-Identifier: MIT
// Shared native bridge-rule generator. Only structured, validated values can
// enter nft syntax; the controller never supplies an executable ruleset.
function mac(value) {
    if (type(value) != 'string'
        || !match(value, /^[0-9a-f][02468ace](:[0-9a-f]{2}){5}$/)) die('invalid isolation MAC');
    return value;
}
function name(value) {
    if (type(value) != 'string' || !length(value) || length(value) > 15
        || !match(value, /^[A-Za-z0-9_.-]+$/)) die('invalid isolation interface');
    return sprintf('"%s"', value);
}
export function render(clients, network) {
    if (type(clients) != 'array' || type(network.isolated_ports) != 'array'
        || !length(network.isolated_ports)) die('missing isolation ports');
    let addresses = [], ports = [];
    for (let value in clients) push(addresses, mac(value));
    for (let value in network.isolated_ports) push(ports, name(value));
    let gateway = mac(network.gateway_mac);
    let elements = length(addresses) ? 'elements = { ' + join(', ', addresses) + ' };' : '';
    return sprintf('table bridge deco_clients {\n'
        + '  set isolated { type ether_addr; %s }\n'
        + '  set isolated_ports { type ifname; elements = { %s }; }\n'
        + '  chain forward {\n'
        + '    type filter hook forward priority -200; policy accept;\n'
        + '    meta ibrname != %s return\n'
        + '    ether saddr %s accept\n'
        + '    ether saddr @isolated ether daddr %s accept\n'
        + '    ether saddr @isolated ether daddr @isolated accept\n'
        + '    ether saddr @isolated ether daddr & 02:00:00:00:00:01 == 02:00:00:00:00:01 oifname @isolated_ports accept\n'
        + '    ether saddr @isolated ether daddr & 02:00:00:00:00:01 == 02:00:00:00:00:01 oifname %s accept\n'
        + '    ether saddr @isolated counter drop\n'
        + '    ether daddr @isolated counter drop\n'
        + '    oifname @isolated_ports ether daddr & 02:00:00:00:00:01 == 02:00:00:00:00:01 counter drop\n'
        + '  }\n}\n', elements, join(', ', ports), name(network.bridge), gateway, gateway, name(network.uplink));
}

// SPDX-License-Identifier: MIT
// Assemble one bounded observation cycle only after both native collectors and
// their final membership checks succeeded. Contexts are owned by the publisher.
import * as fs from 'fs';
const owner='520C7831F7302242F81407BC050E7E7C4B5C697F';
if (length(ARGV)!=5) die('expected Wi-Fi context, wired context, cycle directory, generation and sequence');
function read(path) {
    let data=fs.readfile(path);
    if (!data || length(data)>1048576) die('node collection input unavailable');
    return json(data);
}
let wifi_context=read(ARGV[0]), wired_context=read(ARGV[1]), cycle=ARGV[2];
if (wifi_context.device_id!=owner || wired_context.device_id!=owner
    || !match(ARGV[3],/^[0-9a-f-]{36}$/) || !match(ARGV[4],/^[0-9]+$/)) die('invalid node collection owner');
function interfaces(items, wired) {
    if (type(items)!='array') die('invalid node coverage');
    let names=[],seen={};
    for (let item in items) {
        if (wired && item.role!='client') continue;
        if (type(item.interface)!='string' || seen[item.interface]) die('duplicate node coverage');
        seen[item.interface]=true;push(names,item.interface);
    }
    sort(names);return names;
}
let coverage={version:1,device_id:owner,generation:ARGV[3],sources:[
    {scope:'wifi-associations',interfaces:interfaces(wifi_context.aps,false)},
    {scope:wired_context.switch ? 'wired-switch' : 'wired-forwarding',
        interfaces:wired_context.switch ? [wired_context.interface] : interfaces(wired_context.ports,true)}]};
function same_clients(first,last,wifi) {
    if (length(first.clients)!=length(last.clients)) die('node clients changed during collection');
    let remaining={};
    for (let row in first.clients) remaining[row.mac]=row;
    for (let row in last.clients) {
        let old=remaining[row.mac];
        if (!old || old.interface!=row.interface || old.network_type!=row.network_type
            || old.physical_port!=row.physical_port
            || (wifi && old.association_id!=row.association_id)) die('node client moved during collection');
        delete remaining[row.mac];
    }
    if (length(remaining)) die('node client left during collection');
    if (!wifi) {
        if (length(first.port_generations)!=length(last.port_generations)) die('wired port scope changed');
        for (let port,generation in first.port_generations)
            if (last.port_generations[port]!=generation) die('wired port replaced during collection');
    }
}
same_clients(read(cycle+'/wifi-first.json'),read(cycle+'/wifi-last.json'),true);
same_clients(read(cycle+'/wired-first.json'),read(cycle+'/wired-last.json'),false);
let sources=[read(cycle+'/wifi-report.json'),read(cycle+'/wired-report.json')],seen={},all_interfaces={};
for (let i,source in sources) {
    if (source.device_id!=owner || source.scope!=coverage.sources[i].scope
        || type(source.observed_at)!='int' || source.observed_at>time()
        || time()-source.observed_at>30) die('stale or invalid node source');
    let names=sort(source.interfaces);
    if (join(',',names)!=join(',',coverage.sources[i].interfaces)) die('node coverage changed');
    for (let name in names) {
        if (all_interfaces[name]) die('overlapping node sources');
        all_interfaces[name]=true;
    }
    for (let client in source.client_list) {
        if (seen[client.mac]) die('client claimed by two node sources');
        seen[client.mac]=true;
    }
}
if (length(seen)>2048) die('too many node clients');
if (!fs.writefile(cycle+'/coverage.json',sprintf('%J',coverage))) die('cannot stage node coverage');
print(sprintf('%J\n',{version:1,device_id:owner,generation:ARGV[3],
    collection_id:ARGV[3]+':'+ARGV[4],sources}));

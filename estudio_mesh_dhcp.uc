#!/usr/bin/ucode
// SPDX-License-Identifier: MIT
// udhcpc runs this hook in the management namespace, never on the host LAN.
import * as fs from 'fs';
import { storage_ok } from './estudio_mesh_storage.uc';
function need(value,message) { if (!value) die(message+'\n'); }
function run(args) { need(system(args)==0,'lease network operation failed'); }
const root='/tmp/estudio-mesh-dhcp';
const path=root+'/lease.json';
let ns=fs.stat('/var/run/netns/codex-sixbh-client');
need(ns && fs.readlink('/proc/self/ns/net')=='net:['+ns.inode+']','wrong network namespace');
need(getenv('interface')=='br-lan','wrong lease interface');
need(trim(fs.readfile('/sys/class/net/br-lan/address') ?? '')=='02:00:00:00:00:0c','wrong management identity');
need(storage_ok(),'flash is accessible');
let text=fs.readfile(path);
let previous=text ? json(text) : {};
let event=ARGV[0];
let value={version:1,sequence:(previous.sequence ?? 0)+1,event,observed_at:time()};
switch (event) {
case 'deconfig':
    run(['/sbin/ip','-4','address','flush','dev','br-lan','scope','global']);
    value.state='unconfigured';
    value.ip=null;
    break;
case 'bound':
case 'renew':
    let address=getenv('ip');
    let parts=split(address ?? '', '.');
    need(length(parts)==4 && parts[0]=='192' && parts[1]=='168'
        && match(parts[2],/^(68|69|70|71)$/) && match(parts[3],/^(0|[1-9][0-9]{0,2})$/)
        && int(parts[3])<=255 && address!='198.18.68.0'
        && address!='198.18.68.1' && address!='198.18.71.255','invalid management address');
    need(getenv('subnet')=='255.255.252.0' && getenv('router')=='198.18.68.1'
        && getenv('serverid')=='198.18.68.1','unexpected DHCP authority or network');
    let lifetime=getenv('lease');
    need(match(lifetime ?? '',/^[0-9]+$/) && int(lifetime)>0,'invalid DHCP lifetime');
    run(['/sbin/ip','-4','address','replace',address+'/22','dev','br-lan']);
    run(['/sbin/ip','-4','route','replace','default','via','198.18.68.1','dev','br-lan']);
    if (previous.state=='bound' && previous.ip && previous.ip!=address)
        run(['/sbin/ip','-4','address','del',previous.ip+'/22','dev','br-lan']);
    value.state='bound';
    value.ip=address;
    value.server='198.18.68.1';
    value.lease_seconds=int(lifetime);
    value.expires_at=value.observed_at+value.lease_seconds;
    break;
default:
    exit(0);
}
need(fs.writefile(path+'.new',sprintf('%J',value)),'cannot store lease state');
need(fs.chmod(path+'.new',0600),'cannot protect lease state');
need(fs.rename(path+'.new',path),'cannot publish lease state');

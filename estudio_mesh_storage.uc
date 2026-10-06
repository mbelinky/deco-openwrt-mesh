// SPDX-License-Identifier: MIT
// Permit the original RAM image or only this spare's boot environment.
// Firmware, calibration and factory partitions must remain inaccessible.
import * as fs from 'fs';

export function storage_ok() {
    let table=trim(fs.readfile('/proc/mtd') ?? '');
    let rows=split(table,'\n');
    if (!match(rows[0] ?? '',/^dev: +size +erasesize +name$/)) return false;
    if (length(rows)==1) return true;
    if (length(rows)!=2 || rows[1]!='mtd0: 00080000 00020000 "0:APPSBLENV"') return false;
    if (trim(fs.readfile('/proc/sys/kernel/osrelease') ?? '')!='6.18.52') return false;
    let root='/sys/class/mtd/mtd0/';
    for (let name,value in {name:'0:APPSBLENV',size:'524288',erasesize:'131072',
                           writesize:'2048',oobsize:'64',type:'nand'}) {
        if (trim(fs.readfile(root+name) ?? '')!=value) return false;
    }
    if (index(['0x0','0x400'],trim(fs.readfile(root+'flags') ?? ''))<0) return false;
    let parts='/sys/firmware/devicetree/base/soc@0/spi@79b0000/nand@0/partitions/';
    let entries=fs.lsdir(parts);
    if (!entries || length(entries)!=5 || index(entries,'partition@300000')<0) return false;
    let reg=fs.readfile(parts+'partition@300000/reg');
    return reg!=null && hexenc(reg)=='0030000000080000';
}

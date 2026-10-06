// SPDX-License-Identifier: MIT
// Parse bounded Ethernet captures, retaining only addresses sent by authorized
// client MACs. No payload, packet file, or address cache is persisted.
import * as fs from 'fs';

function u16(data, offset, little) {
    let a=ord(data,offset), b=ord(data,offset+1);
    return little ? a+b*256 : a*256+b;
}
function u32(data, offset, little) {
    return little ? u16(data,offset,true)+u16(data,offset+2,true)*65536
        : u16(data,offset,false)*65536+u16(data,offset+2,false);
}
function mac(data, offset) {
    return sprintf('%02X-%02X-%02X-%02X-%02X-%02X',ord(data,offset),ord(data,offset+1),
        ord(data,offset+2),ord(data,offset+3),ord(data,offset+4),ord(data,offset+5));
}
function address(data, offset) {
    let a=ord(data,offset), b=ord(data,offset+1), c=ord(data,offset+2), d=ord(data,offset+3);
    if (!a || a==127 || a>=224 || (a==169 && b==254)) return null;
    return sprintf('%d.%d.%d.%d',a,b,c,d);
}
export function observe(interface, authorized) {
    if (!match(interface, /^[A-Za-z0-9_.-]{1,15}$/)) die('invalid capture interface');
    if (!length(authorized)) return {};
    // -P in is this pinned OEM tcpdump's spelling of incoming-only capture.
    // -c and -s bound memory; timeout bounds a quiet interface. -U flushes packets.
    let command='/usr/bin/timeout 4 /usr/sbin/chroot /tmp/oem-mesh-peer /usr/sbin/tcpdump '
        + '-U -n -p -P in -s 64 -c 256 -i '+interface+" -w - 'arp or ip' 2>/dev/null";
    let pipe=fs.popen(command,'r');
    if (!pipe) die('cannot start address observation');
    let data=pipe.read('all'), status=pipe.close();
    if ((status!=0 && status!=124) || length(data)<24 || length(data)>65536)
        die('address capture failed');
    let magic=u32(data,0,false), little=magic==0xd4c3b2a1;
    if ((!little && magic!=0xa1b2c3d4) || u16(data,4,little)!=2 || u16(data,6,little)!=4
        || u32(data,20,little)!=1 || u32(data,16,little)!=64) die('unsupported address capture format');
    let found={}, pos=24, packets=0;
    while (pos<length(data)) {
        if (length(data)-pos<16 || ++packets>256) die('truncated address capture');
        let size=u32(data,pos+8,little), original=u32(data,pos+12,little);
        pos+=16;
        if (size>64 || size>original || pos+size>length(data)) die('invalid captured frame');
        let frame=substr(data,pos,size); pos+=size;
        if (size<14) continue;
        let sender=mac(frame,6);
        if (!authorized[sender]) continue;
        let protocol=u16(frame,12,false), offset=14;
        for (let tags=0; tags<2 && (protocol==0x8100 || protocol==0x88a8); tags++) {
            if (size<offset+4) break;
            protocol=u16(frame,offset+2,false); offset+=4;
        }
        let ip=null;
        if (protocol==0x0806 && size>=offset+28 && u16(frame,offset,false)==1
            && u16(frame,offset+2,false)==0x0800 && ord(frame,offset+4)==6 && ord(frame,offset+5)==4
            && (u16(frame,offset+6,false)==1 || u16(frame,offset+6,false)==2)
            && mac(frame,offset+8)==sender) ip=address(frame,offset+14);
        if (protocol==0x0800 && size>=offset+20 && (ord(frame,offset)>>4)==4) {
            let header=(ord(frame,offset)&15)*4;
            if (header>=20 && u16(frame,offset+2,false)>=header) ip=address(frame,offset+12);
        }
        if (!ip) continue;
        if (!found[sender]) found[sender]={ip, conflict:false};
        else if (found[sender].ip!=ip) found[sender].conflict=true;
    }
    return found;
}

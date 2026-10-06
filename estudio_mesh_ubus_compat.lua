#!/usr/bin/lua
-- SPDX-License-Identifier: MIT
-- Bounded experiment: adapt the OEM ubus header peer byte order to upstream.
-- Native network.device status calls expose carrier as the OEM's link field.
-- Other payloads and sequence numbers are unchanged. This is not a general ubus
-- proxy: descriptor passing and non-root credential propagation are untested.
local n=require "nixio"
local fs=require "nixio.fs"
local bit=require "bit"
assert(os.getenv("ADAPTER_CONFINED")=="1" and fs.stat("/codex-isolated-peer"))
assert(#arg==0 or #arg==2,"expected listen and upstream socket paths")
local listen=arg[1] or "/tmp/codex-wps-native/legacy-ubus.sock"
local upstream=arg[2] or "/tmp/codex-wps-native/oem-ubus.sock"
-- Explicit sockets are the normal startup path to the host's real bus.
-- The no-argument experiment runs against an isolated bus and service manager.
local guarded=#arg==2
for _,path in ipairs({listen,upstream}) do
    assert(path:match("^/tmp/[%w_./%-]+$") and not path:find("..",1,true),"invalid ubus socket path")
end
assert(not fs.stat(listen),"legacy ubus socket already exists")
local server=assert(n.socket("unix","stream"))
assert(server:bind(listen));assert(fs.chmod(listen,"600"))
assert(server:listen(16));assert(server:setblocking(false))
local IN,OUT,HUP,ERR=n.poll_flags("in"),n.poll_flags("out"),n.poll_flags("hup"),n.poll_flags("err")
local endpoints={}
local function padded(size) return math.floor((size+3)/4)*4 end
local function length(s,p)
    return s:byte(p+1)*65536+s:byte(p+2)*256+s:byte(p+3)
end
local function blob(kind,payload)
    local size=4+#payload
    assert(size<=65536,"ubus compatibility blob too large")
    return string.char(kind,math.floor(size/65536),math.floor(size/256)%256,size%256)..payload
end
local function attrs(s)
    local out={}
    local p=1
    while p<=#s do
        assert(p+3<=#s,"truncated ubus attribute")
        local size=length(s,p)
        assert(size>=4 and p+padded(size)-1<=#s,"invalid ubus attribute size")
        out[#out+1]={kind=s:byte(p),payload=s:sub(p+4,p+size-1),raw=s:sub(p,p+padded(size)-1)}
        p=p+padded(size)
    end
    return out
end
local function values(s,array,depth)
    depth=(depth or 0)+1
    assert(depth<=8,"nested ubus data too deep")
    local result={}
    for _,a in ipairs(attrs(s)) do
        assert(a.kind>=128 and #a.payload>=3,"invalid named attribute")
        local size=a.payload:byte(1)*256+a.payload:byte(2)
        assert(size<=#a.payload-3 and a.payload:byte(3+size)==0,"invalid attribute name")
        local name=a.payload:sub(3,2+size)
        local data=a.payload:sub(padded(3+size)+1)
        local kind=a.kind-128
        local value
        if kind==1 or kind==2 then value=values(data,kind==1,depth)
        elseif kind==3 then
            assert(data:sub(-1)=="\0" and not data:sub(1,-2):find("\0",1,true),"invalid string")
            value=data:sub(1,-2)
        elseif kind==5 then
            assert(#data==4,"invalid integer")
            value=data:byte(1)*16777216+data:byte(2)*65536+data:byte(3)*256+data:byte(4)
        elseif kind==7 then
            assert(data=="\0" or data=="\1","invalid boolean")
            value=data=="\1"
        else error("unsupported request value") end
        if array then
            assert(name=="","named array entry")
            result[#result+1]=value
        else
            assert(name~="" and result[name]==nil,"duplicate or empty data field")
            result[name]=value
        end
    end
    return result
end
local function same(a,b)
    if type(a)~=type(b) then return false end
    if type(a)~="table" then return a==b end
    for k,v in pairs(a) do if not same(v,b[k]) then return false end end
    for k in pairs(b) do if a[k]==nil then return false end end
    return true
end
local watcher={name="deco-wps",triggers={
    {"deco.wifi",{"run_script","/usr/sbin/deco-wps-service","reconcile"},250}
},instances={watcher={command={"/usr/sbin/deco-wps-service","watch"},
    env={ADAPTER_CONFINED="1"},respawn={"3600","2","5"},
    term_timeout=2,stdout=true,stderr=true}}}
local pairing={name="deco-wps",instances={pairing={
    command={"/usr/sbin/wpsd","-c","/tmp/deco-wps.conf","-l","i"},
    env={ADAPTER_CONFINED="1"},file={"/tmp/deco-runtime/tmp/deco-wps.conf"},
    respawn={"3600","2","5"},term_timeout=2,stdout=true,stderr=true}}}
local function permitted(state,kind,fields)
    if kind==5 then
        local object=state.objects[fields[3]]
        local method=fields[4] and fields[4]:match("^([^%z]+)%z$")
        local data=values(fields[7] or "")
        local empty=next(data)==nil
        if object=="service" then
            if method=="list" then return same(data,{name="deco-wps"}) end
            if method=="add" then return same(data,watcher) or same(data,pairing) end
            if method=="delete" then
                return same(data,{name="deco-wps"}) or
                    same(data,{name="deco-wps",instance="pairing"}) or
                    same(data,{name="deco-wps",instance="watcher"})
            end
            if method=="event" then
                return same(data,{type="deco.wifi",data={source="wireless"}})
            end
        elseif object=="network.wireless" then return method=="status" and empty
        elseif object=="network.device" then
            return method=="status" and (same(data,{name="phy0-ap0"}) or same(data,{name="phy1-ap0"}))
        elseif object=="hostapd.phy0-ap0" or object=="hostapd.phy1-ap0" then
            return empty and (method=="get_status" or method=="wps_status" or method=="wps_cancel")
        elseif object=="wps" then
            if empty and (method=="status" or method=="cancel") then return true end
            return method=="pbc" and type(data.id)=="number" and
                data.id>=0 and data.id<=4294967295 and data.id%1==0 and
                type(data.from)=="string" and #data.from==40 and data.from:match("^%x+$") and
                same(data,{id=data.id,from=data.from})
        elseif fields[3]=="\0\0\0\1" and method=="register" then
            return type(data.object)=="number" and (same(data,{object=data.object,pattern="network.interface"}) or
                same(data,{object=data.object,pattern="ubus.object.add"}) or
                same(data,{object=data.object,pattern="ubus.object.remove"}))
        end
        return false
    elseif kind==6 then
        -- Only publish WPS or unnamed event-listener objects on the host bus.
        return fields[2]=="wps\0" or not fields[2]
    end
    return kind==1 or kind==2 or kind==3 or kind==4 or kind==7
end
local function adapt(ep,frame)
    local kind=frame:byte(2)
    local seq=frame:sub(3,4)
    local fields=attrs(frame:sub(13))
    local by_id={}
    for _,a in ipairs(fields) do
        assert(not by_id[a.kind],"duplicate ubus attribute")
        by_id[a.kind]=a.payload
    end
    local state=ep.state
    if ep.native and kind==2 and by_id[2] and by_id[3] then
        state.objects[by_id[3]]=by_id[2]:match("^([^%z]+)%z$")
    end
    if guarded and not ep.native and not permitted(state,kind,by_id) then
        -- Reply locally with PERMISSION_DENIED, preserving the OEM header.
        -- No arguments (which can contain credentials) enter diagnostic logs.
        local object=state.objects[by_id[3]] or "unknown"
        local method=by_id[4] and by_id[4]:match("^([%w_.%-]+)%z$") or "unknown"
        print("OEM_UBUS_DENIED type="..kind.." object="..object.." method="..method)
        local body=blob(1,"\0\0\0\6")
        if by_id[3] then body=body..blob(3,by_id[3]) end
        ep.pending=ep.pending..frame:sub(1,1).."\1"..frame:sub(3,8)..blob(0,body)
        return ""
    end
    if ep.native and kind==2 and by_id[2]=="network.device\0" then
        state.device_id=by_id[3]
    elseif not ep.native and kind==5 and state.device_id and
        by_id[3]==state.device_id and by_id[4]=="status\0" then
        state.device_status[seq]=true
    elseif ep.native and state.device_status[seq] then
        if kind==1 then state.device_status[seq]=nil end
        if kind==2 and by_id[7] then
            local carrier,present,has_link
            for _,a in ipairs(attrs(by_id[7])) do
                if a.kind>=128 and #a.payload>=3 then
                    local nlen=a.payload:byte(1)*256+a.payload:byte(2)
                    local name=a.payload:sub(3,2+nlen)
                    if name=="link" then has_link=true end
                    if (name=="carrier" or name=="present") and a.kind==135 then
                        local value=a.payload:sub(padded(2+nlen+1)+1)
                        assert(value=="\0" or value=="\1","invalid device boolean")
                        if name=="carrier" then carrier=value else present=value end
                    end
                end
            end
            -- netifd omits carrier entirely when the device is not present.
            if not carrier and present=="\0" then carrier="\0" end
            if carrier and not has_link then
                local link=blob(135,"\0\4link\0\0"..carrier).."\0\0\0"
                local payload={}
                for _,a in ipairs(fields) do
                    payload[#payload+1]=a.kind==7 and blob(7,a.payload..link) or a.raw
                end
                frame=frame:sub(1,8)..blob(frame:byte(9),table.concat(payload))
            end
        end
    end
    return frame:sub(1,4)..frame:sub(5,8):reverse()..frame:sub(9)
end
local function close(ep)
    if ep.closed then return end
    ep.closed=true;ep.fd:close()
    if not ep.other.closed then ep.other.closed=true;ep.other.fd:close() end
end
local function add(client)
    if #endpoints>=64 then client:close();return end
    local remote=assert(n.socket("unix","stream"))
    if not remote:connect(upstream) then remote:close();client:close();return end
    assert(client:setblocking(false));assert(remote:setblocking(false))
    local state={device_status={},objects={}}
    local a={fd=client,buffer="",pending="",state=state}
    local b={fd=remote,buffer="",pending="",state=state,native=true}
    a.other=b;b.other=a
    endpoints[#endpoints+1]=a;endpoints[#endpoints+1]=b
end
local function receive(ep)
    local data,err=ep.fd:read(65536)
    if not data then if err~=11 then close(ep) end;return end
    if data=="" then
        ep.eof=true
        if #ep.buffer>0 or #ep.other.pending==0 then close(ep) end
        return
    end
    ep.buffer=ep.buffer..data
    while #ep.buffer>=12 do
        local b=ep.buffer
        local length=b:byte(10)*65536+b:byte(11)*256+b:byte(12)
        if b:byte(1)~=0 or length<4 or length>65536 then close(ep);return end
        local size=8+length
        if #b<size then break end
        local ok,converted=pcall(adapt,ep,b:sub(1,size))
        if not ok then print("OEM_UBUS_ADAPTER_INVALID_FRAME "..tostring(converted));close(ep);return end
        ep.other.pending=ep.other.pending..converted
        ep.buffer=b:sub(size+1)
        if #ep.other.pending>131072 then close(ep);return end
    end
end
local function flush(ep)
    local count,err=ep.fd:write(ep.pending)
    if not count then if err~=11 then close(ep) end;return end
    if count==0 then close(ep);return end
    ep.pending=ep.pending:sub(count+1)
    if #ep.pending==0 and ep.other.eof then close(ep) end
end
io.stdout:setvbuf("line")
print("OEM_UBUS_PEER_ADAPTER_READY")
while true do
    local active={}
    local poll={{fd=server,events=IN}}
    for _,ep in ipairs(endpoints) do
        if not ep.closed then
            active[#active+1]=ep
            poll[#poll+1]={fd=ep.fd,events=(ep.eof and 0 or IN)+(#ep.pending>0 and OUT or 0)}
        end
    end
    endpoints=active
    local ready,err=n.poll(poll,1000)
    -- This OEM nixio returns false,nil on an ordinary poll timeout.
    assert(ready or err==nil or err==4,"ubus adapter poll failed")
    if ready and ready>0 then
        if bit.band(poll[1].revents or 0,IN)~=0 then
            while true do
                local client=server:accept()
                if not client then break end
                add(client)
            end
        end
        for i=2,#poll do
            local ep=active[i-1]
            local flags=poll[i].revents or 0
            if not ep.closed and bit.band(flags,OUT)~=0 and #ep.pending>0 then flush(ep) end
            if not ep.closed and not ep.eof and bit.band(flags,IN+HUP)~=0 then receive(ep) end
            if not ep.closed and bit.band(flags,ERR)~=0 then close(ep) end
        end
    end
end

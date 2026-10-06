-- SPDX-License-Identifier: MIT
-- RAM delivery journal for complete Wi-Fi observations. The owner holds this
-- lock across prepare, authenticated transport and ack, then closes it. Prepare
-- records possible receiver state BEFORE transport; a lost reply cannot erase
-- the obligation to disconnect clients which subsequently leave.
local fs=require "nixio.fs"
local nixio=require "nixio"
local json=require "luci.json"
local Locker=require("luci.model.locker").Locker
local owner="520C7831F7302242F81407BC050E7E7C4B5C697F"
local M={}
local function array(value,maximum)
    assert(type(value)=="table" and #value<=maximum,"invalid array")
    for key in pairs(value) do
        assert(type(key)=="number" and key%1==0 and key>=1 and key<=#value,"invalid array index")
    end
    return value
end
local function mac(value)
    return type(value)=="string" and value==value:upper()
        and value:match("^%x%x%-%x%x%-%x%x%-%x%x%-%x%x%-%x%x$")
        and tonumber(value:sub(1,2),16)%2==0
end
local function interfaces(value)
    local seen={}
    assert(#array(value,16)>0,"empty observation scope")
    for _,name in ipairs(value) do
        assert(type(name)=="string" and #name<=15 and name:match("^[%w_.%-]+$")
            and not seen[name],"invalid observation interface")
        seen[name]=true
    end
    return seen
end
local function save(path,value)
    local encoded=json.encode(value)
    assert(#encoded<=1048576,"delivery state too large")
    assert(fs.writefile(path..".new",encoded),"cannot write delivery state")
    assert(fs.rename(path..".new",path),"cannot commit delivery state")
end
local function state(path)
    local data=fs.readfile(path)
    if not data then assert(not fs.stat(path),"delivery state unreadable");return nil end
    assert(#data<=1048576,"delivery state too large")
    local value=assert(json.decode(data),"delivery state unreadable")
    assert(value.version==1 and value.device_id==owner and value.scope=="wifi-associations"
        and type(value.possible)=="table" and type(value.last_observed_at)=="number",
        "invalid delivery state")
    interfaces(value.interfaces)
    local count=0
    for key,v in pairs(value.possible) do
        assert(mac(key) and v==true,"invalid possible client")
        count=count+1
    end
    assert(count<=2048,"too many pending clients")
    return value
end
local function protected(fn)
    local ok,value=pcall(fn)
    if ok then return value end
    return nil,value
end
function M.open(path)
    assert(type(path)=="string" and path:match("^/private/[%w_.%-]+%.json$"),"expected private RAM journal")
    local lock=Locker(path..".lock")
    if not lock:tlock() then lock:close();return nil,"client delivery busy" end
    local writer={}
    function writer:close()
        if lock then lock:close();lock=nil end
    end
    function writer:prepare(observation)
        return protected(function()
            assert(lock,"delivery owner closed")
            assert(type(observation)=="table" and observation.scope=="wifi-associations"
                and observation.device_id==owner and type(observation.observed_at)=="number"
                and observation.observed_at%1==0 and observation.observed_at<=os.time()
                and os.time()-observation.observed_at<=30,"stale or invalid observation")
            local scope=interfaces(observation.interfaces)
            local previous=state(path)
            if previous then
                assert(previous.last_observed_at<=observation.observed_at,"observation moved backwards")
                assert(#previous.interfaces==#observation.interfaces,"observation scope changed")
                for _,name in ipairs(previous.interfaces) do assert(scope[name],"observation scope changed") end
            end
            local connected,conn_list={},{}
            assert(type(observation.params)=="table","missing client report")
            for _,row in ipairs(array(observation.params.conn_list,2048)) do
                assert(type(row)=="table" and mac(row.mac) and not connected[row.mac]
                    and row.device_id==owner and row.wire_type=="wireless"
                    and (row.connection_type=="band2_4" or row.connection_type=="band5" or row.connection_type=="band6")
                    and (row.network_type==0 or row.network_type==1 or row.network_type==2)
                    and row.is_guest==(row.network_type==1 and 1 or 0),"invalid reported client")
                connected[row.mac]=true
                -- These fields come from the validated native report compiler.
                -- Never accept caller-provided disconnects or another owner.
                conn_list[#conn_list+1]={mac=row.mac,device_id=owner,wire_type="wireless",
                    connection_type=row.connection_type,is_guest=row.is_guest,
                    network_type=row.network_type,ip=row.ip}
            end
            local possible=previous and previous.possible or {}
            local disconn_list={}
            for key in pairs(possible) do
                if not connected[key] then disconn_list[#disconn_list+1]={mac=key,device_id=owner} end
            end
            for key in pairs(connected) do possible[key]=true end
            local pending_count=0
            for _ in pairs(possible) do pending_count=pending_count+1 end
            assert(pending_count<=2048,"too many pending clients")
            local random=assert(io.open("/dev/urandom","rb"))
            local bytes=random:read(16);random:close()
            assert(bytes and #bytes==16,"delivery token unavailable")
            local id=nixio.bin.hexlify(bytes)
            save(path,{version=1,device_id=owner,scope="wifi-associations",
                interfaces=observation.interfaces,last_observed_at=observation.observed_at,
                possible=possible,pending={id=id,connected=connected}})
            return {id=id,params={conn_list=conn_list,disconn_list=disconn_list}}
        end)
    end
    function writer:ack(id,response)
        return protected(function()
            assert(lock,"delivery owner closed")
            local current=assert(state(path),"delivery state missing")
            assert(type(current.pending)=="table" and current.pending.id==id,"superseded acknowledgement")
            assert(type(response)=="table" and response.error_code==0
                and type(response.result)=="table" and response.result.recv==1,"report not acknowledged")
            assert(type(current.pending.connected)=="table","invalid pending delivery")
            current.possible=current.pending.connected
            current.pending=nil
            save(path,current)
            return true
        end)
    end
    return writer
end
return M

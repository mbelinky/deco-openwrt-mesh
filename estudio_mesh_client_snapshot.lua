-- SPDX-License-Identifier: MIT
-- Serve one atomic native observation set in the isolated fixture or the
-- explicitly enabled, authenticated live management service.
local fs=require "nixio.fs"
local json=require "luci.json"
local owner="520C7831F7302242F81407BC050E7E7C4B5C697F"
local M={}
local function array(value,maximum)
    assert(type(value)=="table" and #value<=maximum,"invalid array")
    for key in pairs(value) do
        assert(type(key)=="number" and key%1==0 and key>=1 and key<=#value,"invalid array index")
    end
    return value
end
local function read(name)
    local data=assert(fs.readfile("/private/client-snapshot/"..name),"observation unavailable")
    assert(#data<=1048576,"observation too large")
    local value=assert(json.decode(data),"invalid observation")
    assert(value.version==1 and value.device_id==owner,"incorrect observation owner")
    return value
end
local function mac(value)
    return type(value)=="string" and value==value:upper()
        and value:match("^%x%x%-%x%x%-%x%x%-%x%x%-%x%x%-%x%x$")
        and tonumber(value:sub(1,2),16)%2==0
end
local function source_key(source,interfaces)
    assert(type(source)=="table" and (source.scope=="wifi-associations" or source.scope=="wired-forwarding"
        or source.scope=="wired-switch"),"invalid source scope")
    local names={}
    assert(#array(source.interfaces,32)>0 or source.scope=="wired-forwarding","empty source coverage")
    for _,name in ipairs(source.interfaces) do
        assert(type(name)=="string" and #name<=15 and name:match("^[%w_.%-]+$") and not interfaces[name],"invalid or overlapping source interface")
        interfaces[name]=true;names[#names+1]=name
    end
    table.sort(names)
    return source.scope..":"..table.concat(names,",")
end
local function ipv4(value)
    assert(type(value)=="string","invalid client address")
    local a,b,c,d=value:match("^(%d+)%.(%d+)%.(%d+)%.(%d+)$")
    assert(a and #a<=3 and #b<=3 and #c<=3 and #d<=3,"invalid client address")
    a,b,c,d=tonumber(a),tonumber(b),tonumber(c),tonumber(d)
    assert(a>0 and a<224 and a~=127 and b<=255 and c<=255 and d<=255
        and not (a==169 and b==254),"unusable client address")
    return value
end
function M.read(params)
    -- tmpsvr constructs a fresh CGI environment. Verify kernel-enforced
    -- confinement directly instead of trusting an inherited shell flag.
    local status=assert(fs.readfile("/proc/self/status"),"confinement unavailable")
    assert(fs.stat("/codex-isolated-peer") and status:match("NoNewPrivs:%s*1\n")
        and status:match("CapBnd:%s*00000000000000c0\n"),"live client snapshots are not enabled")
    local group=require("luci.model.sync").read_group_info()
    assert(group.gid=="codex-isolated-group" or
        (fs.readfile("/private/live-controller")=="52AC6DE2B63BB051EB29D46337989727DC28F87A"
        and fs.stat("/private/adapter-committed.json")),"live client reporting is not enabled")
    assert(type(params)=="table","invalid full-list request")
    for key,value in pairs(params) do
        -- Stock controllers include their own clients. Port classification is
        -- native-owned; remote records never become this node's observations.
        assert(key=="client_list","unexpected full-list request field")
        for _,row in ipairs(array(value,2048)) do assert(type(row)=="table" and mac(row.mac),"invalid controller client list") end
    end
    local state_data=assert(fs.readfile("/private/client-snapshot/status.json"),"collector state unavailable")
    assert(#state_data<=4096,"invalid collector state")
    local state=assert(json.decode(state_data),"invalid collector state")
    local now=os.time()
    assert(state.state=="observed" and type(state.updated_at)=="number"
        and state.updated_at%1==0 and state.updated_at<=now and now-state.updated_at<=30,
        "collector is unavailable or stale")
    assert(type(state.generation)=="string" and #state.generation==36
        and state.generation:match("^[%x%-]+$") and type(state.collection_id)=="string"
        and #state.collection_id<=64 and state.collection_id:sub(1,37)==state.generation..":"
        and state.collection_id:sub(38):match("^%d+$"),"invalid collection identity")
    local coverage=read("coverage.json")
    assert(coverage.generation==state.generation,"coverage belongs to a previous collector")
    local expected,interfaces={},{}
    assert(#array(coverage.sources,32)>0,"no expected client sources")
    for _,source in ipairs(coverage.sources) do
        local key=source_key(source,interfaces)
        assert(not expected[key],"duplicate coverage source");expected[key]=true
    end
    local snapshot=read("current.json")
    assert(snapshot.generation==state.generation and snapshot.collection_id==state.collection_id,
        "incomplete client publication")
    assert(#array(snapshot.sources,32)==#coverage.sources,"incomplete observation set")
    local seen,clients,observed_interfaces={},{},{}
    for _,source in ipairs(snapshot.sources) do
        local key=source_key(source,observed_interfaces)
        assert(expected[key] and source.device_id==owner,"unexpected client source")
        expected[key]=nil
        assert(type(source.observed_at)=="number" and source.observed_at%1==0
            and source.observed_at<=now and now-source.observed_at<=30,"stale client source")
        for _,row in ipairs(array(source.client_list,2048)) do
            assert(type(row)=="table" and mac(row.mac) and row.device_id==owner
                and not seen[row.mac],"invalid or ambiguous client owner")
            assert((row.network_type==0 or row.network_type==1 or row.network_type==2)
                and row.is_guest==(row.network_type==1 and 1 or 0),"invalid client group")
            if source.scope=="wired-forwarding" or source.scope=="wired-switch" then
                assert(row.wire_type=="wired" and row.connection_type=="wired","invalid wired client")
            else
                assert(row.wire_type=="wireless" and (row.connection_type=="band2_4"
                    or row.connection_type=="band5" or row.connection_type=="band6"),"invalid wireless client")
            end
            local client={mac=row.mac,device_id=owner,wire_type=row.wire_type,
                connection_type=row.connection_type,network_type=row.network_type,is_guest=row.is_guest,
                -- The stock client daemon rejects records without hostname.
                -- UNKNOWN is its observed wire value for an unknown name.
                hostname="UNKNOWN"}
            if row.ip~=nil then client.ip=ipv4(row.ip) end
            clients[#clients+1]=client;seen[row.mac]=true
            assert(#clients<=2048,"too many observed clients")
        end
    end
    assert(not next(expected),"missing client source")
    assert(fs.readfile("/private/client-snapshot/status.json")==state_data,"collector changed during request")
    return {client_list=clients}
end
return M

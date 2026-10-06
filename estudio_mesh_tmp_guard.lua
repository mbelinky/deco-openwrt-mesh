#!/usr/bin/lua
-- SPDX-License-Identifier: MIT
-- Compatibility service entry point. Configuration is received in RAM only.
-- Synchronization ACK requires retained OEM configuration and verified native
-- Wi-Fi. It does not assert that every optional OEM feature is implemented.
-- Built from this canonical source into the private runtime. The unmodified
-- original executable is retained separately as tmp-luci-oem.
local nixio = require "nixio"
local json = require "luci.json"
local fs = require "nixio.fs"
local opcode = tonumber(os.getenv("OPCODE") or "")
local protocol = os.getenv("SERVER_PROTOCOL")
local operation = os.getenv("OPERATION")
local allowed = {[0x0001]=true,[0xc40d]=true,[0xc40f]=true}
-- TDP discovery and TMP configuration check reuse the same numeric opcode.
allowed[0xc401] = operation == "sync_config" and protocol == "TDP/2.0"
local log = assert(io.open("/tmp/adapter-operations.log", "a"))
log:write(string.format("opcode=%s operation=%s protocol=%s allowed=%s\n", tostring(opcode),
    tostring(os.getenv("OPERATION")), tostring(os.getenv("SERVER_PROTOCOL")), tostring(allowed[opcode]==true)))
log:close()
if allowed[opcode] then
    nixio.exec("/usr/bin/tmp-luci-oem", unpack(arg))
    error("OEM dispatcher execution failed")
end
local result = {error_code=1,msg="OpenWrt adapter: operation not implemented"}
local failure_source,failure_line
local function fail(message) return {error_code=1,msg=message} end
local commit_journal="/private/adapter-commit-rollback.json"
local function replace(path,data)
    assert(fs.writefile(path..".adapter-new",data))
    assert(fs.readfile(path..".adapter-new")==data,"configuration write incomplete")
    assert(fs.rename(path..".adapter-new",path))
end
local function recover_commit()
    local saved=fs.readfile(commit_journal)
    if not saved then return end
    local rows=assert(json.decode(saved),"invalid configuration recovery data")
    for _,row in ipairs(rows) do
        assert(type(row.path)=="string" and (row.path:match("^/etc/config/[%w_%-]+$")
            or row.path=="/private/adapter-committed.bin" or row.path=="/private/adapter-committed.json"))
        if row.before==false then
            if fs.lstat(row.path) then assert(fs.unlink(row.path)) end
        else assert(type(row.before)=="string");replace(row.path,row.before) end
        fs.unlink(row.path..".adapter-new")
    end
    assert(fs.unlink(commit_journal))
end
local function commit_configuration(plan,request_id)
    -- These are the OEM userspace's configuration files in its confined RAM
    -- root, never the host OpenWrt /etc/config. Keep non-user device settings.
    assert(fs.stat("/usr/bin/tmp-luci-oem") and fs.stat("/private/adapter-decoded/config"))
    local rows={}
    for name in fs.dir("/private/adapter-decoded/config") do
        assert(name:match("^[%w_%-]+$") and fs.stat("/private/adapter-decoded/config/"..name,"type")=="reg")
        rows[#rows+1]={path="/etc/config/"..name,
            value=assert(fs.readfile("/private/adapter-decoded/config/"..name))}
    end
    table.sort(rows,function(a,b)
        if a.path=="/etc/config/sync" then return false end
        if b.path=="/etc/config/sync" then return true end
        return a.path<b.path
    end)
    assert(#rows>0 and rows[#rows].path=="/etc/config/sync","missing configuration version")
    table.insert(rows,#rows,{path="/private/adapter-committed.bin",
        value=assert(fs.readfile("/private/adapter-staged.bin"))})
    table.insert(rows,#rows,{path="/private/adapter-committed.json",value=json.encode({
        version=plan.version,request_id=request_id,configuration_stored=true,
        wireless_applied=true,full_configuration_applied=false,time=os.time()})})
    local before={}
    for _,row in ipairs(rows) do
        local kind=fs.lstat(row.path,"type")
        assert(not kind or kind=="reg","configuration target is not a regular file")
        before[#before+1]={path=row.path,before=fs.readfile(row.path) or false}
    end
    replace(commit_journal,json.encode(before))
    local ok=pcall(function()
        -- Publish the configuration version last, just before acknowledging.
        for _,row in ipairs(rows) do replace(row.path,row.value) end
        assert(require("luci.model.uci").new_cursor():get("sync","config","version")==plan.version)
    end)
    if not ok then recover_commit();error("configuration import failed") end
    assert(fs.unlink(commit_journal))
end
local function handoff(plan)
    -- Native supervision must be explicitly running. Unsupported features stay
    -- staged; no partial update is presented as a complete Deco configuration.
    if #plan.unsupported>0 then return nil end
    local root="/private/native-apply"
    local service=json.decode(fs.readfile(root.."/service.json") or "null")
    if type(service)~="table" or service.accepting~=true
        or type(service.expires)~="number" or service.expires<=os.time()
        or type(service.generation)~="string" or not service.generation:match("^[%x%-]+$") then
        return nil
    end
    if service.acknowledge_configuration==true and require("luci.model.sync").read_group_info().role~="RE" then
        return fail("configuration receiver is not a satellite")
    end
    for _,name in ipairs({"preparing","pending","processing"}) do
        if fs.stat(root.."/"..name) then return fail("native wireless worker busy") end
    end
    local random=assert(io.open("/dev/urandom","rb"))
    local request_id=nixio.bin.hexlify(assert(random:read(16)))
    random:close()
    local dir=root.."/preparing"
    assert(fs.mkdir(dir,"700"))
    assert(fs.writefile(dir.."/before",assert(fs.readfile("/private/openwrt-before/wireless"))))
    assert(fs.writefile(dir.."/wireless",assert(fs.readfile("/private/openwrt-candidate/wireless"))))
    assert(fs.writefile(dir.."/plan.json",json.encode(plan)))
    assert(fs.writefile(dir.."/request.json",json.encode({request_id=request_id,
        generation=service.generation,version=plan.version,expires=service.expires})))
    assert(fs.rename(dir,root.."/pending"))
    if service.acknowledge_configuration==true then
        for attempt=1,45 do
            local receipt=json.decode(fs.readfile(root.."/receipt.json") or "null")
            if type(receipt)=="table" and receipt.request_id==request_id
                and receipt.generation==service.generation and receipt.version==plan.version then
                if receipt.state~="verified" or receipt.wireless_applied~=true then
                    return fail("native configuration application failed")
                end
                commit_configuration(plan,request_id)
                return {error_code=0,request_id=request_id,configuration_stored=true,wireless_applied=true}
            end
            nixio.nanosleep(1)
        end
        return fail("native configuration application timed out")
    end
    return {error_code=1,msg="wireless update queued; full configuration not applied",request_id=request_id}
end
local function receive()
    local length = tonumber(os.getenv("CONTENT_LENGTH"))
    local checksum = tonumber(os.getenv("CHECKSUM") or "",16)
    if not length or length<1 or length>1048576 or length%1~=0 or not checksum then
        return nil,"invalid configuration framing"
    end
    local data=io.read(length)
    if not data or #data~=length or nixio.bin.crc32(data)%4294967296~=checksum then
        return nil,"invalid configuration checksum"
    end
    return data
end
local function pairing()
    local data,err=receive()
    assert(data,err)
    local request=assert(json.decode(data),"invalid pairing request")
    local params=request.params
    assert(type(params)=="table" and
        (params.method=="pbc" or params.method=="cancel" or params.method=="report"),
        "invalid pairing method")
    local function reject(message)
        return {error_code=0,result={code=1,msg=message}}
    end
    if params.method=="pbc" then
        local session=params.data
        if type(session)~="table" or type(session.id)~="number" or
            session.id~=session.id or session.id%1~=0 or session.id<0 or session.id>4294967295 or
            type(session.from)~="string" or #session.from~=40 or not session.from:match("^%x+$") then
            return reject("invalid WPS session")
        end
    end
    if params.method~="report" then
        local conn=require("ubus").connect()
        if not conn then return reject("WPS service unavailable") end
        local ok,status=pcall(conn.call,conn,"wps","status",{})
        conn:close()
        local identity=require("luci.model.getfirm").getfirm_cached("DEV_ID")
        identity=type(identity)=="string" and identity:match("^%s*(%x+)%s*$") or nil
        if not ok or type(status)~="table" or type(status.ctrls)~="table" or
            not identity or #identity~=40 or status.dev~=identity then
            return reject("WPS service unavailable")
        end
        if params.method=="pbc" then
            local ready=false
            for _,ap in pairs(status.ctrls) do
                if type(ap)=="table" and ap.ready==true then ready=true end
            end
            if not ready then return reject("no WPS access point available") end
        end
    end
    -- Keep the original session/node validation and report aggregation. Reports
    -- remain valid when the local radio is stopped: they may concern a peer.
    return require("luci.controller.admin.wpsd").dispatch({operation="main",params=params})
end
local function stage()
    recover_commit()
    local token=os.getenv("TOKEN")
    if not token or #token==0 or #token>256 then return fail("no token") end
    local data,err=receive()
    if not data then return fail(err) end
    local pending_path="/private/adapter-pending.json"
    local pending=json.decode(fs.readfile(pending_path) or "null")
    if opcode==0xc401 then
        local request=json.decode(data)
        local params=request and request.params
        local group=require("luci.model.sync").read_group_info()
        if type(params)~="table" or params.group_id~=group.gid then
            return fail("group id mismatched")
        end
        if tostring(params.sync_version)~="2" then return fail("sync version mismatched") end
        local version=params.config_version
        if type(version)~="string" or #version>64 or not version:match("^%d+%.%d+$") then
            return fail("invalid configuration version")
        end
        if pending and os.time()-pending.time<60 and pending.token~=token then return fail("busy") end
        assert(fs.writefile(pending_path,json.encode({token=token,version=version,time=os.time()})))
        return {error_code=0}
    end
    if not pending or pending.token~=token or os.time()-pending.time>=60 then
        return fail("no matching configuration check")
    end
    fs.unlink(pending_path)
    assert(fs.writefile("/private/adapter-staged.bin.new",data))
    assert(fs.rename("/private/adapter-staged.bin.new","/private/adapter-staged.bin"))
    assert(fs.writefile("/private/adapter-staged.json",json.encode({version=pending.version,
        received_bytes=#data,received_at=os.time(),applied=false})))
    local plan,reason=dofile("/config-translate.lua").translate("/private/adapter-staged.bin",pending.version)
    if not plan then return fail(reason) end
    local queued=handoff(plan)
    if queued then return queued end
    return fail("configuration validated but not applied")
end
if protocol=="TMP/2.0" and opcode==0xc443 and operation=="main" then
    local ok,value=pcall(pairing)
    result=ok and value or fail("pairing request failed")
elseif protocol=="TMP/2.0" and opcode==0xc430 and operation=="read" then
    local ok,value=pcall(function()
        local data,err=receive()
        assert(data,err)
        local request=assert(json.decode(data),"invalid client request")
        return dofile("/client-snapshot.lua").read(request.params)
    end)
    result=ok and {error_code=0,result=value} or fail("client snapshot unavailable")
elseif protocol=="TMP/2.0" and ((opcode==0xc401 and operation=="sync_check")
        or (opcode==0xc402 and operation=="sync_config")) then
    local locker=require("luci.model.locker").Locker("/var/run/adapter-stage.lock")
    if locker:tlock() then
        local ok,value=pcall(stage)
        result=ok and value or fail("configuration receiver failed")
        if not ok then
            local source,line=tostring(value):match("^([/%w_.%-]+):(%d+):")
            if source and #source<=128 then failure_source,failure_line=source,tonumber(line) end
        end
    else result=fail("busy") end
    locker:close()
end
if protocol=="TMP/2.0" and (opcode==0xc401 or opcode==0xc402) then
    assert(fs.writefile("/private/adapter-last-result.json",json.encode({
        opcode=opcode,error_code=result.error_code,msg=result.msg,
        failure_source=failure_source,failure_line=failure_line})))
end
local body = json.encode(result)
io.write(string.format("Content-Length: %d\r\nContent-Checksum: %.8x\r\n\r\n", #body, nixio.bin.crc32(body)))
io.write(body)

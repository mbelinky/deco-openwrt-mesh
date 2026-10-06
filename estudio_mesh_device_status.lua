-- SPDX-License-Identifier: MIT
-- Answer the controller's app device-list query using fresh native state.
-- Offline or missing observations never become a successful online report.
local fs=require "nixio.fs"
local json=require "luci.json"
local M={}
local owner="520C7831F7302242F81407BC050E7E7C4B5C697F"
local controller="52AC6DE2B63BB051EB29D46337989727DC28F87A"
local identity_path="/private/node-nickname.json"
local function supported_parents(state)
    assert(state.parent_control_band=="band5" or state.parent_control_band=="band6","native parent profile unavailable")
    local parents={[controller]=true,
        ["5355353F82EA7AF944FFF5582BFE58BA00CA10BF"]=true,
        ["6D44C8260C8599BC54A3F345F4494FCF1516ECD4"]=true}
    -- secondary_parent's live radio inventory has no 6 GHz backhaul interface.
    if state.parent_control_band=="band5" then parents["DDF89F67F85C238B2E57D57FF79A782C67EAED6A"]=true end
    return parents
end
local function require_writer()
    local status=assert(fs.readfile("/proc/self/status"))
    assert(fs.stat("/codex-isolated-peer") and status:match("NoNewPrivs:%s*1\n")
        and status:match("CapBnd:%s*00000000000000c0\n"),"identity writer is not confined")
    assert(fs.readfile("/private/live-controller")==controller
        and fs.stat("/private/adapter-committed.json"),"node is not admitted")
end
function M.write_nickname(params)
    require_writer()
    assert(type(params)=="table" and params.from==controller and params.device_id==owner,
        "wrong nickname controller or target")
    assert(params.operation==nil or params.operation=="write","wrong nickname operation")
    for key in pairs(params) do
        assert(key=="from" or key=="device_id" or key=="nickname" or key=="custom_nickname" or key=="operation",
            "unexpected nickname field")
    end
    assert(type(params.nickname)=="string" and #params.nickname>0 and #params.nickname<=64
        and not params.nickname:find("%c"),"invalid nickname")
    local value={device_id=owner,nickname=params.nickname}
    if params.nickname=="custom" then
        local bin=require("nixio").bin
        local encoded=params.custom_nickname
        assert(type(encoded)=="string" and #encoded>0 and #encoded<=256,"invalid custom nickname")
        local decoded=bin.b64decode(encoded)
        assert(decoded and #decoded>0 and not decoded:find("%c") and bin.b64encode(decoded)==encoded,
            "invalid encoded nickname")
        value.custom_nickname=encoded
    end
    local data=json.encode(value)
    assert(fs.writefile(identity_path..".new",data),"nickname write failed")
    assert(fs.chmod(identity_path..".new","600"),"nickname permissions failed")
    assert(fs.rename(identity_path..".new",identity_path),"nickname commit failed")
    assert(fs.readfile(identity_path)==data,"nickname verification failed")
    return true
end
function M.write_parent(params)
    require_writer()
    -- The stock main forwards this command with from_re=true and no `from`
    -- field. The encrypted service is restricted to the main's source address.
    assert(type(params)=="table" and params.device_id==owner and params.from_re==true
        and (params.from==nil or params.from==controller),"wrong parent command target or sender")
    for key in pairs(params) do
        assert(key=="device_id" or key=="topology" or key=="from_re" or key=="from",
            "unexpected parent command field")
    end
    local topology=params.topology
    assert(type(topology)=="table" and type(topology.auto)=="boolean","invalid parent selection")
    for key in pairs(topology) do assert(key=="auto" or key=="device_id","unexpected parent selection field") end
    local preferred=topology.device_id
    local state=assert(json.decode(assert(fs.readfile("/private/node-state.json"))))
    assert(state.device_id==owner and state.parent_control_ready==true and state.configuration_verified
        and state.observed_at<=os.time() and os.time()-state.observed_at<=15,
        "native parent selector unavailable")
    local allowed=supported_parents(state)
    assert((topology.auto and (preferred==nil or preferred=="")) or (not topology.auto and allowed[preferred]),"unverified preferred parent")
    local random=assert(io.open("/dev/urandom","rb"))
    local revision=require("nixio").bin.hexlify(assert(random:read(16)));random:close()
    local data=json.encode({version=1,device_id=owner,controller=controller,boot_id=state.boot_id,
        revision=revision,auto=topology.auto,preferred_device=not topology.auto and preferred or nil})
    local path="/private/node-parent-policy.json"
    assert(fs.writefile(path..".new",data),"parent policy write failed")
    assert(fs.chmod(path..".new","600"),"parent policy permissions failed")
    assert(fs.rename(path..".new",path),"parent policy commit failed")
    -- Like stock awn, accept the preference asynchronously. Actual parent and
    -- connectivity continue to come exclusively from native observations.
    return true
end
function M.read_signals(params)
    require_writer()
    assert(type(params)=="table" and params.from==controller and params.device_id==owner,
        "wrong signal requester or target")
    for key in pairs(params) do assert(key=="from" or key=="device_id","unexpected signal query field") end
    local state=assert(json.decode(assert(fs.readfile("/private/node-state.json"))))
    assert(state.device_id==owner and state.parent_control_ready and state.configuration_verified
        and state.backhaul_ifindex and os.time()-state.observed_at>=0 and os.time()-state.observed_at<=15,
        "native signal observer unavailable")
    local allowed=supported_parents(state)
    local parent_count=0
    for _ in pairs(allowed) do parent_count=parent_count+1 end
    local function current()
        local text=fs.readfile("/private/node-parent-signals.json")
        local value=text and json.decode(text)
        if not value or value.boot_id~=state.boot_id or value.ifindex~=state.backhaul_ifindex
            or type(value.observed_at)~="number" or os.time()-value.observed_at<0
            or os.time()-value.observed_at>15 then return nil end
        assert(type(value.parents)=="table" and #value.parents==parent_count,"invalid signal snapshot")
        local rows,seen={},{}
        for _,parent in ipairs(value.parents) do
            assert(allowed[parent.device_id]
                and not seen[parent.device_id] and type(parent.signal_level)=="number"
                and parent.signal_level>=0 and parent.signal_level<=3 and parent.signal_level%1==0,
                "invalid signal observation")
            seen[parent.device_id]=true
            rows[#rows+1]={device_id=parent.device_id,signal_level=parent.signal_level}
        end
        return {device_list=rows}
    end
    local value=current();if value then return value end
    local request_path="/private/node-signal-request.json"
    local existing=fs.readfile(request_path)
    existing=existing and json.decode(existing)
    if not existing or existing.boot_id~=state.boot_id or type(existing.requested_at)~="number"
        or os.time()-existing.requested_at<0 or os.time()-existing.requested_at>15 then
        local random=assert(io.open("/dev/urandom","rb"))
        local revision=require("nixio").bin.hexlify(assert(random:read(16)));random:close()
        local data=json.encode({version=1,device_id=owner,controller=controller,
            boot_id=state.boot_id,requested_at=os.time(),revision=revision})
        assert(fs.writefile(request_path..".new",data) and fs.chmod(request_path..".new","600")
            and fs.rename(request_path..".new",request_path),"signal request commit failed")
    end
    for attempt=1,72 do
        require("nixio").nanosleep(0,250000000)
        value=current();if value then return value end
    end
    error("native parent scan did not complete")
end
function M.read(params)
    assert(type(params)=="table" and params.from==controller,"wrong requesting controller")
    local value=assert(json.decode(assert(fs.readfile("/private/node-state.json"))))
    assert(value.version==1 and value.device_id==owner,"wrong observation owner")
    local now=os.time()
    assert(type(value.observed_at)=="number" and value.observed_at<=now
        and now-value.observed_at<=15,"node state is stale")
    assert(type(value.ip)=="string" and value.ip==fs.readfile("/private/join-ip"),"node address changed")
    local parent=value.mesh_connected and value.parent or nil
    if parent then
        assert(type(parent)=="table" and type(parent.device_id)=="string" and #parent.device_id==40
            and parent.device_id:match("^[0-9A-F]+$") and parent.device_id~=owner
            and type(parent.mac)=="string" and #parent.mac==17
            and parent.mac:match("^%x%x:%x%x:%x%x:%x%x:%x%x:%x%x$"),"invalid observed parent")
    end
    assert(not value.mesh_connected or parent,"connected node has no observed parent")
    assert(not value.mesh_connected or value.backhaul_band=="band5" or value.backhaul_band=="band6",
        "connected node has no observed band")
    local bands=value.backhaul_bands or (value.mesh_connected and {value.backhaul_band} or {})
    assert(type(bands)=="table" and #bands<=2 and (not value.mesh_connected or #bands>=1),"invalid active bands")
    local seen={}
    for _,band in ipairs(bands) do
        assert((band=="band5" or band=="band6") and not seen[band],"invalid active band")
        seen[band]=true
    end
    -- Internet status is a fresh traffic observation. A pending update must
    -- not turn a retained working path into an offline report; first admission
    -- still requires verification and every configuration gate stays separate.
    local online=value.mesh_connected and value.internet_online
        and (value.configuration_verified or value.configuration_admitted==true)
    local row={device_id=owner,mac="02-00-00-00-00-19",device_model="Deco XE75",
        hardware_ver="3.0",software_ver=value.software_ver,role="slave",
        ip=value.ip,device_ip=value.ip,master_device_id=controller,parent_device_id=parent and parent.device_id or nil,
        previous=parent and parent.mac:upper():gsub(":","-") or nil,connection_type=value.mesh_connected and bands or {},
        group_status=value.mesh_connected and "connected" or "disconnected",
        inet_status=online and "online" or "offline",inet_error_msg=online and "well" or "master_unknown",
        is_wired=false,support_plc=false,set_gateway_support=false,speed_get_support=false}
    if value.parent_control_ready then
        local preference=value.parent_preference
        assert(type(preference)=="table" and type(preference.auto)=="boolean"
            and (preference.auto and preference.device_id=="" or not preference.auto and
                supported_parents(value)[preference.device_id]),
            "invalid native parent preference")
        row.topology=preference
    end
    local identity=fs.readfile(identity_path)
    if identity then
        identity=assert(json.decode(identity))
        assert(identity.device_id==owner,"wrong nickname owner")
        row.nickname=identity.nickname
        row.custom_nickname=identity.custom_nickname
    end
    for _,name in ipairs({"bssid_2g","bssid_5g","bssid_6g"}) do
        local mac=value.bssids[name]
        if mac then assert(type(mac)=="string" and #mac==17);row[name]=mac:gsub(":","-") end
    end
    return {device_list={row}}
end
return M

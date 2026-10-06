#!/usr/bin/lua
-- SPDX-License-Identifier: MIT
-- WPS lifecycle in the confined OEM runtime, owned by native OpenWrt procd.
local fs=require "nixio.fs"
local nixio=require "nixio"
assert(os.getenv("ADAPTER_CONFINED")=="1" and fs.stat("/codex-isolated-peer"))
local action=arg[1]
assert(#arg==1 and (action=="start" or action=="stop" or action=="reconcile" or action=="watch"),
    "expected start, stop, reconcile or watch")
local enabled="/tmp/deco-wps.enabled"
local loop
if action=="watch" then loop=require "uloop";loop.init() end
local conn=assert(require("ubus").connect(nil,2))
local function service()
    local result=assert(conn:call("service","list",{name="deco-wps"}),
        "native service manager unavailable")
    return result["deco-wps"]
end
local function call(method,data)
    local _,err=conn:call("service",method,data)
    assert(not err,"WPS service manager request failed")
end
local function pairing()
    local managed=service()
    return managed and managed.instances and managed.instances.pairing
end
local function stop_pairing()
    if pairing() then
        if conn:call("wps","status",{}) then
            local result=conn:call("wps","cancel",{})
            assert(result and result.code==0,"could not cancel pairing before stop")
        end
        call("delete",{name="deco-wps",instance="pairing"})
        local stopped=false
        for i=1,10 do
            if not pairing() and not conn:call("wps","status",{}) then
                stopped=true;break
            end
            nixio.nanosleep(1)
        end
        assert(stopped,"WPS service did not stop")
    end
    require("luci.model.wps").refresh()
end
local function discover()
    local runtime=assert(conn:call("network.wireless","status",{}),
        "native wireless state unavailable")
    local selected={}
    local seen={}
    -- These are the adapter's main AP sections. Guest, IoT, isolated-client
    -- duplicates and the private backhaul must not inherit main-network WPS.
    local main5="default_radio1"
    for _,radio in pairs(runtime) do
        for _,ap in ipairs(radio.interfaces or {}) do
            if ap.section=="test5" then main5="test5" end
        end
    end
    local main={default_radio0=true,[main5]=true}
    for _,radio in pairs(runtime) do
        if radio.up and not radio.pending and not radio.disabled then
            for _,ap in ipairs(radio.interfaces or {}) do
                local c=ap.config or {}
                local security=c.encryption=="psk2" or c.encryption=="psk2+ccmp"
                    or c.encryption=="sae-mixed"
                if main[ap.section] and c.mode=="ap" and security and
                    c.wps_pushbutton==true and not c.hidden and not c.disabled then
                    local iface=ap.ifname
                    assert(type(iface)=="string" and #iface<=15 and
                        iface:match("^[%w_.%-]+$") and not seen[iface],"invalid WPS AP identity")
                    local status=conn:call("hostapd."..iface,"get_status",{})
                    assert(status and status.status=="ENABLED" and status.ssid==c.ssid,
                        "native WPS AP is changing")
                    local frequency=tonumber(status.freq)
                    local band=radio.config and radio.config.band
                    local allowed=frequency and ((band=="2g" and frequency>=2412 and frequency<=2484)
                        or (band=="5g" and frequency>=5180 and frequency<=5885))
                    if allowed then
                        local path="/var/run/hostapd/"..iface
                        assert(fs.stat(path) and conn:call("hostapd."..iface,"wps_status",{}),
                            "native WPS control unavailable")
                        seen[iface]=true
                        selected[#selected+1]=path
                    end
                end
            end
        end
    end
    table.sort(selected)
    return selected
end
if action=="watch" then
    local function changed()
        if fs.stat(enabled) then
            call("event",{type="deco.wifi",data={source="wireless"}})
        end
    end
    local function object_changed(event)
        local path=event and event.path
        if type(path)=="string" and (path=="network.wireless" or path:match("^hostapd%.")) then
            changed()
        end
    end
    conn:listen({["network.interface"]=changed,
        ["ubus.object.add"]=object_changed,["ubus.object.remove"]=object_changed})
    changed()
    loop.run()
    conn:close()
    return
end
-- Serialize explicit start/stop with event-triggered reconciliations. A queued
-- event must not resurrect pairing after an explicit stop has completed.
local lock=require("luci.model.locker").Locker("/tmp/deco-wps-lifecycle.lock")
local acquired=false
for i=1,10 do
    if lock:tlock() then acquired=true;break end
    nixio.nanosleep(1)
end
assert(acquired,"WPS lifecycle busy")
if action=="stop" then
    fs.unlink(enabled)
    stop_pairing()
    if service() then call("delete",{name="deco-wps"}) end
elseif action=="start" or fs.stat(enabled) then
    if action=="start" then
        assert(fs.writefile(enabled,"1\n"))
        assert(fs.chmod(enabled,"600"))
        call("add",{name="deco-wps",triggers={
            {"deco.wifi",{"run_script","/usr/sbin/deco-wps-service","reconcile"},250}
        },instances={watcher={
            command={"/usr/sbin/deco-wps-service","watch"},
            env={ADAPTER_CONFINED="1"},respawn={"3600","2","5"},
            term_timeout=2,stdout=true,stderr=true
        }}})
    end
    local ok,selected=pcall(discover)
    if not ok or #selected==0 then
        stop_pairing()
        conn:close()
        lock:close()
        -- Errors below are fixed diagnostic strings, never UCI/key values.
        assert(ok,selected)
        return
    end
    local config="/tmp/deco-wps.conf"
    local contents=table.concat(selected,"\n").."\n"
    if fs.readfile(config)~=contents then
        stop_pairing()
        assert(fs.writefile(config..".new",contents))
        assert(fs.chmod(config..".new","600"))
        assert(fs.rename(config..".new",config))
    end
    call("add",{name="deco-wps",instances={pairing={
        command={"/usr/sbin/wpsd","-c",config,"-l","i"},
        env={ADAPTER_CONFINED="1"},file={(os.getenv("ADAPTER_SERVICE_ROOT") or "")..config},
        respawn={"3600","2","5"},term_timeout=2,stdout=true,stderr=true
    }}})
    local ready=false
    for i=1,10 do
        local managed=service()
        local instance=managed and managed.instances and managed.instances.pairing
        local status=conn:call("wps","status",{})
        if instance and instance.running and status and status.ctrls then
            ready=true
            for _,path in ipairs(selected) do
                local iface=path:match("([^/]+)$")
                if not status.ctrls[iface] or not status.ctrls[iface].ready then ready=false end
            end
            if ready then break end
        end
        nixio.nanosleep(1)
    end
    assert(ready,"supervised WPS service did not become ready")
end
conn:close()
lock:close()

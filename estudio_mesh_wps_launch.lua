#!/usr/bin/lua
-- SPDX-License-Identifier: MIT
-- Recover radio and local session state before publishing the OEM WPS service.
-- The original daemon then owns requests and reports, with the same process ID.
local fs=require "nixio.fs"
local nixio=require "nixio"
assert(os.getenv("ADAPTER_CONFINED")=="1" and fs.stat("/codex-isolated-peer"))
local hostapd_gid=os.getenv("ADAPTER_HOSTAPD_GID")
if hostapd_gid then
    assert(hostapd_gid:match("^%d+$") and tonumber(hostapd_gid)>0 and
        tonumber(hostapd_gid)<=65535,"invalid native radio group")
    assert(nixio.setgid(tonumber(hostapd_gid)),"cannot join native radio group")
    assert(os.getenv("ADAPTER_WPA_CTRL_DIR")=="/var/run/hostapd/deco-wps-control",
        "invalid native radio reply directory")
    assert(nixio.setenv("LD_PRELOAD","/usr/lib/libdeco-wpa-ctrl.so"))
end
local config
local i=1
while i<=#arg do
    assert(arg[i]=="-c" or arg[i]=="-l","unsupported WPS service argument")
    assert(arg[i+1],"missing WPS service argument")
    if arg[i]=="-c" then
        assert(not config,"duplicate WPS configuration")
        config=arg[i+1]
    end
    i=i+2
end
assert(config and config:match("^/tmp/[%w_./%-]+$") and
    not config:find("..",1,true),"invalid WPS configuration path")
local file=assert(io.open(config,"r"))
local contents=file:read(8193)
file:close()
assert(contents and #contents<=8192,"WPS configuration too large")
local interfaces={}
local seen={}
for path in contents:gmatch("[^\r\n]+") do
    local iface=path:match("^/var/run/hostapd/([%w_.%-]+)$")
    assert(iface and #iface<=15 and not path:find("..",1,true),
        "invalid WPS control interface")
    assert(not seen[iface] and #interfaces<16,"duplicate or excess WPS interface")
    seen[iface]=true
    interfaces[#interfaces+1]=iface
end
assert(#interfaces>0,"no WPS control interfaces")
local conn=assert(require("ubus").connect(nil,2))
assert(not conn:call("wps","status",{}),"WPS service already running")
for _,iface in ipairs(interfaces) do
    local object="hostapd."..iface
    local status=assert(conn:call(object,"wps_status",{}),"WPS AP unavailable")
    if status.pbc_status=="Active" then
        -- A successful ubus method with no payload may return nil, nil.
        local _,err=conn:call(object,"wps_cancel",{})
        assert(not err,"WPS cancellation failed")
    end
    status=assert(conn:call(object,"wps_status",{}),"WPS AP status unavailable")
    assert(status.pbc_status=="Disabled" or status.pbc_status=="Timed-out",
        "previous WPS pairing window still active")
end
conn:close()
local wps=require "luci.model.wps"
wps.refresh()
assert(wps.get_status().tag=="Idle","previous WPS session still active")
nixio.exec("/usr/sbin/wpsd-oem",unpack(arg))
error("could not start original WPS daemon")

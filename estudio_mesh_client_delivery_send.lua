-- SPDX-License-Identifier: MIT
-- One serialized client-report delivery, with RAM recovery after uncertain
-- transport outcomes. Live delivery stays disabled until managed membership
-- and the controller's capability/configuration contract are implemented.
local fs=require "nixio.fs"
local json=require "luci.json"
assert(os.getenv("ADAPTER_CONFINED")=="1" and fs.stat("/codex-isolated-peer"),
    "live client delivery is not enabled")
assert(require("luci.model.sync").read_group_info().gid=="codex-isolated-group",
    "expected disconnected controller group")
assert(arg[1] and not arg[2],"expected observation envelope path")
local input=assert(fs.readfile(arg[1]),"observation unavailable")
assert(#input<=1048576,"observation too large")
local observation=assert(json.decode(input),"invalid observation envelope")
local writer=assert(dofile("/client-delivery.lua").open("/private/client-delivery.json"))
local ok,err=pcall(function()
    local attempt,reason=writer:prepare(observation)
    assert(attempt,reason)
    assert(fs.writefile("/private/client-delivery-request.json",json.encode({params=attempt.params})))
    assert(os.execute("/usr/bin/tmpcli -S -s -U root -u 127.0.0.1 -p 20002 -w 4 -o 0xc432 -I /private/client-delivery-request.json > /private/client-delivery-response.json")==0,
        "client report delivery uncertain")
    local response=fs.readfile("/private/client-delivery-response.json")
    assert(response and #response<=65536,"client report reply unavailable")
    local ack,why=writer:ack(attempt.id,json.decode(response))
    assert(ack,why)
end)
fs.unlink("/private/client-delivery-request.json")
fs.unlink("/private/client-delivery-response.json")
writer:close()
if not ok then
    -- Keep the possible receiver state for retry, without logging client data.
    io.stderr:write("Client report not acknowledged; RAM delivery state retained.\n")
    os.exit(1)
end
print("CLIENT_REPORT_ACKNOWLEDGED")

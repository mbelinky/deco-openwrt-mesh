# SPDX-License-Identifier: MIT
"""Build the confined RAM mesh runtime shared by probes and the service."""
from pathlib import Path
import json
import ipaddress

BASE = Path(__file__).resolve().parent

def build_runtime(args, initial_identity, stock_address, resident=False):
    address=ipaddress.IPv4Address(stock_address)
    network=ipaddress.ip_network('198.18.68.0/22')
    assert str(address)==stock_address and address in network
    assert address not in (network.network_address,network.broadcast_address,ipaddress.IPv4Address('198.18.68.1'))
    if resident:
        assert args.admit_profile and args.receive_config and args.apply_config
    script = r'''set -eu
umask 077
export PATH=/sbin:/usr/sbin:/bin:/usr/bin
test "$(cat /sys/class/net/eth0/address)" = 02:00:00:00:00:19
ucode -e 'import { storage_ok } from "/tmp/estudio_mesh_storage.uc"; if (!storage_ok()) exit(9);'
test -f /tmp/codex-sixsta-active/management-ready
test "$(basename "$(readlink /sys/class/net/sixbh.1/master)")" = br-sixbh
ip -n codex-sixbh-client route get 198.18.68.1 | grep -q 'dev br-lan'
root=/tmp/codex-mesh-join
test ! -e "$root"
mkdir "$root"
native_pid=''
node_pid=''
clients_pid=''
test ! -e /var/run/netns/codex-mesh-report
test ! -e /sys/class/net/mesh-report
backhaul_phy=$(basename "$(readlink -f /sys/class/net/deco-sixsta/phy80211)")
case "$backhaul_phy" in phy1|phy2) ;; *) exit 1;; esac
mcast_option=/sys/kernel/debug/ieee80211/$backhaul_phy/netdev:deco-sixsta/accept_3addr_vlan_mcast
test -f "$mcast_option"
mcast_before=$(cat "$mcast_option")
stage=prepare_runtime
cleanup() {
    printf 'JOIN_LAST_STAGE=%s\n' "$stage"
    if [ -n "$node_pid" ]; then kill "$node_pid" 2>/dev/null || true; wait "$node_pid" 2>/dev/null || true; fi
    if [ -n "$clients_pid" ]; then kill "$clients_pid" 2>/dev/null || true; wait "$clients_pid" 2>/dev/null || true; fi
    if test -f "$root/private/report-client-owned"; then
        for pid in $(ip netns pids codex-mesh-report); do kill "$pid" 2>/dev/null || true; done
        ip link delete mesh-report 2>/dev/null || true
        ip netns delete codex-mesh-report
    fi
NATIVE_CLEANUP
    test ! -f "$mcast_option" || echo "$mcast_before" > "$mcast_option"
    ip netns exec codex-sixbh-client nft delete table inet codex_mesh_join 2>/dev/null || true
    rm -rf "$root"
}
trap cleanup EXIT
trap 'exit 130' INT TERM HUP
# Reuse the already extracted original firmware. Private material is copied
# explicitly below; the general source private/tmp trees are not copied.
for name in bin sbin lib usr etc; do cp -a "/tmp/oem-mesh-peer/$name" "$root/"; done
cp /tmp/oem-mesh-peer/adapter-caps.json "$root/adapter-caps.json"
mkdir -p "$root/tmp/run" "$root/private" "$root/dev" "$root/var" "$root/etc/dropbear"
cat /proc/sys/kernel/random/boot_id > "$root/private/boot-id"
PROFILE_SETUP
touch "$root/dev/console" "$root/codex-isolated-peer"
cp /tmp/oem-mesh-peer/private/group-info "$root/tmp/group-info"
cp /tmp/oem-mesh-peer/private/group.openssh "$root/etc/dropbear/id_rsa"
printf '%s' 520C7831F7302242F81407BC050E7E7C4B5C697F > "$root/tmp/sync-cached-DEV_ID"
printf '%s' 'OpenWrt-r36662-mesh-lab' > "$root/tmp/sync-cached-SOFTVERSION"
printf '%s' 'Deco XE75' > "$root/tmp/sync-cached-MODEL"
printf '%s' '02-00-00-00-00-19' > "$root/tmp/sync-cached-MAC"
cat > "$root/usr/bin/tmp-luci" <<'GUARD'
#!/usr/bin/lua
local fs=require "nixio.fs"
local json=require "luci.json"
local nixio=require "nixio"
local opcode=tonumber(os.getenv("OPCODE") or "")
local protocol=os.getenv("SERVER_PROTOCOL")
if protocol=="TMP/2.0" and (opcode==1 or opcode==0xc40f) then
    nixio.exec("/usr/bin/tmp-luci-oem",unpack(arg));error("dispatcher failed")
end
if protocol=="TMP/2.0" and (opcode==0xc401 or opcode==0xc402) and fs.stat("/private/receive-config") then
    local log=assert(io.open("/private/inbound.jsonl","a"))
    log:write(json.encode({opcode=opcode,protocol=protocol,operation=os.getenv("OPERATION"),
        configuration_receiver=true,token_present=os.getenv("TOKEN")~=nil}).."\n");log:close()
    nixio.exec("/usr/bin/tmp-luci-config",unpack(arg));error("configuration dispatcher failed")
end
local length=tonumber(os.getenv("CONTENT_LENGTH") or "")
local group_valid=false
local master_valid=false
local discovery_peer_valid=false
local discovery_sender
local result={error_code=1,msg="OpenWrt mesh profile admission pending"}
local discovery=protocol=="TDP/2.0" and opcode==0xc401
local no_checksum=discovery and os.getenv("NO_CHECKSUM")=="1"
local framing_valid=false
local profile_returned=false
local client_status=protocol=="TMP/2.0" and opcode==0xc430 and os.getenv("OPERATION")=="read"
local client_count
local client_error
local test_client
local device_status=protocol=="TMP/2.0" and opcode==0x400f and os.getenv("OPERATION")=="read"
local device_status_health
local device_status_error
local nickname_write=protocol=="TMP/2.0" and opcode==0x4003 and os.getenv("OPERATION")=="write"
local nickname_written=false
local nickname_error
local parent_write=protocol=="TMP/2.0" and opcode==0x4091 and os.getenv("OPERATION")=="set"
local parent_written=false
local parent_error
local signal_read=protocol=="TMP/2.0" and opcode==0x4094 and os.getenv("OPERATION")=="get"
local signal_returned=false
local signal_error
if ((protocol=="TMP/2.0" and opcode==0xc40d) or device_status or nickname_write or parent_write or signal_read or client_status or discovery) and length and length>0 and length<8192 then
    local data=io.read(length)
    local checksum=tonumber(os.getenv("CHECKSUM") or "",16)
    framing_valid=data and #data==length and (no_checksum or
        (checksum and nixio.bin.crc32(data)%4294967296==checksum)) or false
    if framing_valid then
        local request=json.decode(data)
        local params=request and request.params
        if signal_read and os.getenv("TOKEN") then
            local ok,value=pcall(function() return dofile("/device-status.lua").read_signals(params) end)
            signal_returned=ok
            if not ok then signal_error=tostring(value):match(":%d+: (.*)$") end
            result=ok and {error_code=0,result=value} or {error_code=1,msg="native parent signals unavailable"}
        end
        if parent_write and os.getenv("TOKEN") then
            local ok,value=pcall(function() return dofile("/device-status.lua").write_parent(params) end)
            parent_written=ok and value==true
            if not ok then parent_error=tostring(value):match(":%d+: (.*)$") end
            result=parent_written and {error_code=0} or {error_code=1,msg="native parent preference rejected"}
        end
        if nickname_write and os.getenv("TOKEN") then
            local ok,value=pcall(function() return dofile("/device-status.lua").write_nickname(params) end)
            nickname_written=ok and value==true
            if not ok then nickname_error=tostring(value):match(":%d+: (.*)$") end
            result=nickname_written and {error_code=0} or {error_code=1,msg="native nickname update rejected"}
        end
        if device_status and os.getenv("TOKEN") then
            local ok,value=pcall(function() return dofile("/device-status.lua").read(params) end)
            result=ok and {error_code=0,result=value} or {error_code=1,msg="native device state unavailable"}
            if ok then
                local node=value.device_list[1]
                device_status_health={group_status=node.group_status,inet_status=node.inet_status}
            else
                device_status_error=tostring(value):find("node state is stale",1,true)
                    and "node_state_stale" or "native_read_refused"
            end
        end
        if client_status and os.getenv("TOKEN") then
            local ok,value=pcall(function() return dofile("/client-snapshot.lua").read(params) end)
            result=ok and {error_code=0,result=value} or {error_code=1,msg="native client state unavailable"}
            if ok then
                client_count=#value.client_list
                for _,client in ipairs(value.client_list) do
                    if client.mac=="02-00-00-00-00-0D" then test_client=client end
                end
            else client_error=tostring(value):match(":%d+: (.*)$") end
        end
        local sync=require "luci.model.sync"
        local group=sync.read_group_info()
        if discovery and type(params)=="table" and params.group_hid==nixio.bin.crc32(group.gid)
            and type(params.secret)=="string" then
            params=sync.decrypt_table(params.secret,group.key)
        end
        group_valid=type(params)=="table" and params.group_id==group.gid
        master_valid=type(params)=="table" and
            (discovery and params.device_id or params.master_devid)=="52AC6DE2B63BB051EB29D46337989727DC28F87A"
        if discovery and group_valid then
            discovery_sender=params.device_id
            -- Satellite inventories are built from their own discovery
            -- replies. Admit only the selected stock experiment peer here;
            -- this does not grant it controller configuration privileges.
            discovery_peer_valid=params.device_id=="5355353F82EA7AF944FFF5582BFE58BA00CA10BF"
                and params.role=="RE" and params.ip=="STOCK_PEER_ADDRESS"
        end
        if discovery and group_valid and (master_valid or discovery_peer_valid) then
            -- The original probe populates each node's local mesh directory
            -- from replies, rather than incoming announcements alone.
            local peer={group_id=group.gid,device_id="520C7831F7302242F81407BC050E7E7C4B5C697F",
                role="RE",ip=assert(fs.readfile("/private/join-ip")),mac="02:00:00:00:00:19",
                device_model="Deco XE75",firmware_ver="OpenWrt-r36662-mesh-lab",
                config_version=(json.decode(fs.readfile("/private/adapter-committed.json") or "null") or {}).version or "0",
                sync_version="2",need_account_digest=true}
            result={error_code=0,result={secret=assert(sync.encrypt_table(peer,group.key))}}
        end
        if protocol=="TMP/2.0" and opcode==0xc40d and group_valid and master_valid
            and os.getenv("TOKEN") and fs.stat("/private/admit-profile") then
            assert(fs.writefile("/private/profile-request.json",data))
            local child=assert(io.popen("/usr/bin/tmp-luci-oem < /private/profile-request.json 2>/private/profile-error.log"))
            local output=child:read("*a");child:close()
            local original=assert(json.decode(assert(output:match("\r\n\r\n(.*)$"))))
            assert(original.error_code==0 and type(original.result)=="table")
            result={error_code=0,result=assert(loadfile("/admission-profile.lua"))()(original.result)}
            assert(result.result.ip==fs.readfile("/private/join-ip"))
            profile_returned=true
            assert(fs.writefile("/private/profile-ready","1"))
            fs.unlink("/private/profile-request.json")
        end
    end
end
local token=os.getenv("TOKEN")
local row={response_unix=os.time(),opcode=opcode,protocol=protocol,group_valid=group_valid,master_valid=master_valid,
    discovery_sender=discovery_sender,discovery_peer_valid=discovery_peer_valid,
    operation=os.getenv("OPERATION"),uri=os.getenv("URI"),client_status_returned=client_status and result.error_code==0,
    client_count=client_count,client_error=client_error,test_client=test_client,device_status_returned=device_status and result.error_code==0,
    device_status_health=device_status_health,device_status_error=device_status_error,
    nickname_written=nickname_written,nickname_error=nickname_error,
    parent_policy_written=parent_written,parent_policy_error=parent_error,
    parent_signals_returned=signal_returned,parent_signals_error=signal_error,
    token_present=type(token)=="string" and #token>0,profile_returned=profile_returned,
    discovery_replied=discovery and result.error_code==0,
    framing_valid=framing_valid,no_checksum=no_checksum,content_length=length}
local log=assert(io.open("/private/inbound.jsonl","a"));log:write(json.encode(row).."\n");log:close()
local body=json.encode(result)
io.write(string.format("Content-Length: %d\r\n",#body))
if not no_checksum then io.write(string.format("Content-Checksum: %.8x\r\n",nixio.bin.crc32(body))) end
io.write("\r\n")
io.write(body)
GUARD
chmod 755 "$root/usr/bin/tmp-luci"
cat > "$root/join.lua" <<'JOIN'
local fs=require "nixio.fs"
local json=require "luci.json"
local sync=require "luci.model.sync"
local nixio=require "nixio"
local group=sync.read_group_info()
assert(group.role=="RE" and group.gid~="codex-isolated-group")
local encrypt_announcement=dofile("/announcement.lua")
local ip=assert(os.getenv("JOIN_IP"))
assert(ip:match("^192%.168%.6[89]%.%d+$") or ip:match("^192%.168%.7[01]%.%d+$"))
local result={operation="live_join_inbound_management",announced_ip=ip,profile_returned=false,
    management_request_received=false,discovery_accepted=false}
local admission=fs.stat("/private/admit-profile")~=nil
local resident=fs.stat("/private/resident")~=nil
local function stopping() return resident and fs.stat("/control/stop")~=nil end
local function management_ip()
    if not resident then return ip end
    local node=json.decode(fs.readfile("/private/node-state.json") or "null")
    if not node or node.device_id~="520C7831F7302242F81407BC050E7E7C4B5C697F"
        or node.management_address_valid~=true or type(node.observed_at)~="number"
        or node.observed_at>os.time() or os.time()-node.observed_at>15
        or type(node.ip)~="string" or node.ip~=fs.readfile("/private/join-ip") then return nil end
    return node.ip
end
local function requested()
    for line in (fs.readfile("/private/inbound.jsonl") or ""):gmatch("[^\n]+") do
        local row=json.decode(line)
        if row and row.opcode==0xc40d and row.protocol=="TMP/2.0" and row.group_valid
            and row.master_valid and row.token_present and row.profile_returned==admission then return true end
    end
    return false
end
local controller_config,controller_sync
local attempt=0
while resident or attempt<15 do
    if stopping() then break end
    attempt=attempt+1
    local address=management_ip()
    local data={group_id=group.gid,device_id="520C7831F7302242F81407BC050E7E7C4B5C697F",
        role="RE",mac="02:00:00:00:00:19",device_model="Deco XE75",
        firmware_ver="OpenWrt-r36662-mesh-lab",config_version=controller_config or "0",
        sync_version=controller_sync or "2"}
    -- The original discovery handler skips inventory insertion when the
    -- advertised version is older. First read its version without announcing
    -- an address, then exercise admission with matching discovery metadata.
    -- Profile admission remains closed; no configuration receipt is claimed.
    if controller_config and controller_sync then data.ip=address end
    if address then
    assert(fs.writefile("/private/discovery.json",json.encode({params={
        group_hid=nixio.bin.crc32(group.gid),secret=assert(sync.encrypt_table(data,group.key)),
        sv="v1",tmp_port_ver="v2"}})))
    os.execute("/usr/bin/tmpcli -t -u 198.18.68.1 -p 20002 -w 3 -o 0xc401 -I /private/discovery.json > /private/discovery-response.json 2>/private/discovery-error.log")
    local response=json.decode(fs.readfile("/private/discovery-response.json") or "null")
    local payload=response and response.result and response.result.secret and sync.decrypt_table(response.result.secret,group.key)
    if response and response.error_code==0 and payload and payload.group_id==group.gid
        and payload.device_id=="52AC6DE2B63BB051EB29D46337989727DC28F87A" then
        result.discovery_accepted=true
        assert(type(payload.config_version)=="string" and type(payload.sync_version)=="string")
        controller_config,controller_sync=payload.config_version,payload.sync_version
    end
    end
    result.attempts=attempt
    if requested() then
        result.management_request_received=true
        result.profile_returned=admission
        break
    end
    nixio.nanosleep(2)
end
if admission and result.profile_returned then
    -- Keep the service alive through radio replacement and a full sequence
    -- of subsequent discovery replies. Advertise only a committed version.
    local committed_at=nil
    local observation_started=os.time()
    local attempt=0
    local encryption={attempts=0,failures=0,consecutive_failures=0}
    while resident or attempt<(fs.stat("/private/apply-config") and 1000 or 35) do
        if stopping() then break end
        attempt=attempt+1
        local logstat=fs.stat("/private/inbound.jsonl")
        if resident and logstat and logstat.size>65536 then
            fs.rename("/private/inbound.jsonl","/private/inbound.previous.jsonl")
        end
        local seen=false
        for line in (fs.readfile("/private/inbound.jsonl") or ""):gmatch("[^\n]+") do
            local row=json.decode(line)
            if row and row.opcode==0xc401 and row.protocol=="TMP/2.0" then seen=true end
        end
        if seen then result.configuration_requested=true end
        local committed=json.decode(fs.readfile("/private/adapter-committed.json") or "null")
        if committed then committed_at=committed_at or os.time() end
            local address=management_ip()
            if attempt%5==0 and address then
                local data={group_id=group.gid,device_id="520C7831F7302242F81407BC050E7E7C4B5C697F",
                    role="RE",ip=address,mac="02:00:00:00:00:19",device_model="Deco XE75",
                    firmware_ver="OpenWrt-r36662-mesh-lab",config_version=committed and committed.version or "0",
                    sync_version="2",need_account_digest=true}
                local secret,reason=encrypt_announcement(data,group.key)
                encryption.attempts=encryption.attempts+1
                encryption.observed_at=os.time()
                encryption.last_error=reason
                if secret then
                    encryption.consecutive_failures=0
                    encryption.last_success_at=os.time()
                    assert(fs.writefile("/private/discovery.json",json.encode({params={
                        group_hid=nixio.bin.crc32(group.gid),secret=secret,
                        sv="v1",tmp_port_ver="v2"}})))
                    os.execute("/usr/bin/tmpcli -t -u 198.18.68.1 -p 20002 -w 3 -o 0xc401 -I /private/discovery.json > /private/discovery-response.json 2>/private/discovery-error.log")
                    local counter=committed and "committed_announcements" or "pending_announcements"
                    result[counter]=(result[counter] or 0)+1
                    result.announced_ip=address
                    assert(fs.writefile("/private/runtime-status.json.new",json.encode({
                        announced_at=os.time(),announced_ip=address,
                        configuration_version=committed and committed.version or "0"})))
                    assert(fs.rename("/private/runtime-status.json.new","/private/runtime-status.json"))
                else
                    encryption.failures=encryption.failures+1
                    encryption.consecutive_failures=encryption.consecutive_failures+1
                    encryption.last_failure_at=os.time()
                end
                assert(fs.writefile("/private/announcement-encryption.json.new",json.encode(encryption)))
                assert(fs.rename("/private/announcement-encryption.json.new","/private/announcement-encryption.json"))
            end
        if not resident and fs.stat("/private/observation-done") and (not committed_at or os.time()-committed_at>=30) then
            result.observation_finished=true
            break
        end
        if not resident and os.time()-observation_started>=1000 then
            result.observation_deadline_reached=true
            break
        end
        nixio.nanosleep(1)
    end
end
local committed=json.decode(fs.readfile("/private/adapter-committed.json") or "null")
if committed then result.configuration_committed={version=committed.version,configuration_stored=committed.configuration_stored,wireless_applied=committed.wireless_applied} end
local staged=json.decode(fs.readfile("/private/adapter-staged.json") or "null")
local plan=json.decode(fs.readfile("/private/adapter-plan.json") or "null")
local config_result=json.decode(fs.readfile("/private/adapter-last-result.json") or "null")
if staged then result.configuration_received={received_bytes=staged.received_bytes,applied=staged.applied,version=staged.version} end
if plan then result.configuration_plan={validated=plan.validated,applied=plan.applied,
    unsupported=plan.unsupported,pending_validation=plan.pending_validation,
    client_preference_count=#plan.client_preferences,isolated_client_count=#plan.isolated_clients} end
if config_result then result.configuration_response=config_result end
local sshlog=fs.readfile("/private/dropbear.log") or ""
result.ssh_controller_authenticated=sshlog:find("Pubkey auth succeeded",1,true)~=nil
result.ssh_connection_received=sshlog:find("Child connection",1,true)~=nil
result.discovery_version_matched=controller_config~=nil and controller_sync~=nil
result.inbound_operations={}
for line in (fs.readfile("/private/inbound.jsonl") or ""):gmatch("[^\n]+") do
    local row=json.decode(line)
    if row then result.inbound_operations[#result.inbound_operations+1]=row end
end
result.dispatch_error_lines={}
for line in (fs.readfile("/private/tmpsvr.log") or ""):gmatch("[^\n]+") do
    local number=line:match("/usr/bin/tmp%-luci:(%d+):")
    if number then result.dispatch_error_lines[#result.dispatch_error_lines+1]=tonumber(number) end
end
assert(fs.writefile("/private/join-result.json",json.encode(result)))
print(json.encode(result))
assert(stopping() or (result.discovery_accepted and result.management_request_received and result.ssh_controller_authenticated),
    "controller did not complete inbound management handshake")
JOIN
cat > "$root/join-service.sh" <<'SERVICE'
#!/bin/sh
set -eu
umask 077
test -f /codex-isolated-peer
# The public firmware archive contains no generated account database. Own this
# confined runtime's account instead of inheriting a previous probe's fixture.
/bin/busybox printf 'root:codex-disabled-password:0:0:root:/root:/bin/sh\n' > /etc/passwd
/bin/busybox printf 'root:x:0:\n' > /etc/group
/usr/bin/dropbearconvert openssh dropbear /etc/dropbear/id_rsa /etc/dropbear/group_rsa > /private/convert.log 2>&1
/usr/bin/dropbearkey -y -f /etc/dropbear/group_rsa 2>/dev/null | /bin/busybox awk '/^ssh-rsa / {print $1 " " $2}' > /etc/dropbear/authorized_keys
# Extracted firmware carries a public cache for a different private key.
# The outgoing client reads this cache before loading the admitted key.
/bin/busybox rm -f /etc/dropbear/id_rsa.pub
/bin/busybox cp /etc/dropbear/authorized_keys /etc/dropbear/id_rsa.pub
# The admitted group key is also Main's independently verified host key.
# Pin Main and the fixed admitted stock peer used by native preparation.
test -s /etc/dropbear/authorized_keys
{ /bin/busybox printf '[198.18.68.1]:20001 '; /bin/busybox cat /etc/dropbear/authorized_keys; } > /etc/dropbear/known_hosts
{ /bin/busybox printf '[STOCK_PEER_ADDRESS]:20001 '; /bin/busybox cat /etc/dropbear/authorized_keys; } >> /etc/dropbear/known_hosts
/bin/busybox mkdir -p /root/.ssh
/bin/busybox cp /etc/dropbear/authorized_keys /root/.ssh/authorized_keys
/sbin/ubusd -s /var/run/ubus.sock > /private/ubus.log 2>&1 &
bus_pid=$!
/usr/bin/tmpsvr > /private/tmpsvr.log 2>&1 &
tmp_pid=$!
# This listener lives only inside codex-sixbh-client. Its unchanged firewall
# admits Main only; binding the port permits a real DHCP address replacement.
/usr/sbin/dropbear -F -E -s -r /etc/dropbear/group_rsa -p 20001 -P /private/dropbear.pid > /private/dropbear.log 2>&1 &
ssh_pid=$!
controller_pid=''
if test -f /private/resident; then
    /usr/bin/lua /relay-controller.lua watch > /private/controller-client.log 2>&1 &
    controller_pid=$!
fi
trap 'kill "$ssh_pid" "$tmp_pid" "$bus_pid" ${controller_pid:+"$controller_pid"} 2>/dev/null || true' EXIT
/bin/busybox sleep 1
kill -0 "$ssh_pid" "$tmp_pid" "$bus_pid"
if test -n "$controller_pid"; then kill -0 "$controller_pid"; fi
/usr/bin/lua /join.lua
SERVICE
JOIN_IP=$(ip -n codex-sixbh-client -4 -o address show dev br-lan | awk '{split($4,a,"/"); print a[1]}')
test -n "$JOIN_IP"
printf '%s' "$JOIN_IP" > "$root/private/join-ip"
export JOIN_IP ADAPTER_CONFINED=1
# OEM get-info and the DHCP daemon share a stable namespace interface name.
NATIVE_SETUP
stage=controller_firewall
ip netns exec codex-sixbh-client nft -f - <<'RULES'
table inet codex_mesh_join {
    chain input {
        type filter hook input priority 0; policy drop;
        iifname "lo" accept
        ct state established,related accept
        ip saddr 198.18.68.1 tcp dport 20001 accept
        ip saddr 198.18.68.1 udp dport 20002 accept
        ip saddr STOCK_PEER_ADDRESS udp dport 20002 accept
        ip saddr 198.18.68.1 udp sport 67 udp dport 68 accept
        ip protocol icmp accept
    }
}
RULES
stage=encrypted_management
# Discovery probes are broadcast inside the private VLAN. This existing,
# tested driver option applies only to the temporary private-backhaul STA.
echo 1 > "$mcast_option"
test "$(cat "$mcast_option")" = 1
timeout -k 3 85 /sbin/ip netns exec codex-sixbh-client unshare --mount --pid --fork --kill-child -- \
    /sbin/ujail -E -i -c -p -C "$root/adapter-caps.json" -e JOIN_IP -e ADAPTER_CONFINED -R "$root" \
    -w /dev/null -r /dev/urandom -V "$root/dev/console:/dev/console" -V "$root/tmp:/var" \
    NATIVE_BIND -n codex-mesh-join -- /bin/sh /join-service.sh
'''
    announcement_source=(BASE/'estudio_mesh_announcement.lua').read_text()
    assert 'ANNOUNCEMENT_MODULE_END' not in announcement_source
    profile_setup = 'cat > "$root/announcement.lua" <<\'ANNOUNCEMENT_MODULE_END\'\n'+announcement_source+'\nANNOUNCEMENT_MODULE_END\n'
    if args.admit_profile:
        source = (BASE / 'estudio_mesh_admission_profile.lua').read_text()
        assert 'PROFILE_MODULE_END' not in source
        profile_setup += 'touch "$root/private/admit-profile"\ncat > "$root/admission-profile.lua" <<\'PROFILE_MODULE_END\'\n' + source + '\nPROFILE_MODULE_END\n'
    if args.receive_config:
        profile_setup += '\ntouch "$root/private/receive-config"\nmkdir -p "$root/private/openwrt-before" "$root/private/openwrt-candidate"\ncp /etc/config/wireless "$root/private/openwrt-before/wireless"\n'
        for name, target in {'estudio_mesh_tmp_guard.lua': 'usr/bin/tmp-luci-config',
                             'estudio_mesh_config_translate.lua': 'config-translate.lua',
                             'estudio_mesh_client_policy.lua': 'client-policy.lua',
                             'estudio_mesh_device_status.lua': 'device-status.lua',
                             'estudio_mesh_client_snapshot.lua': 'client-snapshot.lua'}.items():
            source = (BASE / name).read_text()
            assert 'CONFIG_MODULE_END' not in source
            profile_setup += 'cat > "$root/' + target + '" <<\'CONFIG_MODULE_END\'\n' + source + '\nCONFIG_MODULE_END\n'
        profile_setup += 'chmod 755 "$root/usr/bin/tmp-luci-config"\n'
    native_setup = native_cleanup = native_bind = ''
    if args.apply_config:
        profile_setup += 'touch "$root/private/apply-config"\nprintf %s 52AC6DE2B63BB051EB29D46337989727DC28F87A > "$root/private/live-controller"\n'
        profile_setup += 'cat > "$root/private/node-nickname.json" <<\'INITIAL_IDENTITY\'\n' + json.dumps(initial_identity) + '\nINITIAL_IDENTITY\n'
        native_setup = """(
    while test -d "$root"; do
        ucode /tmp/estudio_mesh_device_observe.uc || true
        sleep 3
    done
) > /tmp/codex-live-node-observation.log 2>&1 &
node_pid=$!
(
    for n in $(seq 1 410); do
        test ! -f "$root/private/adapter-committed.json" || break
        sleep 1
    done
    test -f "$root/private/adapter-committed.json" || exit 1
    ucode /tmp/estudio_mesh_clients.uc - context > "$root/private/wifi-context.json"
    ucode /tmp/estudio_mesh_client_context.uc "$root/private/wifi-context.json" "$root/private/wired-context.json"
    # A separate real network client exercises observation and app ownership.
    # Only its port role is declared; all MAC/IP observations come from traffic.
    ip netns add codex-mesh-report
    touch "$root/private/report-client-owned"
    ip link add mesh-report type veth peer name mesh-peer
    ip link set mesh-report master br-sixbh
    ip link set mesh-report up
    ip link set mesh-peer netns codex-mesh-report
    ip -n codex-mesh-report link set lo up
    ip -n codex-mesh-report link set mesh-peer address 02:00:00:00:00:0d
    ip -n codex-mesh-report link set mesh-peer up
    ucode -e 'import * as fs from "fs"; let p=ARGV[0]; let c=json(fs.readfile(p)); push(c.ports,{interface:"mesh-report",role:"client"}); if (!fs.writefile(p,sprintf("%J",c))) die("context write failed");' "$root/private/wired-context.json"
    cat > "$root/private/report-client-lease.sh" <<'CLIENT_LEASE'
#!/bin/sh
set -eu
case "$1" in bound|renew)
    test "$subnet" = 255.255.252.0 && test "$router" = 198.18.68.1
    ip addr add "$ip/22" dev mesh-peer
    ip route add default via "$router" dev mesh-peer
    printf %s "$ip" > /tmp/codex-mesh-join/private/report-client-ip
    ;;
esac
CLIENT_LEASE
    chmod 700 "$root/private/report-client-lease.sh"
    ip netns exec codex-mesh-report udhcpc -i mesh-peer -n -q -t 4 -T 3 -s "$root/private/report-client-lease.sh"
    ip netns exec codex-mesh-report ping -c 2 -W 2 198.18.68.1
    ip netns exec codex-mesh-report ping -c 2 -W 2 1.1.1.1
    touch "$root/private/report-client-ready"
    timeout 1100 /sbin/ip netns exec codex-mesh-report ping -i 1 1.1.1.1 > "$root/private/report-client-traffic.log" 2>&1 &
    exec sh /tmp/estudio_mesh_clients.sh --node "$root/private/wifi-context.json" "$root/private/wired-context.json" "$root/private/client-snapshot"
) > /tmp/codex-live-client-observation.log 2>&1 &
clients_pid=$!
test -d /tmp/oem-mesh-peer/private/native-apply
test ! -e /tmp/oem-mesh-peer/private/native-apply/service.json
sh /tmp/estudio_mesh_wifi_worker.sh serve-config > /tmp/codex-live-config-native.log 2>&1 &
native_pid=$!
for attempt in $(seq 1 20); do
    test ! -f /tmp/oem-mesh-peer/private/native-apply/service.json || break
    kill -0 "$native_pid"
    sleep 1
done
test -f /tmp/oem-mesh-peer/private/native-apply/service.json"""
        native_bind = '-V /tmp/oem-mesh-peer/private/native-apply:/private/native-apply -V /tmp/oem-mesh-peer/private/openwrt-before:/private/openwrt-before'
        native_cleanup = """    if [ -n "$native_pid" ]; then
        touch /tmp/oem-mesh-peer/private/native-apply/stop
        wait "$native_pid" || true
        if [ -f /tmp/codex-mesh-apply/status.json ]; then
            cp /tmp/codex-mesh-apply/status.json /tmp/codex-live-config-native-result.json
            ucode /tmp/estudio_mesh_wifi_apply.uc restore || return 1
        fi
        rm -f /tmp/oem-mesh-peer/private/native-apply/stop
    fi"""
        script = script.replace('timeout -k 3 85 ', 'timeout -k 3 1100 ')
    if resident:
        source=(BASE/'estudio_mesh_relay_controller.lua').read_text()
        assert 'CONTROLLER_MODULE_END' not in source
        profile_setup+='cat > "$root/relay-controller.lua" <<\'CONTROLLER_MODULE_END\'\n'+source+'\nCONTROLLER_MODULE_END\n'
        profile_setup += 'touch "$root/private/resident"\nmkdir "$root/control"\n'
        native_bind += ' -V /tmp/estudio-mesh-resident/control:/control'
        # Retire the relay while its admitted radios/upstream still exist.
        # The native Wi-Fi transaction restores radios in its own cleanup.
        native_cleanup = """    if test -e /tmp/estudio-mesh-relay; then
        # Keep supervision available to the transaction's rollback verifier.
        /bin/sh -c '
            . /tmp/estudio_mesh_links.sh
            link_data=$(jsonfilter -i /tmp/estudio-deco-backhaul-status.json -e "@.link_data")
            link_broadcast=$(jsonfilter -i /tmp/estudio-deco-backhaul-status.json -e "@.link_broadcast")
            mesh_links_retire_relay
        ' || return 1
        test ! -e /tmp/estudio-mesh-relay || return 1
    fi
""" + native_cleanup
        # Resident observation uses actual AP/port traffic. The synthetic
        # downstream client belongs only to the bounded integration probe.
        first=native_setup.index('    # A separate real network client')
        last=native_setup.index('    exec sh /tmp/estudio_mesh_clients.sh',first)
        native_setup=native_setup[:first]+native_setup[last:]
        native_setup=native_setup.replace('    for n in $(seq 1 410); do',
            '    while test ! -f /tmp/estudio-mesh-resident/control/stop; do')
        script=script.replace('timeout -k 3 1100 ', '')
        if getattr(args,'native_tipc',False):
            script=script.replace("clients_pid=''", "clients_pid=''\ntipc_pid=''")
            native_cleanup='''    if test -n "$tipc_pid"; then
        kill "$tipc_pid" 2>/dev/null || true
        wait "$tipc_pid" || true
        test ! -e /sys/module/tipc || return 1
        test ! -e /tmp/estudio-mesh-resident/tipc-response || return 1
    fi
'''+native_cleanup
            native_setup+='''
(
    set -eu
    task=/tmp/estudio-mesh-resident
    loaded=0
    transport_pid=''
    native_cleanup() {
        result=$?
        set +e
        test -z "$transport_pid" || { kill "$transport_pid" 2>/dev/null || true; wait "$transport_pid" || true; }
        if test "$loaded" = 1; then rmmod tipc || result=1; fi
        rm -f "$task/tipc-response" "$task/tipc-response.new" "$task/tipc-state.json.new" "$task/tipc-validation.json.new"
        test "$result" = 0 || touch "$task/control/stop"
        return "$result"
    }
    native_failure() { touch "$task/control/stop"; exit 1; }
    trap native_cleanup EXIT
    trap 'exit 0' HUP INT TERM
    test "$(cat /proc/sys/kernel/random/boot_id)" = "$(jsonfilter -i "$task/tipc-config.json" -e '@.boot_id')"
    test "$(sha256sum "$task/tipc-control" | cut -d ' ' -f 1)" = "$(jsonfilter -i "$task/tipc-config.json" -e '@.binary_sha256')"
    sha256sum -c "$task/tipc-module-checks" >/dev/null
    test ! -e /sys/module/tipc
    test ! -e "$task/tipc-response"
    test ! -e "$task/tipc-response.new"
    test "$(cat /sys/class/net/sixbh.1/brport/state)" = 3
    test "$(cat /sys/class/net/standby.1/brport/state)" = 3
    test "$(cat /sys/class/net/sixbh.1/brport/unicast_flood)" = 0
    node=$(jsonfilter -i "$task/tipc-config.json" -e '@.node_address')
    main=$(jsonfilter -i "$task/tipc-config.json" -e '@.main_address')
    insmod /lib/modules/6.18.52/tipc.ko
    loaded=1
    "$task/tipc-control" "$node" "$main" --native-path --native-resident > "$task/tipc-transport.log" 2>&1 &
    transport_pid=$!
    validated=0
    while test ! -e "$task/control/stop"; do
        kill -0 "$transport_pid" 2>/dev/null || native_failure
        if test -e "$task/tipc-response"; then
            validated=$((validated + 1))
            ucode "$task/tipc-validate.uc" "$validated" > "$task/tipc-validation.json.new" || native_failure
            test "$(jsonfilter -i "$task/tipc-validation.json.new" -e '@.verified')" = true || native_failure
            mv "$task/tipc-validation.json.new" "$task/tipc-validation.json"
            rm "$task/tipc-response"
        fi
        sleep 1
    done
) > /tmp/estudio-mesh-resident/tipc-worker.log 2>&1 &
tipc_pid=$!
'''
    script = script.replace('NATIVE_SETUP', native_setup).replace('NATIVE_CLEANUP', native_cleanup).replace('NATIVE_BIND', native_bind)
    script = script.replace('PROFILE_SETUP', profile_setup)
    return script.replace('STOCK_PEER_ADDRESS',stock_address)

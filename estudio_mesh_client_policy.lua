-- SPDX-License-Identifier: MIT
-- Decode Deco's isolated-device group and stage its separate wireless ports.
-- The native ucode policy module owns firewall-rule generation.
local M={}
local function mac(value)
    assert(type(value)=="string","Invalid client MAC")
    value=value:lower():gsub("-",":")
    assert(value:match("^%x%x:%x%x:%x%x:%x%x:%x%x:%x%x$"),"Invalid client MAC")
    assert(tonumber(value:sub(1,2),16)%2==0,"Multicast client MAC")
    return value
end
-- Manual link preferences and NRD exclusions are separate stock settings.
-- Mesh Technology off means no automatic steering, not denial of Wi-Fi access.
-- Keep both in the received plan; the dynamic native policy must also consume
-- current peer availability before it can safely enforce preferred-node rules.
function M.preferences(cursor)
    local clients,seen={},{}
    for _,section in pairs(cursor:get_all("client_mgmt") or {}) do
        if section[".type"]=="client" and (section.link_pri_band~=nil or section.link_pri_device_id~=nil) then
            local address=mac(section.mac)
            assert(not seen[address],"Duplicate client preference")
            seen[address]=true
            local band,node=section.link_pri_band,section.link_pri_device_id
            assert(band==nil or band=="band2_4" or band=="band5" or band=="band6","Invalid preferred band")
            assert(node==nil or (type(node)=="string" and #node==40 and node:match("^%x+$")),"Invalid preferred node")
            clients[address]={mac=address,preferred_band=band,preferred_node=node,mesh_enabled=true}
        end
    end
    for _,section in pairs(cursor:get_all("nrd_blacklist") or {}) do
        if section[".type"]=="client" then
            local address=mac(section.mac)
            clients[address]=clients[address] or {mac=address}
            clients[address].mesh_enabled=false
        end
    end
    local result={}
    for _,client in pairs(clients) do result[#result+1]=client end
    table.sort(result,function(a,b) return a.mac<b.mac end)
    return result
end
function M.from_config(cursor)
    local out={}
    local enabled=cursor:get("iot_wifi","iot","client_isolation") or "0"
    assert(enabled=="0" or enabled=="1","Invalid isolation switch")
    if enabled=="0" or cursor:get("sysmode","sysmode","mode")=="AP" then return out end
    for _,section in pairs(cursor:get_all("client_mgmt") or {}) do
        if section[".type"]=="client" and section.enable_isolation=="1" then
            out[#out+1]=mac(assert(section.mac))
        end
    end
    table.sort(out)
    return out
end
-- ath11k does not expose AP/VLAN with its hardware-encryption path. Prepare
-- two BSSes with complementary admission lists instead. This is only staged:
-- the bridge policy and station association must be verified before applying.
function M.stage_bss(cursor,clients)
    local main5=cursor:get("wireless","test5") and "test5" or "default_radio1"
    if main5=="default_radio1" then
        assert(cursor:get("wireless",main5,"device")=="radio1"
            and cursor:get("wireless",main5,"mode")=="ap","Missing native 5 GHz AP")
    end
    local addresses={}
    for _,value in ipairs(clients) do addresses[#addresses+1]=mac(value) end
    local groups={}
    for _,entry in ipairs({
        {"default_radio0","dec_iso2","deco-i2","02:00:00:00:00:1c"},
        {main5,"dec_iso5","deco-i5","02:00:00:00:00:0a"},
        {"default_radio2","dec_iso6","deco-i6","02:00:00:00:00:0b"},
        {"deco_iot2","dec_ioti2","deco-ti2","02:00:00:00:00:1e"},
        {"deco_iot5","dec_ioti5","deco-ti5","02:00:00:00:00:0f"}
    }) do
        local normal,isolated,iface,address=unpack(entry)
        assert(not cursor:get("wireless",isolated)
            or cursor:get("wireless",isolated,"deco_isolation_owned")=="1",
            "Existing isolated section is not adapter-owned")
        cursor:delete("wireless",isolated)
        if cursor:get("wireless",normal,"deco_isolation_owned")=="1" then
            cursor:delete("wireless",normal,"macfilter")
            cursor:delete("wireless",normal,"maclist")
            cursor:delete("wireless",normal,"deco_isolation_owned")
        end
        if #addresses>0 and cursor:get("wireless",normal)
                and (normal~="default_radio2" or cursor:get("wireless",normal,"disabled")~="1") then
            assert(cursor:get("wireless",normal,"mode")=="ap","Missing normal AP")
            assert(not cursor:get("wireless",normal,"macfilter"),"Existing AP access policy needs merging")
            assert(not cursor:get("wireless",normal,"macfile"),"Existing AP access file needs merging")
            assert(cursor:set("wireless",normal,"macfilter","deny"))
            assert(cursor:set("wireless",normal,"maclist",addresses))
            assert(cursor:set("wireless",normal,"deco_isolation_owned","1"))
            assert(cursor:set("wireless",isolated,"wifi-iface"))
            for _,option in ipairs({"device","mode","network","ssid","key","encryption","hidden","disabled","ieee80211r"}) do
                local value=assert(cursor:get("wireless",normal,option),"Missing AP option")
                assert(cursor:set("wireless",isolated,option,value))
            end
            -- The 6 GHz group must retain mandatory protected management
            -- frames and SAE H2E, just like its normal AP.
            for _,option in ipairs({"ieee80211w","sae_pwe","sae_require_mfp",
                    "mobility_domain","nasid","ft_psk_generate_local","ft_over_ds","reassociation_deadline"}) do
                local value=cursor:get("wireless",normal,option)
                if value then assert(cursor:set("wireless",isolated,option,value)) end
            end
            for option,value in pairs({ifname=iface,macaddr=address,isolate="0",macfilter="allow",maclist=addresses,deco_isolation_owned="1"}) do
                assert(cursor:set("wireless",isolated,option,value))
            end
            groups[#groups+1]={normal=normal,isolated=isolated,interface=iface}
        end
    end
    return groups
end
return M

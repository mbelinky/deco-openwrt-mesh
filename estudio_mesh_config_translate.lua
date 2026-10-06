-- SPDX-License-Identifier: MIT
-- Decode genuine Deco configuration and prepare native OpenWrt Wi-Fi settings.
-- All output stays in private RAM staging. This module never reloads a radio,
-- applies a configuration, changes the uplink, or writes a flash partition.
local fs=require "nixio.fs"
local json=require "luci.json"
local uci=require "luci.model.uci"
local crypto=require "luci.model.crypto"
local config=require "luci.sys.config"
local M={}
local root="/private/adapter-decoded"
local security_modes={wpa2={encryption="psk2+ccmp",pmf="0"},
    wpa3={encryption="sae",pmf="2"},["wpa3+wpa2"]={encryption="sae-mixed",pmf="1"}}
local function prepare()
    fs.mkdir(root,"700");fs.mkdir(root.."/config","700")
    for name in fs.dir(root.."/config") do
        if name~="." and name~=".." then assert(fs.unlink(root.."/config/"..name)) end
    end
end
local function boolean(value)
    if value=="1" then return true end
    if value=="0" then return false end
    return nil
end
function M.translate(input,version)
    prepare()
    local xml=root.."/received.xml"
    fs.unlink(xml)
    crypto.dec_file_entry_prv(input,xml)
    local text=fs.readfile(xml)
    if not text or #text>2097152 or not text:match("<config>%s*") or not text:match("</config>%s*$") then
        return nil,"configuration decryption failed"
    end
    -- The OEM converter uses tag names as UCI filenames. Constrain those names
    -- before asking it to write only under the private staging directory.
    if text:find("<!",1,true) then return nil,"unsupported configuration XML" end
    for tag in text:gmatch("<([^>]+)>") do
        if tag:sub(1,1)~="?" then
            local name=tag:match("^/?([%w_%-]+)")
            if not name then return nil,"invalid configuration XML tag" end
            local suffix=tag:gsub("^/?[%w_%-]+", "",1)
            if suffix~="" and suffix~="/" and not suffix:match('^ name="[%w_.:%-]+"/?$') then
                return nil,"invalid configuration XML attributes"
            end
        end
    end
    if not config.xmlToFile(xml,root) then return nil,"configuration XML rejected" end
    local source=uci.cursor(root.."/config")
    if source:get("sync","config","version")~=version then return nil,"configuration version mismatched" end
    if source:get("sync","config","sync_version")~="2" then return nil,"sync version mismatched" end
    local ap=source:get_all("wifi","ap")
    if not ap or type(ap.ssid)~="string" or #ap.ssid<1 or #ap.ssid>32 then return nil,"invalid Wi-Fi name" end
    local main_security=security_modes[ap.enc_type]
    if ap.encryption~="1" or not main_security then return nil,"unsupported Wi-Fi encryption" end
    if ap.wpa3~=nil and ap.wpa3~=(ap.enc_type=="wpa2" and "0" or "1") then
        return nil,"inconsistent Wi-Fi WPA3 switch"
    end
    if type(ap.password)~="string" or #ap.password<8 or #ap.password>63 then return nil,"invalid Wi-Fi password" end
    for _,key in ipairs({"enable","enable_2g","enable_5g","enable_6g","hidessid","ieee80211r"}) do
        if boolean(ap[key])==nil then return nil,"invalid Wi-Fi switch" end
    end
    -- The stock wpsd init script defaults this setting to enabled. Native
    -- WPS is restricted to visible WPA2-capable main APs on 2.4/5 GHz.
    local wps_enabled=source:get("wps","wpsd","enabled") or "1"
    if boolean(wps_enabled)==nil then return nil,"invalid WPS switch" end
    local beamforming=ap.beamforming or "1"
    if boolean(beamforming)==nil then return nil,"invalid beamforming switch" end
    local unsupported={}
    local pending_validation={}
    local policy=dofile("/client-policy.lua")
    local preferences_ok,client_preferences=pcall(policy.preferences,source)
    if not preferences_ok then return nil,"invalid client connection preferences" end
    if #client_preferences>0 then
        unsupported[#unsupported+1]="client connection preferences and mesh steering"
    end
    if ap.enable_6g=="1" then
        if ap.encryption_6g~="1" or ap.enc_type_6g~="wpa3" then
            return nil,"unsupported 6 GHz Wi-Fi encryption"
        end
        if type(ap.ssid_6g)~="string" or #ap.ssid_6g<1 or #ap.ssid_6g>32 then
            return nil,"invalid 6 GHz Wi-Fi name"
        end
        if type(ap.password_6g)~="string" or #ap.password_6g<8 or #ap.password_6g>63 then
            return nil,"invalid 6 GHz Wi-Fi password"
        end
        if boolean(ap.hidessid_6g)==nil then return nil,"invalid 6 GHz Wi-Fi switch" end
        pending_validation[#pending_validation+1]="Physical downstream 6 GHz Wi-Fi client"
    end
    if ap.ieee80211r=="1" then
        if ap.enc_type~="wpa2" then unsupported[#unsupported+1]="WPA3 fast roaming" end
        if ap.enable_6g=="1" then unsupported[#unsupported+1]="6 GHz fast roaming" end
        pending_validation[#pending_validation+1]="Fast roaming with a physical stock Deco peer"
    end
    local guest=source:get_all("wifi","guest") or {}
    local guest_enabled=guest.enable or "0"
    if boolean(guest_enabled)==nil then return nil,"invalid guest Wi-Fi switch" end
    local guest_security
    local guest_ethernet_default_retained=false
    if guest_enabled=="1" and ap.ieee80211r=="1" then unsupported[#unsupported+1]="guest fast roaming" end
    if guest_enabled=="1" then
        guest_security=security_modes[guest.enc_type]
        if guest.encryption~="1" or not guest_security then return nil,"unsupported guest Wi-Fi encryption" end
        if guest.wpa3~=nil and guest.wpa3~=(guest.enc_type=="wpa2" and "0" or "1") then
            return nil,"inconsistent guest WPA3 switch"
        end
        if type(guest.ssid)~="string" or #guest.ssid<1 or #guest.ssid>32 then return nil,"invalid guest Wi-Fi name" end
        if type(guest.password)~="string" or #guest.password<8 or #guest.password>63 then return nil,"invalid guest Wi-Fi password" end
        for _,key in ipairs({"enable_2g","enable_5g","enable_6g","host_isolation","vlan_enable"}) do
            if boolean(guest[key])==nil then return nil,"invalid guest Wi-Fi switch" end
        end
        if guest.enable_6g=="1" then
            if guest.encryption_6g~="1" or guest.enc_type_6g~="wpa3" then return nil,"unsupported 6 GHz guest encryption" end
            if type(guest.ssid_6g)~="string" or #guest.ssid_6g<1 or #guest.ssid_6g>32 then return nil,"invalid 6 GHz guest name" end
            if type(guest.password_6g)~="string" or #guest.password_6g<8 or #guest.password_6g>63 then return nil,"invalid 6 GHz guest password" end
        end
        if source:get("sysmode","sysmode","mode")~="Router" or guest.host_isolation~="1" then
            unsupported[#unsupported+1]="guest access to main network"
        end
        if guest.vlan_enable=="1" then
            if guest.vlan_id=="591" then
                -- VLAN 591 is retained OEM Ethernet metadata. The native owner
                -- must prove both physical Ethernet ports are outside the mesh
                -- before accepting this wireless-only guest configuration.
                guest_ethernet_default_retained=true
                pending_validation[#pending_validation+1]="Guest Ethernet VLAN unavailable on wireless-only node"
            else unsupported[#unsupported+1]="guest Ethernet VLAN" end
        end
        if (guest.access_duration or "-1")~="-1" then unsupported[#unsupported+1]="guest access schedule" end
        if (guest.bw_limit_enable or "0")~="0" then unsupported[#unsupported+1]="guest bandwidth limit" end
        pending_validation[#pending_validation+1]="Physical downstream guest Wi-Fi client"
    end
    local iot=source:get_all("iot_wifi","iot") or {}
    local iot_enabled=iot.enable or "0"
    if boolean(iot_enabled)==nil then return nil,"invalid IoT Wi-Fi switch" end
    local iot_encryption
    if iot_enabled=="1" then
        -- The live stock IoT beacons advertise WPA+RSN, PSK and CCMP/TKIP
        -- for wpa2+wpa. Preserve that compatibility instead of assuming WPA2.
        iot_encryption=({wpa2="psk2+ccmp",["wpa2+wpa"]="psk-mixed+tkip+ccmp"})[iot.enc_type]
        if iot.encryption~="1" or not iot_encryption then return nil,"unsupported IoT Wi-Fi encryption" end
        if type(iot.ssid)~="string" or #iot.ssid<1 or #iot.ssid>32 then return nil,"invalid IoT Wi-Fi name" end
        if type(iot.password)~="string" or #iot.password<8 or #iot.password>63 then return nil,"invalid IoT Wi-Fi password" end
        for _,key in ipairs({"enable_2g","enable_5g","enable_6g","ieee80211r","host_isolation","vlan_enable"}) do
            if boolean(iot[key])==nil then return nil,"invalid IoT Wi-Fi switch" end
        end
        if iot.enable_6g=="1" then unsupported[#unsupported+1]="6 GHz IoT network" end
        if iot.ieee80211r=="1" then unsupported[#unsupported+1]="IoT fast roaming" end
        if iot.host_isolation=="1" or iot.vlan_enable=="1" then unsupported[#unsupported+1]="IoT network separation" end
        pending_validation[#pending_validation+1]="Physical downstream IoT Wi-Fi client"
    end
    local before=assert(fs.readfile("/private/openwrt-before/wireless"))
    fs.mkdir("/private/openwrt-next","700")
    assert(fs.writefile("/private/openwrt-next/wireless",before))
    -- UCI operates on a separate package until every input has been validated.
    local out=uci.cursor("/private/openwrt-next")
    local main5=out:get("wireless","test5") and "test5" or "default_radio1"
    if main5=="default_radio1" then
        assert(out:get("wireless",main5)=="wifi-iface"
            and out:get("wireless",main5,"device")=="radio1"
            and out:get("wireless",main5,"mode")=="ap","Missing native 5 GHz AP")
    end
    -- OpenWrt owns VHT/HE capabilities at radio scope and masks requested
    -- flags against the driver's actual capabilities when generating hostapd.
    for _,radio in ipairs({"radio0","radio1","radio2"}) do
        assert(out:get("wireless",radio)=="wifi-device","Missing OpenWrt radio")
        for _,option in ipairs({"su_beamformer","su_beamformee","mu_beamformer","mu_beamformee",
                "he_su_beamformer","he_su_beamformee","he_mu_beamformer"}) do
            assert(out:set("wireless",radio,option,beamforming))
        end
    end
    pending_validation[#pending_validation+1]="Physical beamforming interoperability and guest/IoT/backhaul parity"
    for _,entry in ipairs({{"default_radio0","enable_2g"},{main5,"enable_5g"}}) do
        local section=entry[1]
        assert(out:get("wireless",section)=="wifi-iface","Missing OpenWrt AP")
        assert(out:get("wireless",section,"mode")=="ap","Target is not an AP")
        for k,v in pairs({ssid=ap.ssid,key=ap.password,encryption=main_security.encryption,
                ieee80211w=main_security.pmf,hidden=ap.hidessid,
                disabled=(ap.enable=="1" and ap[entry[2]]=="1") and "0" or "1",ieee80211r="0"}) do
            assert(out:set("wireless",section,k,v))
        end
        local pairing=wps_enabled=="1" and ap.enable=="1" and ap[entry[2]]=="1"
            and ap.hidessid=="0" and ap.enc_type~="wpa3"
        assert(out:set("wireless",section,"wps_pushbutton",pairing and "1" or "0"))
        -- Stock Deco uses over-the-air FT with locally derived WPA2 keys.
        -- SAE, guest and 6 GHz FT remain explicitly unsupported in the plan.
        local roaming=ap.ieee80211r=="1" and ap.enc_type=="wpa2"
        assert(out:set("wireless",section,"ieee80211r",roaming and "1" or "0"))
        for option,value in pairs({mobility_domain="5348",nasid="r0kh.tp-link.com",
                ft_psk_generate_local="1",ft_over_ds="0",reassociation_deadline="1000"}) do
            if roaming then assert(out:set("wireless",section,option,value))
            else out:delete("wireless",section,option) end
        end
        if ap.enc_type~="wpa2" then
            assert(out:set("wireless",section,"sae_pwe","2"))
            assert(out:set("wireless",section,"sae_require_mfp","1"))
        else
            out:delete("wireless",section,"sae_pwe")
            out:delete("wireless",section,"sae_require_mfp")
        end
    end
    assert(out:get("wireless","default_radio2","mode")=="ap","Missing OpenWrt 6 GHz AP")
    assert(out:set("wireless","default_radio2","wps_pushbutton","0"))
    assert(out:set("wireless","default_radio2","disabled",
        (ap.enable=="1" and ap.enable_6g=="1") and "0" or "1"))
    if ap.enable_6g=="1" then
        for k,v in pairs({ssid=ap.ssid_6g,key=ap.password_6g,encryption="sae",hidden=ap.hidessid_6g,
                ieee80211w="2",sae_pwe="1",ieee80211r="0",
                network=assert(out:get("wireless",main5,"network")),macaddr="02:00:00:00:00:05"}) do
            assert(out:set("wireless","default_radio2",k,v))
        end
        -- Keep the demonstrated indoor lab operating point until channel,
        -- bandwidth and regulatory-limit handling have been validated.
        for k,v in pairs({disabled="0",channel="37",htmode="HE20",txpower="10",reg_power_type="0"}) do
            assert(out:set("wireless","radio2",k,v))
        end
    end
    for _,radio in ipairs({"radio0","radio1","radio2"}) do assert(out:set("wireless",radio,"country","ES")) end
    for _,entry in ipairs({
        {"deco_iot2","default_radio0","enable_2g","deco-t2","02:00:00:00:00:1d"},
        {"deco_iot5",main5,"enable_5g","deco-t5","02:00:00:00:00:0e"}
    }) do
        local section,main,band,iface,address=unpack(entry)
        assert(not out:get("wireless",section) or out:get("wireless",section,"deco_iot_owned")=="1",
            "Existing IoT section is not adapter-owned")
        out:delete("wireless",section)
        if iot_enabled=="1" then
            assert(out:set("wireless",section,"wifi-iface"))
            for k,v in pairs({device=assert(out:get("wireless",main,"device")),mode="ap",
                    network=assert(out:get("wireless",main,"network")),ifname=iface,macaddr=address,
                    ssid=iot.ssid,key=iot.password,encryption=iot_encryption,hidden="0",ieee80211r="0",
                    disabled=iot[band]=="1" and "0" or "1",deco_iot_owned="1"}) do
                assert(out:set("wireless",section,k,v))
            end
        end
    end
    if guest_enabled=="1" and out:get("wireless","default_radio0","network")~="sixbh" then
        unsupported[#unsupported+1]="guest backhaul unavailable"
    end
    for _,entry in ipairs({
        {"deco_guest2","radio0","enable_2g","deco-g2","02:00:00:00:00:1b"},
        {"deco_guest5","radio1","enable_5g","deco-g5","02:00:00:00:00:08"},
        {"deco_guest6","radio2","enable_6g","deco-g6","02:00:00:00:00:09"}
    }) do
        local section,radio,band,iface,address=unpack(entry)
        assert(not out:get("wireless",section) or out:get("wireless",section,"deco_guest_owned")=="1",
            "Existing guest section is not adapter-owned")
        out:delete("wireless",section)
        if guest_enabled=="1" and (radio~="radio2" or guest.enable_6g=="1") then
            local six=radio=="radio2"
            assert(out:set("wireless",section,"wifi-iface"))
            for k,v in pairs({device=radio,mode="ap",network="sixguest",ifname=iface,macaddr=address,
                    ssid=six and guest.ssid_6g or guest.ssid,key=six and guest.password_6g or guest.password,
                    encryption=six and "sae" or guest_security.encryption,
                    ieee80211w=six and "2" or guest_security.pmf,hidden="0",ieee80211r="0",isolate="1",
                    disabled=(ap.enable=="1" and guest[band]=="1") and "0" or "1",deco_guest_owned="1"}) do
                assert(out:set("wireless",section,k,v))
            end
            if six or guest.enc_type~="wpa2" then
                assert(out:set("wireless",section,"sae_pwe",six and "1" or "2"))
                assert(out:set("wireless",section,"sae_require_mfp","1"))
            end
            if six then
                for k,v in pairs({disabled="0",channel="37",htmode="HE20",txpower="10",reg_power_type="0"}) do
                    assert(out:set("wireless","radio2",k,v))
                end
            end
        end
    end
    local isolated_clients=policy.from_config(source)
    local isolation_groups=policy.stage_bss(out,isolated_clients)
    if #isolated_clients>0 then pending_validation[#pending_validation+1]="Physical client isolation across all bands" end
    assert(out:commit("wireless"))
    assert(fs.rename("/private/openwrt-next/wireless","/private/openwrt-candidate/wireless"))
    local plan={version=version,validated=true,applied=false,translated_bands={"2.4 GHz","5 GHz","6 GHz"},
        unsupported=unsupported,pending_validation=pending_validation,country="ES",uplink_preserved=true,
        beamforming=beamforming=="1",
        client_preferences=client_preferences,
        iot_enabled=iot_enabled=="1",
        guest_ethernet_default_retained=guest_ethernet_default_retained,
        guest_enabled=guest_enabled=="1",guest_6g_enabled=guest_enabled=="1" and guest.enable_6g=="1",
        isolated_clients=isolated_clients,isolation_groups=isolation_groups}
    assert(fs.writefile("/private/adapter-plan.json",json.encode(plan)))
    return plan
end
return M

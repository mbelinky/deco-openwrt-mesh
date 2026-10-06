-- SPDX-License-Identifier: MIT
-- Native Main control belongs to the existing confined RAM service.
-- A stored-choice request never changes Auto or a foreign parent choice.
local fs=require('nixio.fs')
local json=require('luci.json')
local nixio=require('nixio')
local tmp=require('tmpv2')
local main='52AC6DE2B63BB051EB29D46337989727DC28F87A'
local spare='520C7831F7302242F81407BC050E7E7C4B5C697F'
local stock='5355353F82EA7AF944FFF5582BFE58BA00CA10BF'
local control='/control/relay-retry.json'
local admission='/control/relay-preparation.json'
local preparation_stage='initial_guard'
local function read_main(with_address)
    local client=tmp.tmp_client(0x400f,'198.18.68.1',nil,true,false,nil,nil)
    local ok,value=pcall(function()
        assert(client:connect())
        local raw=assert(client:request(0x400f,json.encode({params={}})))
        local response=assert(json.decode(raw))
        assert(response.error_code==0 and type(response.result.device_list)=='table')
        local rows=response.result.device_list
        assert(#rows>0 and #rows<=64)
        local identities={}
        for _,row in ipairs(rows) do
            assert(type(row.device_id)=='string' and #row.device_id==40
                and row.device_id:match('^[0-9A-F]+$') and not identities[row.device_id])
            identities[row.device_id]=row
        end
        local function mac(row) return row and row.mac and row.mac:lower():gsub('-',':') end
        assert(mac(identities[main])=='02:00:00:00:00:13')
        assert(mac(identities[spare])=='02:00:00:00:00:19')
        assert(mac(identities[stock])=='02:00:00:00:00:18')
        local target_ip
        if with_address then
            local raw=assert(client:request(0xf0,json.encode({params={file='/tmp/sync-server/mesh_dev_list'}})))
            local response=assert(json.decode(raw))
            assert(response.error_code==0 and type(response.result.data)=='string')
            local directory=assert(json.decode(response.result.data))
            local target=directory[stock]
            assert(type(target)=='table' and type(target.ip)=='string')
            local a,b,c,d=target.ip:match('^(%d+)%.(%d+)%.(%d+)%.(%d+)$')
            assert(a=='192' and b=='168' and tonumber(c)>=68 and tonumber(c)<=71
                and tonumber(d)<=255 and tostring(tonumber(c))==c and tostring(tonumber(d))==d
                and not (c=='68' and d=='0') and not (c=='71' and d=='255'))
            local matches=0
            for _,node in pairs(directory) do
                if type(node)=='table' and node.ip==target.ip then matches=matches+1 end
            end
            assert(matches==1,'native preparation peer address is not uniquely bound')
            target_ip=target.ip
        end
        return {rows=rows,target=identities[stock],target_ip=target_ip}
    end)
    pcall(client.disconnect,client)
    return ok and value or nil
end
local function prepare_admission()
    assert(os.getenv('ADAPTER_CONFINED')=='1' and fs.stat('/codex-isolated-peer')
        and fs.stat('/private/resident') and fs.stat('/private/admit-profile'))
    fs.unlink(admission)
    preparation_stage='initial_controller_read'
    local data=assert(read_main(true),'native preparation controller read failed')
    local function healthy(value)
        assert(#value.rows==14,'native preparation baseline differs')
        for _,row in ipairs(value.rows) do
            assert(row.group_status=='connected' and row.inet_status=='online','native preparation baseline unhealthy')
        end
        assert(type(value.target.topology)=='table' and value.target.topology.auto==true
            and value.target.parent_device_id==main,'native preparation target is not Auto/Main')
    end
    preparation_stage='initial_health';healthy(data)
    local target_ip=data.target_ip
    local client=tmp.tmp_client(0xf0,target_ip,nil,true,false,nil,nil)
    local ok,value=pcall(function()
        preparation_stage='peer_connect';assert(client:connect(),'native preparation peer unavailable')
        local function address(path,expected)
            preparation_stage=path=='/sys/class/net/br-lan/address' and 'peer_lan'
                or path=='/sys/class/net/ath13/address' and 'peer_station5' or 'peer_station2'
            local raw=assert(client:request(0xf0,json.encode({params={file=path}})))
            local response=assert(json.decode(raw))
            local observed=response.result and response.result.data
            assert(response.error_code==0 and type(observed)=='string'
                and observed:gsub('%s+$',''):lower()==expected,'native preparation peer identity differs')
            return expected
        end
        return {lan=address('/sys/class/net/br-lan/address','02:00:00:00:00:18'),
            station5=address('/sys/class/net/ath13/address','02:00:00:00:00:22'),
            station2=address('/sys/class/net/ath03/address','02:00:00:00:00:23')}
    end)
    pcall(client.disconnect,client)
    assert(ok and value,'native preparation fixed peer read failed')
    preparation_stage='final_controller_read'
    data=assert(read_main(true),'native preparation final controller read failed')
    assert(data.target_ip==target_ip,'native preparation peer address changed during admission')
    preparation_stage='final_health';healthy(data)
    local descendants,parents={}, {[stock]=true}
    for _=1,14 do
        local added=false
        for _,row in ipairs(data.rows) do
            if parents[row.parent_device_id] and not parents[row.device_id] then
                assert(type(row.device_id)=='string' and #row.device_id==40
                    and row.device_id:match('^[A-Z0-9]+$'),'invalid descendant identity')
                parents[row.device_id]=true;descendants[#descendants+1]=row.device_id;added=true
            end
        end
        if not added then break end
    end
    local record={version=1,owner=spare,target=stock,main=main,
        boot_id=assert(fs.readfile('/private/boot-id')):gsub('%s+$',''),
        observed_at=os.time(),device_count=14,stock_auto_main=true,
        lan=value.lan,station5=value.station5,station2=value.station2,target_ip=target_ip,
        original_target_parent=data.target.topology,actual_descendants=descendants}
    preparation_stage='checkpoint'
    assert(fs.writefile(admission..'.new',json.encode(record))
        and fs.chmod(admission..'.new','600') and fs.rename(admission..'.new',admission),
        'cannot store native preparation admission')
    return record
end
local function request()
    if fs.lstat(control,'type')~='reg' or fs.stat(control,'uid')~=0 then return nil end
    local value=json.decode(fs.readfile(control) or 'null')
    local now=os.time()
    if type(value)~='table' or value.version~=1 or value.owner~=spare or value.target~=stock
        or type(value.token)~='string' or #value.token~=32 or not value.token:match('^[0-9a-f]+$')
        or type(value.generation)~='number' or value.generation<0 or value.generation%1~=0
        or value.boot_id~=(fs.readfile('/private/boot-id') or ''):gsub('%s+$','')
        or type(value.expires_at)~='number' or value.expires_at<=now or value.expires_at>now+600
        or type(value.updated_at)~='number' or value.updated_at>now or now-value.updated_at>10 then
        return nil
    end
    if value.kind=='initial' then
        if value.generation~=0 or type(value.configuration_version)~='string'
            or #value.configuration_version<1 or #value.configuration_version>64
            or not value.configuration_version:match('^[0-9.]+$')
            or value.nonce~=value.token..':0' then return nil end
        local committed=json.decode(fs.readfile('/private/adapter-committed.json') or 'null')
        local staged=json.decode(fs.readfile('/private/adapter-staged.json') or 'null')
        if type(committed)~='table' or type(staged)~='table'
            or committed.version~=value.configuration_version or staged.version~=committed.version then return nil end
    elseif value.generation<1 or (value.kind~=nil and value.kind~='recovery')
        or value.nonce~=value.token..':'..value.generation then return nil end
    return value
end
local function store(value)
    assert(fs.writefile('/control/relay-controller-state.json.new',json.encode(value)))
    assert(fs.rename('/control/relay-controller-state.json.new','/control/relay-controller-state.json'))
end
local function retry(ticket)
    local previous=json.decode(fs.readfile('/control/relay-controller-state.json') or 'null')
    if type(previous)=='table' and previous.nonce==ticket.nonce
        and previous.command_attempted==true then return true end
    local result={version=1,nonce=ticket.nonce,generation=ticket.generation,kind=ticket.kind or 'recovery',
        configuration_version=ticket.configuration_version,
        observed_at=os.time(),command_attempted=false}
    local data=read_main()
    if not data then result.reason='controller_read';store(result);return false end
    local target=data.target
    if type(target.topology)~='table' or target.topology.auto~=false
        or target.topology.device_id~=spare
        or (target.parent_device_id~=main and target.parent_device_id~=spare) then
        result.reason='stored_choice_changed';store(result);return true
    end
    for _,row in ipairs(data.rows) do
        if row.device_id~=stock and (row.group_status~='connected' or row.inet_status~='online') then
            result.reason='baseline_unhealthy';store(result);return false
        end
    end
    local current=request()
    if not current or current.nonce~=ticket.nonce or current.configuration_version~=ticket.configuration_version
        or current.expires_at<=os.time()+70
        or fs.stat('/control/stop') then
        result.reason='lease_changed';store(result);return false
    end
    local payload='/private/relay-retry-payload.json'
    local reply='/private/relay-retry-reply.json'
    assert(fs.writefile(payload,json.encode({params={device_id=stock,
        topology={auto=false,device_id=spare}}})))
    fs.unlink(reply)
    result.command_attempted=true;result.attempted_at=os.time();store(result)
    local code=os.execute('/usr/bin/tmpcli -S -s -U root -u 198.18.68.1 -p 20001 -w 65 -o 0x4091'
        ..' -I '..payload..' > '..reply..' 2>/dev/null')
    local response=json.decode(fs.readfile(reply) or 'null')
    result.finished_at=os.time();result.controller_accepted=code==0
        and type(response)=='table' and response.error_code==0
    result.reason=result.controller_accepted and 'replayed' or 'reply_unconfirmed'
    fs.unlink(payload);fs.unlink(reply);store(result)
    return true
end
if arg[1]=='prepare' then
    local ok,data=pcall(prepare_admission)
    print('DECO_CONTROLLER_RESULT '..json.encode({read_only_stock=true,received=ok,
        device_count=ok and data.device_count or nil,stock_auto_main=ok or nil,
        station_identities_verified=ok or nil,failure_stage=not ok and preparation_stage or nil}))
    if not ok then os.exit(1) end
elseif arg[1]=='read' then
    local data=read_main()
    print('DECO_CONTROLLER_RESULT '..json.encode({read_only=true,
        received=data~=nil,device_count=data and #data.rows}))
    assert(data,'native controller read failed')
elseif arg[1]=='watch' then
    assert(fs.stat('/private/resident') and fs.stat('/private/admit-profile'))
    local done
    while not fs.stat('/control/stop') do
        local ticket=request()
        if ticket and ticket.nonce~=done then
            local ok,finished=pcall(retry,ticket)
            if ok and finished then done=ticket.nonce end
        end
        nixio.nanosleep(2)
    end
else error('unsupported native controller action') end

-- SPDX-License-Identifier: MIT
-- Registration profile for the experimental satellite management service.
-- Keep the hardware's shared compatibility declarations, while making the
-- controller retain ownership of configuration and general app operations.
-- This is not a claim of complete optional-feature implementation.
return function(info)
    assert(type(info)=="table" and type(info.component_whole)=="table")
    assert(info.devid=="520C7831F7302242F81407BC050E7E7C4B5C697F")
    info.cfg={}
    -- Group detection is served directly but not globally advertised by the
    -- controller. Advertising it would introduce a new routing destination.
    info.op={"0x0001","0xc401","0xc402","0xc40d"}
    info.opcode_cfg={}
    for _,role in ipairs({"router_owner","router_user","ap_owner","ap_user"}) do
        info["component_"..role]={}
    end
    return info
end

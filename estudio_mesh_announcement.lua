-- SPDX-License-Identifier: MIT
-- A failed periodic encryption must not terminate the mesh session.
-- Initial controller admission still uses its original fail-fast path.
local sync=require "luci.model.sync"

return function(data,key)
    local ok,secret=pcall(sync.encrypt_table,data,key)
    if not ok then return nil,"encrypt_exception" end
    if type(secret)~="string" or #secret==0 then
        return nil,"invalid_ciphertext"
    end
    return secret
end

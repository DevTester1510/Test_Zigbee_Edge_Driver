local data_types = require "st.zigbee.data_types"
local UintABC = require "st.zigbee.data_types.base_defs.UintABC"

-- Copyright 2024 SmartThings
--
-- Licensed under the Apache License, Version 2.0 (the "License");
-- you may not use this file except in compliance with the License.
-- You may obtain a copy of the License at
--
--     http://www.apache.org/licenses/LICENSE-2.0
--
-- Unless required by applicable law or agreed to in writing, software
-- distributed under the License is distributed on an "AS IS" BASIS,
-- WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
-- See the License for the specific language governing permissions and
-- limitations under the License.

-- DO NOT EDIT: this code is automatically generated by tools/zigbee-lib_generator/generate_clusters_from_xml.py
-- Script version: b'aab104a27ce2f5279180e69ba93ef579673eddc5'
-- ZCL XML version: 7.2

--- @class st.zigbee.zcl.clusters.TouchlinkCommissioning.types.TlStatus: st.zigbee.data_types.Uint8
--- @alias TlStatus
---
--- @field public byte_length number 1
--- @field public SUCCESS number 0
--- @field public FAILURE number 1
local TlStatus = {}
local new_mt = UintABC.new_mt({NAME = "TlStatus", ID = data_types.name_to_id_map["Uint8"]}, 1)
new_mt.__index.pretty_print = function(self)
  local name_lookup = {
    [self.SUCCESS] = "SUCCESS",
    [self.FAILURE] = "FAILURE",
  }
  return string.format("%s: %s", self.NAME or self.field_name, name_lookup[self.value] or string.format("%d", self.value))
end
new_mt.__tostring = new_mt.__index.pretty_print
new_mt.__index.SUCCESS = 0x00
new_mt.__index.FAILURE = 0x01

setmetatable(TlStatus, new_mt)

return TlStatus

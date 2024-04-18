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

--- @class st.zigbee.zcl.clusters.DoorLock.types.ProgramEventCode: st.zigbee.data_types.Uint8
--- @alias ProgramEventCode
---
--- @field public byte_length number 1
--- @field public UNKNOWN_OR_MS number 0
--- @field public MASTER_CODE_CHANGED number 1
--- @field public PIN_CODE_ADDED number 2
--- @field public PIN_CODE_DELETED number 3
--- @field public PIN_CODE_CHANGED number 4
--- @field public RFID_CODE_ADDED number 5
--- @field public RFID_CODE_DELETED number 6
local ProgramEventCode = {}
local new_mt = UintABC.new_mt({NAME = "ProgramEventCode", ID = data_types.name_to_id_map["Uint8"]}, 1)
new_mt.__index.pretty_print = function(self)
  local name_lookup = {
    [self.UNKNOWN_OR_MS]       = "UNKNOWN_OR_MS",
    [self.MASTER_CODE_CHANGED] = "MASTER_CODE_CHANGED",
    [self.PIN_CODE_ADDED]      = "PIN_CODE_ADDED",
    [self.PIN_CODE_DELETED]    = "PIN_CODE_DELETED",
    [self.PIN_CODE_CHANGED]    = "PIN_CODE_CHANGED",
    [self.RFID_CODE_ADDED]     = "RFID_CODE_ADDED",
    [self.RFID_CODE_DELETED]   = "RFID_CODE_DELETED",
  }
  return string.format("%s: %s", self.NAME or self.field_name, name_lookup[self.value] or string.format("%d", self.value))
end
new_mt.__tostring = new_mt.__index.pretty_print
new_mt.__index.UNKNOWN_OR_MS       = 0x00
new_mt.__index.MASTER_CODE_CHANGED = 0x01
new_mt.__index.PIN_CODE_ADDED      = 0x02
new_mt.__index.PIN_CODE_DELETED    = 0x03
new_mt.__index.PIN_CODE_CHANGED    = 0x04
new_mt.__index.RFID_CODE_ADDED     = 0x05
new_mt.__index.RFID_CODE_DELETED   = 0x06

setmetatable(ProgramEventCode, new_mt)

return ProgramEventCode

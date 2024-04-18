local data_types = require "st.zigbee.data_types"
local BitmapABC = require "st.zigbee.data_types.base_defs.BitmapABC"

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

--- @class st.zigbee.zcl.clusters.Commissioning.types.Options: st.zigbee.data_types.Bitmap8
--- @alias Options
---
--- @field public byte_length number 1
--- @field public RESET_CURRENT number 1
--- @field public RESET_ALL number 2
--- @field public ERASE_INDEX number 4
local Options = {}
local new_mt = BitmapABC.new_mt({NAME = "Options", ID = data_types.name_to_id_map["Bitmap8"]}, 1)
new_mt.__index.BASE_MASK     = 0xFF
new_mt.__index.RESET_CURRENT = 0x01
new_mt.__index.RESET_ALL     = 0x02
new_mt.__index.ERASE_INDEX   = 0x04

--- @function Options:is_reset_current_set
--- @return boolean True if the value of RESET_CURRENT is non-zero
new_mt.__index.is_reset_current_set = function(self)
  return (self.value & self.RESET_CURRENT) ~= 0
end
 
--- @function Options:set_reset_current
--- Set the value of the bit in the RESET_CURRENT field to 1
new_mt.__index.set_reset_current = function(self)
  self.value = self.value | self.RESET_CURRENT
end

--- @function Options:unset_reset_current
--- Set the value of the bits in the RESET_CURRENT field to 0
new_mt.__index.unset_reset_current = function(self)
  self.value = self.value & (~self.RESET_CURRENT & self.BASE_MASK)
end

--- @function Options:is_reset_all_set
--- @return boolean True if the value of RESET_ALL is non-zero
new_mt.__index.is_reset_all_set = function(self)
  return (self.value & self.RESET_ALL) ~= 0
end
 
--- @function Options:set_reset_all
--- Set the value of the bit in the RESET_ALL field to 1
new_mt.__index.set_reset_all = function(self)
  self.value = self.value | self.RESET_ALL
end

--- @function Options:unset_reset_all
--- Set the value of the bits in the RESET_ALL field to 0
new_mt.__index.unset_reset_all = function(self)
  self.value = self.value & (~self.RESET_ALL & self.BASE_MASK)
end

--- @function Options:is_erase_index_set
--- @return boolean True if the value of ERASE_INDEX is non-zero
new_mt.__index.is_erase_index_set = function(self)
  return (self.value & self.ERASE_INDEX) ~= 0
end
 
--- @function Options:set_erase_index
--- Set the value of the bit in the ERASE_INDEX field to 1
new_mt.__index.set_erase_index = function(self)
  self.value = self.value | self.ERASE_INDEX
end

--- @function Options:unset_erase_index
--- Set the value of the bits in the ERASE_INDEX field to 0
new_mt.__index.unset_erase_index = function(self)
  self.value = self.value & (~self.ERASE_INDEX & self.BASE_MASK)
end

setmetatable(Options, new_mt)
return Options

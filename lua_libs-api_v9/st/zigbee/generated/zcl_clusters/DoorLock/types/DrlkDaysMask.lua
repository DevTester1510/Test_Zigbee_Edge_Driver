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

--- @class st.zigbee.zcl.clusters.DoorLock.types.DrlkDaysMask: st.zigbee.data_types.Bitmap8
--- @alias DrlkDaysMask
---
--- @field public byte_length number 1
--- @field public SUN number 1
--- @field public MON number 2
--- @field public TUE number 4
--- @field public WED number 8
--- @field public THU number 16
--- @field public FRI number 32
--- @field public SAT number 64
--- @field public ENABLE number 128
local DrlkDaysMask = {}
local new_mt = BitmapABC.new_mt({NAME = "DrlkDaysMask", ID = data_types.name_to_id_map["Bitmap8"]}, 1)
new_mt.__index.BASE_MASK = 0xFF
new_mt.__index.SUN    = 0x01
new_mt.__index.MON    = 0x02
new_mt.__index.TUE    = 0x04
new_mt.__index.WED    = 0x08
new_mt.__index.THU    = 0x10
new_mt.__index.FRI    = 0x20
new_mt.__index.SAT    = 0x40
new_mt.__index.ENABLE = 0x80

--- @function DrlkDaysMask:is_sun_set
--- @return boolean True if the value of SUN is non-zero
new_mt.__index.is_sun_set = function(self)
  return (self.value & self.SUN) ~= 0
end
 
--- @function DrlkDaysMask:set_sun
--- Set the value of the bit in the SUN field to 1
new_mt.__index.set_sun = function(self)
  self.value = self.value | self.SUN
end

--- @function DrlkDaysMask:unset_sun
--- Set the value of the bits in the SUN field to 0
new_mt.__index.unset_sun = function(self)
  self.value = self.value & (~self.SUN & self.BASE_MASK)
end

--- @function DrlkDaysMask:is_mon_set
--- @return boolean True if the value of MON is non-zero
new_mt.__index.is_mon_set = function(self)
  return (self.value & self.MON) ~= 0
end
 
--- @function DrlkDaysMask:set_mon
--- Set the value of the bit in the MON field to 1
new_mt.__index.set_mon = function(self)
  self.value = self.value | self.MON
end

--- @function DrlkDaysMask:unset_mon
--- Set the value of the bits in the MON field to 0
new_mt.__index.unset_mon = function(self)
  self.value = self.value & (~self.MON & self.BASE_MASK)
end

--- @function DrlkDaysMask:is_tue_set
--- @return boolean True if the value of TUE is non-zero
new_mt.__index.is_tue_set = function(self)
  return (self.value & self.TUE) ~= 0
end
 
--- @function DrlkDaysMask:set_tue
--- Set the value of the bit in the TUE field to 1
new_mt.__index.set_tue = function(self)
  self.value = self.value | self.TUE
end

--- @function DrlkDaysMask:unset_tue
--- Set the value of the bits in the TUE field to 0
new_mt.__index.unset_tue = function(self)
  self.value = self.value & (~self.TUE & self.BASE_MASK)
end

--- @function DrlkDaysMask:is_wed_set
--- @return boolean True if the value of WED is non-zero
new_mt.__index.is_wed_set = function(self)
  return (self.value & self.WED) ~= 0
end
 
--- @function DrlkDaysMask:set_wed
--- Set the value of the bit in the WED field to 1
new_mt.__index.set_wed = function(self)
  self.value = self.value | self.WED
end

--- @function DrlkDaysMask:unset_wed
--- Set the value of the bits in the WED field to 0
new_mt.__index.unset_wed = function(self)
  self.value = self.value & (~self.WED & self.BASE_MASK)
end

--- @function DrlkDaysMask:is_thu_set
--- @return boolean True if the value of THU is non-zero
new_mt.__index.is_thu_set = function(self)
  return (self.value & self.THU) ~= 0
end
 
--- @function DrlkDaysMask:set_thu
--- Set the value of the bit in the THU field to 1
new_mt.__index.set_thu = function(self)
  self.value = self.value | self.THU
end

--- @function DrlkDaysMask:unset_thu
--- Set the value of the bits in the THU field to 0
new_mt.__index.unset_thu = function(self)
  self.value = self.value & (~self.THU & self.BASE_MASK)
end

--- @function DrlkDaysMask:is_fri_set
--- @return boolean True if the value of FRI is non-zero
new_mt.__index.is_fri_set = function(self)
  return (self.value & self.FRI) ~= 0
end
 
--- @function DrlkDaysMask:set_fri
--- Set the value of the bit in the FRI field to 1
new_mt.__index.set_fri = function(self)
  self.value = self.value | self.FRI
end

--- @function DrlkDaysMask:unset_fri
--- Set the value of the bits in the FRI field to 0
new_mt.__index.unset_fri = function(self)
  self.value = self.value & (~self.FRI & self.BASE_MASK)
end

--- @function DrlkDaysMask:is_sat_set
--- @return boolean True if the value of SAT is non-zero
new_mt.__index.is_sat_set = function(self)
  return (self.value & self.SAT) ~= 0
end
 
--- @function DrlkDaysMask:set_sat
--- Set the value of the bit in the SAT field to 1
new_mt.__index.set_sat = function(self)
  self.value = self.value | self.SAT
end

--- @function DrlkDaysMask:unset_sat
--- Set the value of the bits in the SAT field to 0
new_mt.__index.unset_sat = function(self)
  self.value = self.value & (~self.SAT & self.BASE_MASK)
end

--- @function DrlkDaysMask:is_enable_set
--- @return boolean True if the value of ENABLE is non-zero
new_mt.__index.is_enable_set = function(self)
  return (self.value & self.ENABLE) ~= 0
end
 
--- @function DrlkDaysMask:set_enable
--- Set the value of the bit in the ENABLE field to 1
new_mt.__index.set_enable = function(self)
  self.value = self.value | self.ENABLE
end

--- @function DrlkDaysMask:unset_enable
--- Set the value of the bits in the ENABLE field to 0
new_mt.__index.unset_enable = function(self)
  self.value = self.value & (~self.ENABLE & self.BASE_MASK)
end

setmetatable(DrlkDaysMask, new_mt)
return DrlkDaysMask
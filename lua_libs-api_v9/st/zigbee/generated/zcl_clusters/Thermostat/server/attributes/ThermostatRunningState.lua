local cluster_base = require "st.zigbee.cluster_base"
local data_types = require "st.zigbee.data_types"

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

--- @class st.zigbee.zcl.clusters.Thermostat.ThermostatRunningState
--- @alias ThermostatRunningState
---
--- @field public ID number 0x0029 the ID of this attribute
--- @field public NAME string "ThermostatRunningState" the name of this attribute
--- @field public data_type st.zigbee.data_types.Bitmap16 the data type of this attribute
--- @field public HEAT_ON number 1
--- @field public COOL_ON number 2
--- @field public FAN_ON number 4
--- @field public HEAT_SECOND_STAGE_ON number 8
--- @field public COOL_SECOND_STAGE_ON number 16
--- @field public FAN_SECOND_STAGE_ON number 32
--- @field public FAN_THIRD_STAGE_ON number 64
local ThermostatRunningState = {
  ID = 0x0029,
  NAME = "ThermostatRunningState",
  base_type = data_types.Bitmap16,
}

ThermostatRunningState.BASE_MASK            = 0xFFFF
ThermostatRunningState.HEAT_ON              = 0x0001
ThermostatRunningState.COOL_ON              = 0x0002
ThermostatRunningState.FAN_ON               = 0x0004
ThermostatRunningState.HEAT_SECOND_STAGE_ON = 0x0008
ThermostatRunningState.COOL_SECOND_STAGE_ON = 0x0010
ThermostatRunningState.FAN_SECOND_STAGE_ON  = 0x0020
ThermostatRunningState.FAN_THIRD_STAGE_ON   = 0x0040


ThermostatRunningState.mask_fields = {
  BASE_MASK = 0xFFFF,
  HEAT_ON = 0x0001,
  COOL_ON = 0x0002,
  FAN_ON = 0x0004,
  HEAT_SECOND_STAGE_ON = 0x0008,
  COOL_SECOND_STAGE_ON = 0x0010,
  FAN_SECOND_STAGE_ON = 0x0020,
  FAN_THIRD_STAGE_ON = 0x0040,
}


--- @function ThermostatRunningState:is_heat_on_set
--- @return boolean True if the value of HEAT_ON is non-zero
ThermostatRunningState.is_heat_on_set = function(self)
  return (self.value & self.HEAT_ON) ~= 0
end
 
--- @function ThermostatRunningState:set_heat_on
--- Set the value of the bit in the HEAT_ON field to 1
ThermostatRunningState.set_heat_on = function(self)
  self.value = self.value | self.HEAT_ON
end

--- @function ThermostatRunningState:unset_heat_on
--- Set the value of the bits in the HEAT_ON field to 0
ThermostatRunningState.unset_heat_on = function(self)
  self.value = self.value & (~self.HEAT_ON & self.BASE_MASK)
end

--- @function ThermostatRunningState:is_cool_on_set
--- @return boolean True if the value of COOL_ON is non-zero
ThermostatRunningState.is_cool_on_set = function(self)
  return (self.value & self.COOL_ON) ~= 0
end
 
--- @function ThermostatRunningState:set_cool_on
--- Set the value of the bit in the COOL_ON field to 1
ThermostatRunningState.set_cool_on = function(self)
  self.value = self.value | self.COOL_ON
end

--- @function ThermostatRunningState:unset_cool_on
--- Set the value of the bits in the COOL_ON field to 0
ThermostatRunningState.unset_cool_on = function(self)
  self.value = self.value & (~self.COOL_ON & self.BASE_MASK)
end

--- @function ThermostatRunningState:is_fan_on_set
--- @return boolean True if the value of FAN_ON is non-zero
ThermostatRunningState.is_fan_on_set = function(self)
  return (self.value & self.FAN_ON) ~= 0
end
 
--- @function ThermostatRunningState:set_fan_on
--- Set the value of the bit in the FAN_ON field to 1
ThermostatRunningState.set_fan_on = function(self)
  self.value = self.value | self.FAN_ON
end

--- @function ThermostatRunningState:unset_fan_on
--- Set the value of the bits in the FAN_ON field to 0
ThermostatRunningState.unset_fan_on = function(self)
  self.value = self.value & (~self.FAN_ON & self.BASE_MASK)
end

--- @function ThermostatRunningState:is_heat_second_stage_on_set
--- @return boolean True if the value of HEAT_SECOND_STAGE_ON is non-zero
ThermostatRunningState.is_heat_second_stage_on_set = function(self)
  return (self.value & self.HEAT_SECOND_STAGE_ON) ~= 0
end
 
--- @function ThermostatRunningState:set_heat_second_stage_on
--- Set the value of the bit in the HEAT_SECOND_STAGE_ON field to 1
ThermostatRunningState.set_heat_second_stage_on = function(self)
  self.value = self.value | self.HEAT_SECOND_STAGE_ON
end

--- @function ThermostatRunningState:unset_heat_second_stage_on
--- Set the value of the bits in the HEAT_SECOND_STAGE_ON field to 0
ThermostatRunningState.unset_heat_second_stage_on = function(self)
  self.value = self.value & (~self.HEAT_SECOND_STAGE_ON & self.BASE_MASK)
end

--- @function ThermostatRunningState:is_cool_second_stage_on_set
--- @return boolean True if the value of COOL_SECOND_STAGE_ON is non-zero
ThermostatRunningState.is_cool_second_stage_on_set = function(self)
  return (self.value & self.COOL_SECOND_STAGE_ON) ~= 0
end
 
--- @function ThermostatRunningState:set_cool_second_stage_on
--- Set the value of the bit in the COOL_SECOND_STAGE_ON field to 1
ThermostatRunningState.set_cool_second_stage_on = function(self)
  self.value = self.value | self.COOL_SECOND_STAGE_ON
end

--- @function ThermostatRunningState:unset_cool_second_stage_on
--- Set the value of the bits in the COOL_SECOND_STAGE_ON field to 0
ThermostatRunningState.unset_cool_second_stage_on = function(self)
  self.value = self.value & (~self.COOL_SECOND_STAGE_ON & self.BASE_MASK)
end

--- @function ThermostatRunningState:is_fan_second_stage_on_set
--- @return boolean True if the value of FAN_SECOND_STAGE_ON is non-zero
ThermostatRunningState.is_fan_second_stage_on_set = function(self)
  return (self.value & self.FAN_SECOND_STAGE_ON) ~= 0
end
 
--- @function ThermostatRunningState:set_fan_second_stage_on
--- Set the value of the bit in the FAN_SECOND_STAGE_ON field to 1
ThermostatRunningState.set_fan_second_stage_on = function(self)
  self.value = self.value | self.FAN_SECOND_STAGE_ON
end

--- @function ThermostatRunningState:unset_fan_second_stage_on
--- Set the value of the bits in the FAN_SECOND_STAGE_ON field to 0
ThermostatRunningState.unset_fan_second_stage_on = function(self)
  self.value = self.value & (~self.FAN_SECOND_STAGE_ON & self.BASE_MASK)
end

--- @function ThermostatRunningState:is_fan_third_stage_on_set
--- @return boolean True if the value of FAN_THIRD_STAGE_ON is non-zero
ThermostatRunningState.is_fan_third_stage_on_set = function(self)
  return (self.value & self.FAN_THIRD_STAGE_ON) ~= 0
end
 
--- @function ThermostatRunningState:set_fan_third_stage_on
--- Set the value of the bit in the FAN_THIRD_STAGE_ON field to 1
ThermostatRunningState.set_fan_third_stage_on = function(self)
  self.value = self.value | self.FAN_THIRD_STAGE_ON
end

--- @function ThermostatRunningState:unset_fan_third_stage_on
--- Set the value of the bits in the FAN_THIRD_STAGE_ON field to 0
ThermostatRunningState.unset_fan_third_stage_on = function(self)
  self.value = self.value & (~self.FAN_THIRD_STAGE_ON & self.BASE_MASK)
end


ThermostatRunningState.mask_methods = {
  is_heat_on_set = ThermostatRunningState.is_heat_on_set,
  set_heat_on = ThermostatRunningState.set_heat_on,
  unset_heat_on = ThermostatRunningState.unset_heat_on,
  is_cool_on_set = ThermostatRunningState.is_cool_on_set,
  set_cool_on = ThermostatRunningState.set_cool_on,
  unset_cool_on = ThermostatRunningState.unset_cool_on,
  is_fan_on_set = ThermostatRunningState.is_fan_on_set,
  set_fan_on = ThermostatRunningState.set_fan_on,
  unset_fan_on = ThermostatRunningState.unset_fan_on,
  is_heat_second_stage_on_set = ThermostatRunningState.is_heat_second_stage_on_set,
  set_heat_second_stage_on = ThermostatRunningState.set_heat_second_stage_on,
  unset_heat_second_stage_on = ThermostatRunningState.unset_heat_second_stage_on,
  is_cool_second_stage_on_set = ThermostatRunningState.is_cool_second_stage_on_set,
  set_cool_second_stage_on = ThermostatRunningState.set_cool_second_stage_on,
  unset_cool_second_stage_on = ThermostatRunningState.unset_cool_second_stage_on,
  is_fan_second_stage_on_set = ThermostatRunningState.is_fan_second_stage_on_set,
  set_fan_second_stage_on = ThermostatRunningState.set_fan_second_stage_on,
  unset_fan_second_stage_on = ThermostatRunningState.unset_fan_second_stage_on,
  is_fan_third_stage_on_set = ThermostatRunningState.is_fan_third_stage_on_set,
  set_fan_third_stage_on = ThermostatRunningState.set_fan_third_stage_on,
  unset_fan_third_stage_on = ThermostatRunningState.unset_fan_third_stage_on,
}

--- Add additional functionality to the base type object
---
--- @param base_type_obj st.zigbee.data_types.Bitmap16 the base data type object to add functionality to
function ThermostatRunningState:augment_type(base_type_obj)
  cluster_base.attribute_augment_type_bitmap(self, base_type_obj)
end

function ThermostatRunningState.pretty_print(value_obj)
  local zb_utils = require "st.zigbee.utils"
  local pattern = ">I" .. value_obj.byte_length
  return string.format("%s: %s[0x%s]", value_obj.field_name or value_obj.NAME, ThermostatRunningState.NAME, zb_utils.pretty_print_hex_str(string.pack(pattern, value_obj.value)))
end

--- @function ThermostatRunningState:build_test_attr_report
---
--- Build a Rx Zigbee message as if a device reported this attribute
--- @param device st.zigbee.Device
--- @param data st.zigbee.data_types.Bitmap16 the attribute value
--- @return st.zigbee.ZigbeeMessageRx containing an AttributeReport body
ThermostatRunningState.build_test_attr_report = cluster_base.build_test_attr_report

--- @function ThermostatRunningState:build_test_read_attr_response
---
--- Build a Rx Zigbee message as if a device sent a read response for this attribute
--- @param device st.zigbee.Device
--- @param data st.zigbee.data_types.Bitmap16 the attribute value
--- @return st.zigbee.ZigbeeMessageRx containing an ReadAttributeResponse body
ThermostatRunningState.build_test_read_attr_response = cluster_base.build_test_read_attr_response

--- Create a Bitmap16 object of this attribute with any additional features provided for the attribute
---
--- This is also usable with the ThermostatRunningState(...) syntax
---
--- @vararg vararg the values needed to construct a Bitmap16
--- @return st.zigbee.data_types.Bitmap16
function ThermostatRunningState:new_value(...)
    local o = self.base_type(table.unpack({...}))
    self:augment_type(o)
    return o
end

--- Construct a st.zigbee.ZigbeeMessageTx to read this attribute from a device
---
--- @param device st.zigbee.Device
--- @return st.zigbee.ZigbeeMessageTx containing a ReadAttribute body
function ThermostatRunningState:read(device)
    return cluster_base.read_attribute(device, data_types.ClusterId(self._cluster.ID), data_types.AttributeId(self.ID))
end

--- Construct a st.zigbee.ZigbeeMessageTx to configure this attribute for reporting on a device
---
--- @param device st.zigbee.Device
--- @param min_rep_int number|st.zigbee.data_types.Uint16 the minimum interval allowed between reports of this attribute
--- @param max_rep_int number|st.zigbee.data_types.Uint16 the maximum interval allowed between reports of this attribute
--- @return st.zigbee.ZigbeeMessageTx containing a ConfigureReporting body
function ThermostatRunningState:configure_reporting(device, min_rep_int, max_rep_int)
  local min = data_types.validate_or_build_type(min_rep_int, data_types.Uint16, "minimum_reporting_interval")
  local max = data_types.validate_or_build_type(max_rep_int, data_types.Uint16, "maximum_reporting_interval")
  local rep_change = nil
  return cluster_base.configure_reporting(device, data_types.ClusterId(self._cluster.ID), data_types.AttributeId(self.ID), data_types.ZigbeeDataType(self.base_type.ID), min, max, rep_change)
end

function ThermostatRunningState:set_parent_cluster(cluster)
  self._cluster = cluster
  return self
end

setmetatable(ThermostatRunningState, {__call = ThermostatRunningState.new_value})
return ThermostatRunningState

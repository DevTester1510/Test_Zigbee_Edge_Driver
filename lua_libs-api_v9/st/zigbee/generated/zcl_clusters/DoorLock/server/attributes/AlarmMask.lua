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

--- @class st.zigbee.zcl.clusters.DoorLock.AlarmMask
--- @alias AlarmMask
---
--- @field public ID number 0x0040 the ID of this attribute
--- @field public NAME string "AlarmMask" the name of this attribute
--- @field public data_type st.zigbee.data_types.Bitmap16 the data type of this attribute
--- @field public DEADBOLT_JAMMED number 1
--- @field public LOCK_RESET_TO_FACTORY_DEFAULTS number 2
--- @field public RF_POWER_MODULE_CYCLED number 8
--- @field public TAMPER_ALARM_WRONG_CODE_ENTRY_LIMIT number 16
--- @field public TAMPER_ALARM_FRONT_ESCUTCHEON_REMOVED_FROM_MAIN number 32
--- @field public FORCED_DOOR_OPEN_UNDER_DOOR_LOCKED_CONDITION number 64
local AlarmMask = {
  ID = 0x0040,
  NAME = "AlarmMask",
  base_type = data_types.Bitmap16,
}

AlarmMask.BASE_MASK                                       = 0xFFFF
AlarmMask.DEADBOLT_JAMMED                                 = 0x0001
AlarmMask.LOCK_RESET_TO_FACTORY_DEFAULTS                  = 0x0002
AlarmMask.RF_POWER_MODULE_CYCLED                          = 0x0008
AlarmMask.TAMPER_ALARM_WRONG_CODE_ENTRY_LIMIT             = 0x0010
AlarmMask.TAMPER_ALARM_FRONT_ESCUTCHEON_REMOVED_FROM_MAIN = 0x0020
AlarmMask.FORCED_DOOR_OPEN_UNDER_DOOR_LOCKED_CONDITION    = 0x0040


AlarmMask.mask_fields = {
  BASE_MASK = 0xFFFF,
  DEADBOLT_JAMMED = 0x0001,
  LOCK_RESET_TO_FACTORY_DEFAULTS = 0x0002,
  RF_POWER_MODULE_CYCLED = 0x0008,
  TAMPER_ALARM_WRONG_CODE_ENTRY_LIMIT = 0x0010,
  TAMPER_ALARM_FRONT_ESCUTCHEON_REMOVED_FROM_MAIN = 0x0020,
  FORCED_DOOR_OPEN_UNDER_DOOR_LOCKED_CONDITION = 0x0040,
}


--- @function AlarmMask:is_deadbolt_jammed_set
--- @return boolean True if the value of DEADBOLT_JAMMED is non-zero
AlarmMask.is_deadbolt_jammed_set = function(self)
  return (self.value & self.DEADBOLT_JAMMED) ~= 0
end
 
--- @function AlarmMask:set_deadbolt_jammed
--- Set the value of the bit in the DEADBOLT_JAMMED field to 1
AlarmMask.set_deadbolt_jammed = function(self)
  self.value = self.value | self.DEADBOLT_JAMMED
end

--- @function AlarmMask:unset_deadbolt_jammed
--- Set the value of the bits in the DEADBOLT_JAMMED field to 0
AlarmMask.unset_deadbolt_jammed = function(self)
  self.value = self.value & (~self.DEADBOLT_JAMMED & self.BASE_MASK)
end

--- @function AlarmMask:is_lock_reset_to_factory_defaults_set
--- @return boolean True if the value of LOCK_RESET_TO_FACTORY_DEFAULTS is non-zero
AlarmMask.is_lock_reset_to_factory_defaults_set = function(self)
  return (self.value & self.LOCK_RESET_TO_FACTORY_DEFAULTS) ~= 0
end
 
--- @function AlarmMask:set_lock_reset_to_factory_defaults
--- Set the value of the bit in the LOCK_RESET_TO_FACTORY_DEFAULTS field to 1
AlarmMask.set_lock_reset_to_factory_defaults = function(self)
  self.value = self.value | self.LOCK_RESET_TO_FACTORY_DEFAULTS
end

--- @function AlarmMask:unset_lock_reset_to_factory_defaults
--- Set the value of the bits in the LOCK_RESET_TO_FACTORY_DEFAULTS field to 0
AlarmMask.unset_lock_reset_to_factory_defaults = function(self)
  self.value = self.value & (~self.LOCK_RESET_TO_FACTORY_DEFAULTS & self.BASE_MASK)
end

--- @function AlarmMask:is_rf_power_module_cycled_set
--- @return boolean True if the value of RF_POWER_MODULE_CYCLED is non-zero
AlarmMask.is_rf_power_module_cycled_set = function(self)
  return (self.value & self.RF_POWER_MODULE_CYCLED) ~= 0
end
 
--- @function AlarmMask:set_rf_power_module_cycled
--- Set the value of the bit in the RF_POWER_MODULE_CYCLED field to 1
AlarmMask.set_rf_power_module_cycled = function(self)
  self.value = self.value | self.RF_POWER_MODULE_CYCLED
end

--- @function AlarmMask:unset_rf_power_module_cycled
--- Set the value of the bits in the RF_POWER_MODULE_CYCLED field to 0
AlarmMask.unset_rf_power_module_cycled = function(self)
  self.value = self.value & (~self.RF_POWER_MODULE_CYCLED & self.BASE_MASK)
end

--- @function AlarmMask:is_tamper_alarm_wrong_code_entry_limit_set
--- @return boolean True if the value of TAMPER_ALARM_WRONG_CODE_ENTRY_LIMIT is non-zero
AlarmMask.is_tamper_alarm_wrong_code_entry_limit_set = function(self)
  return (self.value & self.TAMPER_ALARM_WRONG_CODE_ENTRY_LIMIT) ~= 0
end
 
--- @function AlarmMask:set_tamper_alarm_wrong_code_entry_limit
--- Set the value of the bit in the TAMPER_ALARM_WRONG_CODE_ENTRY_LIMIT field to 1
AlarmMask.set_tamper_alarm_wrong_code_entry_limit = function(self)
  self.value = self.value | self.TAMPER_ALARM_WRONG_CODE_ENTRY_LIMIT
end

--- @function AlarmMask:unset_tamper_alarm_wrong_code_entry_limit
--- Set the value of the bits in the TAMPER_ALARM_WRONG_CODE_ENTRY_LIMIT field to 0
AlarmMask.unset_tamper_alarm_wrong_code_entry_limit = function(self)
  self.value = self.value & (~self.TAMPER_ALARM_WRONG_CODE_ENTRY_LIMIT & self.BASE_MASK)
end

--- @function AlarmMask:is_tamper_alarm_front_escutcheon_removed_from_main_set
--- @return boolean True if the value of TAMPER_ALARM_FRONT_ESCUTCHEON_REMOVED_FROM_MAIN is non-zero
AlarmMask.is_tamper_alarm_front_escutcheon_removed_from_main_set = function(self)
  return (self.value & self.TAMPER_ALARM_FRONT_ESCUTCHEON_REMOVED_FROM_MAIN) ~= 0
end
 
--- @function AlarmMask:set_tamper_alarm_front_escutcheon_removed_from_main
--- Set the value of the bit in the TAMPER_ALARM_FRONT_ESCUTCHEON_REMOVED_FROM_MAIN field to 1
AlarmMask.set_tamper_alarm_front_escutcheon_removed_from_main = function(self)
  self.value = self.value | self.TAMPER_ALARM_FRONT_ESCUTCHEON_REMOVED_FROM_MAIN
end

--- @function AlarmMask:unset_tamper_alarm_front_escutcheon_removed_from_main
--- Set the value of the bits in the TAMPER_ALARM_FRONT_ESCUTCHEON_REMOVED_FROM_MAIN field to 0
AlarmMask.unset_tamper_alarm_front_escutcheon_removed_from_main = function(self)
  self.value = self.value & (~self.TAMPER_ALARM_FRONT_ESCUTCHEON_REMOVED_FROM_MAIN & self.BASE_MASK)
end

--- @function AlarmMask:is_forced_door_open_under_door_locked_condition_set
--- @return boolean True if the value of FORCED_DOOR_OPEN_UNDER_DOOR_LOCKED_CONDITION is non-zero
AlarmMask.is_forced_door_open_under_door_locked_condition_set = function(self)
  return (self.value & self.FORCED_DOOR_OPEN_UNDER_DOOR_LOCKED_CONDITION) ~= 0
end
 
--- @function AlarmMask:set_forced_door_open_under_door_locked_condition
--- Set the value of the bit in the FORCED_DOOR_OPEN_UNDER_DOOR_LOCKED_CONDITION field to 1
AlarmMask.set_forced_door_open_under_door_locked_condition = function(self)
  self.value = self.value | self.FORCED_DOOR_OPEN_UNDER_DOOR_LOCKED_CONDITION
end

--- @function AlarmMask:unset_forced_door_open_under_door_locked_condition
--- Set the value of the bits in the FORCED_DOOR_OPEN_UNDER_DOOR_LOCKED_CONDITION field to 0
AlarmMask.unset_forced_door_open_under_door_locked_condition = function(self)
  self.value = self.value & (~self.FORCED_DOOR_OPEN_UNDER_DOOR_LOCKED_CONDITION & self.BASE_MASK)
end


AlarmMask.mask_methods = {
  is_deadbolt_jammed_set = AlarmMask.is_deadbolt_jammed_set,
  set_deadbolt_jammed = AlarmMask.set_deadbolt_jammed,
  unset_deadbolt_jammed = AlarmMask.unset_deadbolt_jammed,
  is_lock_reset_to_factory_defaults_set = AlarmMask.is_lock_reset_to_factory_defaults_set,
  set_lock_reset_to_factory_defaults = AlarmMask.set_lock_reset_to_factory_defaults,
  unset_lock_reset_to_factory_defaults = AlarmMask.unset_lock_reset_to_factory_defaults,
  is_rf_power_module_cycled_set = AlarmMask.is_rf_power_module_cycled_set,
  set_rf_power_module_cycled = AlarmMask.set_rf_power_module_cycled,
  unset_rf_power_module_cycled = AlarmMask.unset_rf_power_module_cycled,
  is_tamper_alarm_wrong_code_entry_limit_set = AlarmMask.is_tamper_alarm_wrong_code_entry_limit_set,
  set_tamper_alarm_wrong_code_entry_limit = AlarmMask.set_tamper_alarm_wrong_code_entry_limit,
  unset_tamper_alarm_wrong_code_entry_limit = AlarmMask.unset_tamper_alarm_wrong_code_entry_limit,
  is_tamper_alarm_front_escutcheon_removed_from_main_set = AlarmMask.is_tamper_alarm_front_escutcheon_removed_from_main_set,
  set_tamper_alarm_front_escutcheon_removed_from_main = AlarmMask.set_tamper_alarm_front_escutcheon_removed_from_main,
  unset_tamper_alarm_front_escutcheon_removed_from_main = AlarmMask.unset_tamper_alarm_front_escutcheon_removed_from_main,
  is_forced_door_open_under_door_locked_condition_set = AlarmMask.is_forced_door_open_under_door_locked_condition_set,
  set_forced_door_open_under_door_locked_condition = AlarmMask.set_forced_door_open_under_door_locked_condition,
  unset_forced_door_open_under_door_locked_condition = AlarmMask.unset_forced_door_open_under_door_locked_condition,
}

--- Add additional functionality to the base type object
---
--- @param base_type_obj st.zigbee.data_types.Bitmap16 the base data type object to add functionality to
function AlarmMask:augment_type(base_type_obj)
  cluster_base.attribute_augment_type_bitmap(self, base_type_obj)
end

function AlarmMask.pretty_print(value_obj)
  local zb_utils = require "st.zigbee.utils"
  local pattern = ">I" .. value_obj.byte_length
  return string.format("%s: %s[0x%s]", value_obj.field_name or value_obj.NAME, AlarmMask.NAME, zb_utils.pretty_print_hex_str(string.pack(pattern, value_obj.value)))
end

--- @function AlarmMask:build_test_attr_report
---
--- Build a Rx Zigbee message as if a device reported this attribute
--- @param device st.zigbee.Device
--- @param data st.zigbee.data_types.Bitmap16 the attribute value
--- @return st.zigbee.ZigbeeMessageRx containing an AttributeReport body
AlarmMask.build_test_attr_report = cluster_base.build_test_attr_report

--- @function AlarmMask:build_test_read_attr_response
---
--- Build a Rx Zigbee message as if a device sent a read response for this attribute
--- @param device st.zigbee.Device
--- @param data st.zigbee.data_types.Bitmap16 the attribute value
--- @return st.zigbee.ZigbeeMessageRx containing an ReadAttributeResponse body
AlarmMask.build_test_read_attr_response = cluster_base.build_test_read_attr_response

--- Create a Bitmap16 object of this attribute with any additional features provided for the attribute
---
--- This is also usable with the AlarmMask(...) syntax
---
--- @vararg vararg the values needed to construct a Bitmap16
--- @return st.zigbee.data_types.Bitmap16
function AlarmMask:new_value(...)
    local o = self.base_type(table.unpack({...}))
    self:augment_type(o)
    return o
end

--- Construct a st.zigbee.ZigbeeMessageTx to read this attribute from a device
---
--- @param device st.zigbee.Device
--- @return st.zigbee.ZigbeeMessageTx containing a ReadAttribute body
function AlarmMask:read(device)
    return cluster_base.read_attribute(device, data_types.ClusterId(self._cluster.ID), data_types.AttributeId(self.ID))
end

--- Construct a st.zigbee.ZigbeeMessageTx to configure this attribute for reporting on a device
---
--- @param device st.zigbee.Device
--- @param min_rep_int number|st.zigbee.data_types.Uint16 the minimum interval allowed between reports of this attribute
--- @param max_rep_int number|st.zigbee.data_types.Uint16 the maximum interval allowed between reports of this attribute
--- @return st.zigbee.ZigbeeMessageTx containing a ConfigureReporting body
function AlarmMask:configure_reporting(device, min_rep_int, max_rep_int)
  local min = data_types.validate_or_build_type(min_rep_int, data_types.Uint16, "minimum_reporting_interval")
  local max = data_types.validate_or_build_type(max_rep_int, data_types.Uint16, "maximum_reporting_interval")
  local rep_change = nil
  return cluster_base.configure_reporting(device, data_types.ClusterId(self._cluster.ID), data_types.AttributeId(self.ID), data_types.ZigbeeDataType(self.base_type.ID), min, max, rep_change)
end

--- Write a value to this attribute on a device
---
--- @param device st.zigbee.Device
--- @param value st.zigbee.data_types.Bitmap16 the value to write
function AlarmMask:write(device, value)
  return cluster_base.attribute_write(self, device, value)
end

function AlarmMask:set_parent_cluster(cluster)
  self._cluster = cluster
  return self
end

setmetatable(AlarmMask, {__call = AlarmMask.new_value})
return AlarmMask

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

--- @class st.zigbee.zcl.clusters.DoorLock.KeypadOperationEventMask
--- @alias KeypadOperationEventMask
---
--- @field public ID number 0x0041 the ID of this attribute
--- @field public NAME string "KeypadOperationEventMask" the name of this attribute
--- @field public data_type st.zigbee.data_types.Bitmap16 the data type of this attribute
--- @field public KEYPAD_OP_UNKNOWN_OR_MS number 1
--- @field public KEYPAD_OP_LOCK number 2
--- @field public KEYPAD_OP_UNLOCK number 4
--- @field public KEYPAD_OP_LOCK_ERROR_INVALID_PIN number 8
--- @field public KEYPAD_OP_LOCK_ERROR_INVALID_SCHEDULE number 16
--- @field public KEYPAD_OP_UNLOCK_INVALID_PIN number 32
--- @field public KEYPAD_OP_UNLOCK_INVALID_SCHEDULE number 64
--- @field public KEYPAD_OP_NON_ACCESS_USER number 128
local KeypadOperationEventMask = {
  ID = 0x0041,
  NAME = "KeypadOperationEventMask",
  base_type = data_types.Bitmap16,
}

KeypadOperationEventMask.BASE_MASK                             = 0xFFFF
KeypadOperationEventMask.KEYPAD_OP_UNKNOWN_OR_MS               = 0x0001
KeypadOperationEventMask.KEYPAD_OP_LOCK                        = 0x0002
KeypadOperationEventMask.KEYPAD_OP_UNLOCK                      = 0x0004
KeypadOperationEventMask.KEYPAD_OP_LOCK_ERROR_INVALID_PIN      = 0x0008
KeypadOperationEventMask.KEYPAD_OP_LOCK_ERROR_INVALID_SCHEDULE = 0x0010
KeypadOperationEventMask.KEYPAD_OP_UNLOCK_INVALID_PIN          = 0x0020
KeypadOperationEventMask.KEYPAD_OP_UNLOCK_INVALID_SCHEDULE     = 0x0040
KeypadOperationEventMask.KEYPAD_OP_NON_ACCESS_USER             = 0x0080


KeypadOperationEventMask.mask_fields = {
  BASE_MASK = 0xFFFF,
  KEYPAD_OP_UNKNOWN_OR_MS = 0x0001,
  KEYPAD_OP_LOCK = 0x0002,
  KEYPAD_OP_UNLOCK = 0x0004,
  KEYPAD_OP_LOCK_ERROR_INVALID_PIN = 0x0008,
  KEYPAD_OP_LOCK_ERROR_INVALID_SCHEDULE = 0x0010,
  KEYPAD_OP_UNLOCK_INVALID_PIN = 0x0020,
  KEYPAD_OP_UNLOCK_INVALID_SCHEDULE = 0x0040,
  KEYPAD_OP_NON_ACCESS_USER = 0x0080,
}


--- @function KeypadOperationEventMask:is_keypad_op_unknown_or_ms_set
--- @return boolean True if the value of KEYPAD_OP_UNKNOWN_OR_MS is non-zero
KeypadOperationEventMask.is_keypad_op_unknown_or_ms_set = function(self)
  return (self.value & self.KEYPAD_OP_UNKNOWN_OR_MS) ~= 0
end
 
--- @function KeypadOperationEventMask:set_keypad_op_unknown_or_ms
--- Set the value of the bit in the KEYPAD_OP_UNKNOWN_OR_MS field to 1
KeypadOperationEventMask.set_keypad_op_unknown_or_ms = function(self)
  self.value = self.value | self.KEYPAD_OP_UNKNOWN_OR_MS
end

--- @function KeypadOperationEventMask:unset_keypad_op_unknown_or_ms
--- Set the value of the bits in the KEYPAD_OP_UNKNOWN_OR_MS field to 0
KeypadOperationEventMask.unset_keypad_op_unknown_or_ms = function(self)
  self.value = self.value & (~self.KEYPAD_OP_UNKNOWN_OR_MS & self.BASE_MASK)
end

--- @function KeypadOperationEventMask:is_keypad_op_lock_set
--- @return boolean True if the value of KEYPAD_OP_LOCK is non-zero
KeypadOperationEventMask.is_keypad_op_lock_set = function(self)
  return (self.value & self.KEYPAD_OP_LOCK) ~= 0
end
 
--- @function KeypadOperationEventMask:set_keypad_op_lock
--- Set the value of the bit in the KEYPAD_OP_LOCK field to 1
KeypadOperationEventMask.set_keypad_op_lock = function(self)
  self.value = self.value | self.KEYPAD_OP_LOCK
end

--- @function KeypadOperationEventMask:unset_keypad_op_lock
--- Set the value of the bits in the KEYPAD_OP_LOCK field to 0
KeypadOperationEventMask.unset_keypad_op_lock = function(self)
  self.value = self.value & (~self.KEYPAD_OP_LOCK & self.BASE_MASK)
end

--- @function KeypadOperationEventMask:is_keypad_op_unlock_set
--- @return boolean True if the value of KEYPAD_OP_UNLOCK is non-zero
KeypadOperationEventMask.is_keypad_op_unlock_set = function(self)
  return (self.value & self.KEYPAD_OP_UNLOCK) ~= 0
end
 
--- @function KeypadOperationEventMask:set_keypad_op_unlock
--- Set the value of the bit in the KEYPAD_OP_UNLOCK field to 1
KeypadOperationEventMask.set_keypad_op_unlock = function(self)
  self.value = self.value | self.KEYPAD_OP_UNLOCK
end

--- @function KeypadOperationEventMask:unset_keypad_op_unlock
--- Set the value of the bits in the KEYPAD_OP_UNLOCK field to 0
KeypadOperationEventMask.unset_keypad_op_unlock = function(self)
  self.value = self.value & (~self.KEYPAD_OP_UNLOCK & self.BASE_MASK)
end

--- @function KeypadOperationEventMask:is_keypad_op_lock_error_invalid_pin_set
--- @return boolean True if the value of KEYPAD_OP_LOCK_ERROR_INVALID_PIN is non-zero
KeypadOperationEventMask.is_keypad_op_lock_error_invalid_pin_set = function(self)
  return (self.value & self.KEYPAD_OP_LOCK_ERROR_INVALID_PIN) ~= 0
end
 
--- @function KeypadOperationEventMask:set_keypad_op_lock_error_invalid_pin
--- Set the value of the bit in the KEYPAD_OP_LOCK_ERROR_INVALID_PIN field to 1
KeypadOperationEventMask.set_keypad_op_lock_error_invalid_pin = function(self)
  self.value = self.value | self.KEYPAD_OP_LOCK_ERROR_INVALID_PIN
end

--- @function KeypadOperationEventMask:unset_keypad_op_lock_error_invalid_pin
--- Set the value of the bits in the KEYPAD_OP_LOCK_ERROR_INVALID_PIN field to 0
KeypadOperationEventMask.unset_keypad_op_lock_error_invalid_pin = function(self)
  self.value = self.value & (~self.KEYPAD_OP_LOCK_ERROR_INVALID_PIN & self.BASE_MASK)
end

--- @function KeypadOperationEventMask:is_keypad_op_lock_error_invalid_schedule_set
--- @return boolean True if the value of KEYPAD_OP_LOCK_ERROR_INVALID_SCHEDULE is non-zero
KeypadOperationEventMask.is_keypad_op_lock_error_invalid_schedule_set = function(self)
  return (self.value & self.KEYPAD_OP_LOCK_ERROR_INVALID_SCHEDULE) ~= 0
end
 
--- @function KeypadOperationEventMask:set_keypad_op_lock_error_invalid_schedule
--- Set the value of the bit in the KEYPAD_OP_LOCK_ERROR_INVALID_SCHEDULE field to 1
KeypadOperationEventMask.set_keypad_op_lock_error_invalid_schedule = function(self)
  self.value = self.value | self.KEYPAD_OP_LOCK_ERROR_INVALID_SCHEDULE
end

--- @function KeypadOperationEventMask:unset_keypad_op_lock_error_invalid_schedule
--- Set the value of the bits in the KEYPAD_OP_LOCK_ERROR_INVALID_SCHEDULE field to 0
KeypadOperationEventMask.unset_keypad_op_lock_error_invalid_schedule = function(self)
  self.value = self.value & (~self.KEYPAD_OP_LOCK_ERROR_INVALID_SCHEDULE & self.BASE_MASK)
end

--- @function KeypadOperationEventMask:is_keypad_op_unlock_invalid_pin_set
--- @return boolean True if the value of KEYPAD_OP_UNLOCK_INVALID_PIN is non-zero
KeypadOperationEventMask.is_keypad_op_unlock_invalid_pin_set = function(self)
  return (self.value & self.KEYPAD_OP_UNLOCK_INVALID_PIN) ~= 0
end
 
--- @function KeypadOperationEventMask:set_keypad_op_unlock_invalid_pin
--- Set the value of the bit in the KEYPAD_OP_UNLOCK_INVALID_PIN field to 1
KeypadOperationEventMask.set_keypad_op_unlock_invalid_pin = function(self)
  self.value = self.value | self.KEYPAD_OP_UNLOCK_INVALID_PIN
end

--- @function KeypadOperationEventMask:unset_keypad_op_unlock_invalid_pin
--- Set the value of the bits in the KEYPAD_OP_UNLOCK_INVALID_PIN field to 0
KeypadOperationEventMask.unset_keypad_op_unlock_invalid_pin = function(self)
  self.value = self.value & (~self.KEYPAD_OP_UNLOCK_INVALID_PIN & self.BASE_MASK)
end

--- @function KeypadOperationEventMask:is_keypad_op_unlock_invalid_schedule_set
--- @return boolean True if the value of KEYPAD_OP_UNLOCK_INVALID_SCHEDULE is non-zero
KeypadOperationEventMask.is_keypad_op_unlock_invalid_schedule_set = function(self)
  return (self.value & self.KEYPAD_OP_UNLOCK_INVALID_SCHEDULE) ~= 0
end
 
--- @function KeypadOperationEventMask:set_keypad_op_unlock_invalid_schedule
--- Set the value of the bit in the KEYPAD_OP_UNLOCK_INVALID_SCHEDULE field to 1
KeypadOperationEventMask.set_keypad_op_unlock_invalid_schedule = function(self)
  self.value = self.value | self.KEYPAD_OP_UNLOCK_INVALID_SCHEDULE
end

--- @function KeypadOperationEventMask:unset_keypad_op_unlock_invalid_schedule
--- Set the value of the bits in the KEYPAD_OP_UNLOCK_INVALID_SCHEDULE field to 0
KeypadOperationEventMask.unset_keypad_op_unlock_invalid_schedule = function(self)
  self.value = self.value & (~self.KEYPAD_OP_UNLOCK_INVALID_SCHEDULE & self.BASE_MASK)
end

--- @function KeypadOperationEventMask:is_keypad_op_non_access_user_set
--- @return boolean True if the value of KEYPAD_OP_NON_ACCESS_USER is non-zero
KeypadOperationEventMask.is_keypad_op_non_access_user_set = function(self)
  return (self.value & self.KEYPAD_OP_NON_ACCESS_USER) ~= 0
end
 
--- @function KeypadOperationEventMask:set_keypad_op_non_access_user
--- Set the value of the bit in the KEYPAD_OP_NON_ACCESS_USER field to 1
KeypadOperationEventMask.set_keypad_op_non_access_user = function(self)
  self.value = self.value | self.KEYPAD_OP_NON_ACCESS_USER
end

--- @function KeypadOperationEventMask:unset_keypad_op_non_access_user
--- Set the value of the bits in the KEYPAD_OP_NON_ACCESS_USER field to 0
KeypadOperationEventMask.unset_keypad_op_non_access_user = function(self)
  self.value = self.value & (~self.KEYPAD_OP_NON_ACCESS_USER & self.BASE_MASK)
end


KeypadOperationEventMask.mask_methods = {
  is_keypad_op_unknown_or_ms_set = KeypadOperationEventMask.is_keypad_op_unknown_or_ms_set,
  set_keypad_op_unknown_or_ms = KeypadOperationEventMask.set_keypad_op_unknown_or_ms,
  unset_keypad_op_unknown_or_ms = KeypadOperationEventMask.unset_keypad_op_unknown_or_ms,
  is_keypad_op_lock_set = KeypadOperationEventMask.is_keypad_op_lock_set,
  set_keypad_op_lock = KeypadOperationEventMask.set_keypad_op_lock,
  unset_keypad_op_lock = KeypadOperationEventMask.unset_keypad_op_lock,
  is_keypad_op_unlock_set = KeypadOperationEventMask.is_keypad_op_unlock_set,
  set_keypad_op_unlock = KeypadOperationEventMask.set_keypad_op_unlock,
  unset_keypad_op_unlock = KeypadOperationEventMask.unset_keypad_op_unlock,
  is_keypad_op_lock_error_invalid_pin_set = KeypadOperationEventMask.is_keypad_op_lock_error_invalid_pin_set,
  set_keypad_op_lock_error_invalid_pin = KeypadOperationEventMask.set_keypad_op_lock_error_invalid_pin,
  unset_keypad_op_lock_error_invalid_pin = KeypadOperationEventMask.unset_keypad_op_lock_error_invalid_pin,
  is_keypad_op_lock_error_invalid_schedule_set = KeypadOperationEventMask.is_keypad_op_lock_error_invalid_schedule_set,
  set_keypad_op_lock_error_invalid_schedule = KeypadOperationEventMask.set_keypad_op_lock_error_invalid_schedule,
  unset_keypad_op_lock_error_invalid_schedule = KeypadOperationEventMask.unset_keypad_op_lock_error_invalid_schedule,
  is_keypad_op_unlock_invalid_pin_set = KeypadOperationEventMask.is_keypad_op_unlock_invalid_pin_set,
  set_keypad_op_unlock_invalid_pin = KeypadOperationEventMask.set_keypad_op_unlock_invalid_pin,
  unset_keypad_op_unlock_invalid_pin = KeypadOperationEventMask.unset_keypad_op_unlock_invalid_pin,
  is_keypad_op_unlock_invalid_schedule_set = KeypadOperationEventMask.is_keypad_op_unlock_invalid_schedule_set,
  set_keypad_op_unlock_invalid_schedule = KeypadOperationEventMask.set_keypad_op_unlock_invalid_schedule,
  unset_keypad_op_unlock_invalid_schedule = KeypadOperationEventMask.unset_keypad_op_unlock_invalid_schedule,
  is_keypad_op_non_access_user_set = KeypadOperationEventMask.is_keypad_op_non_access_user_set,
  set_keypad_op_non_access_user = KeypadOperationEventMask.set_keypad_op_non_access_user,
  unset_keypad_op_non_access_user = KeypadOperationEventMask.unset_keypad_op_non_access_user,
}

--- Add additional functionality to the base type object
---
--- @param base_type_obj st.zigbee.data_types.Bitmap16 the base data type object to add functionality to
function KeypadOperationEventMask:augment_type(base_type_obj)
  cluster_base.attribute_augment_type_bitmap(self, base_type_obj)
end

function KeypadOperationEventMask.pretty_print(value_obj)
  local zb_utils = require "st.zigbee.utils"
  local pattern = ">I" .. value_obj.byte_length
  return string.format("%s: %s[0x%s]", value_obj.field_name or value_obj.NAME, KeypadOperationEventMask.NAME, zb_utils.pretty_print_hex_str(string.pack(pattern, value_obj.value)))
end

--- @function KeypadOperationEventMask:build_test_attr_report
---
--- Build a Rx Zigbee message as if a device reported this attribute
--- @param device st.zigbee.Device
--- @param data st.zigbee.data_types.Bitmap16 the attribute value
--- @return st.zigbee.ZigbeeMessageRx containing an AttributeReport body
KeypadOperationEventMask.build_test_attr_report = cluster_base.build_test_attr_report

--- @function KeypadOperationEventMask:build_test_read_attr_response
---
--- Build a Rx Zigbee message as if a device sent a read response for this attribute
--- @param device st.zigbee.Device
--- @param data st.zigbee.data_types.Bitmap16 the attribute value
--- @return st.zigbee.ZigbeeMessageRx containing an ReadAttributeResponse body
KeypadOperationEventMask.build_test_read_attr_response = cluster_base.build_test_read_attr_response

--- Create a Bitmap16 object of this attribute with any additional features provided for the attribute
---
--- This is also usable with the KeypadOperationEventMask(...) syntax
---
--- @vararg vararg the values needed to construct a Bitmap16
--- @return st.zigbee.data_types.Bitmap16
function KeypadOperationEventMask:new_value(...)
    local o = self.base_type(table.unpack({...}))
    self:augment_type(o)
    return o
end

--- Construct a st.zigbee.ZigbeeMessageTx to read this attribute from a device
---
--- @param device st.zigbee.Device
--- @return st.zigbee.ZigbeeMessageTx containing a ReadAttribute body
function KeypadOperationEventMask:read(device)
    return cluster_base.read_attribute(device, data_types.ClusterId(self._cluster.ID), data_types.AttributeId(self.ID))
end

--- Construct a st.zigbee.ZigbeeMessageTx to configure this attribute for reporting on a device
---
--- @param device st.zigbee.Device
--- @param min_rep_int number|st.zigbee.data_types.Uint16 the minimum interval allowed between reports of this attribute
--- @param max_rep_int number|st.zigbee.data_types.Uint16 the maximum interval allowed between reports of this attribute
--- @return st.zigbee.ZigbeeMessageTx containing a ConfigureReporting body
function KeypadOperationEventMask:configure_reporting(device, min_rep_int, max_rep_int)
  local min = data_types.validate_or_build_type(min_rep_int, data_types.Uint16, "minimum_reporting_interval")
  local max = data_types.validate_or_build_type(max_rep_int, data_types.Uint16, "maximum_reporting_interval")
  local rep_change = nil
  return cluster_base.configure_reporting(device, data_types.ClusterId(self._cluster.ID), data_types.AttributeId(self.ID), data_types.ZigbeeDataType(self.base_type.ID), min, max, rep_change)
end

--- Write a value to this attribute on a device
---
--- @param device st.zigbee.Device
--- @param value st.zigbee.data_types.Bitmap16 the value to write
function KeypadOperationEventMask:write(device, value)
  return cluster_base.attribute_write(self, device, value)
end

function KeypadOperationEventMask:set_parent_cluster(cluster)
  self._cluster = cluster
  return self
end

setmetatable(KeypadOperationEventMask, {__call = KeypadOperationEventMask.new_value})
return KeypadOperationEventMask

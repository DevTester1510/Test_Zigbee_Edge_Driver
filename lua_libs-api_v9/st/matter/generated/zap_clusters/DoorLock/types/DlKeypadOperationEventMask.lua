-- Copyright 2022 SmartThings
--
-- Licensed under the Apache License, Version 2.0 (the "License");
-- you may not use this file except in compliance with the License.
-- You may obtain a copy of the License at
--
-- http://www.apache.org/licenses/LICENSE-2.0
--
-- Unless required by applicable law or agreed to in writing, software
-- distributed under the License is distributed on an "AS IS" BASIS,
-- WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
-- See the License for the specific language governing permissions and
-- limitations under the License.

-- DO NOT EDIT: this code is automatically generated by ZCL Advanced Platform generator.

local data_types = require "st.matter.data_types"
local UintABC = require "st.matter.data_types.base_defs.UintABC"

--- @class st.matter.clusters.DoorLock.types.DlKeypadOperationEventMask
--- @alias DlKeypadOperationEventMask
---
--- @field public UNKNOWN number 1
--- @field public LOCK number 2
--- @field public UNLOCK number 4
--- @field public LOCK_INVALIDPIN number 8
--- @field public LOCK_INVALID_SCHEDULE number 16
--- @field public UNLOCK_INVALID_CODE number 32
--- @field public UNLOCK_INVALID_SCHEDULE number 64
--- @field public NON_ACCESS_USER_OP_EVENT number 128

local DlKeypadOperationEventMask = {}
local new_mt = UintABC.new_mt({NAME = "DlKeypadOperationEventMask", ID = data_types.name_to_id_map["Uint16"]}, 2)

DlKeypadOperationEventMask.BASE_MASK = 0xFFFF
DlKeypadOperationEventMask.UNKNOWN = 0x0001
DlKeypadOperationEventMask.LOCK = 0x0002
DlKeypadOperationEventMask.UNLOCK = 0x0004
DlKeypadOperationEventMask.LOCK_INVALIDPIN = 0x0008
DlKeypadOperationEventMask.LOCK_INVALID_SCHEDULE = 0x0010
DlKeypadOperationEventMask.UNLOCK_INVALID_CODE = 0x0020
DlKeypadOperationEventMask.UNLOCK_INVALID_SCHEDULE = 0x0040
DlKeypadOperationEventMask.NON_ACCESS_USER_OP_EVENT = 0x0080

DlKeypadOperationEventMask.mask_fields = {
  BASE_MASK = 0xFFFF,
  UNKNOWN = 0x0001,
  LOCK = 0x0002,
  UNLOCK = 0x0004,
  LOCK_INVALIDPIN = 0x0008,
  LOCK_INVALID_SCHEDULE = 0x0010,
  UNLOCK_INVALID_CODE = 0x0020,
  UNLOCK_INVALID_SCHEDULE = 0x0040,
  NON_ACCESS_USER_OP_EVENT = 0x0080,
}

--- @function DlKeypadOperationEventMask:is_unknown_set
--- @return boolean True if the value of UNKNOWN is non-zero
DlKeypadOperationEventMask.is_unknown_set = function(self)
  return (self.value & self.UNKNOWN) ~= 0
end
 
--- @function DlKeypadOperationEventMask:set_unknown
--- Set the value of the bit in the UNKNOWN field to 1
DlKeypadOperationEventMask.set_unknown = function(self)
  if self.value ~= nil then
    self.value = self.value | self.UNKNOWN
  else
    self.value = self.UNKNOWN
  end
end

--- @function DlKeypadOperationEventMask:unset_unknown
--- Set the value of the bits in the UNKNOWN field to 0
DlKeypadOperationEventMask.unset_unknown = function(self)
  self.value = self.value & (~self.UNKNOWN & self.BASE_MASK)
end
--- @function DlKeypadOperationEventMask:is_lock_set
--- @return boolean True if the value of LOCK is non-zero
DlKeypadOperationEventMask.is_lock_set = function(self)
  return (self.value & self.LOCK) ~= 0
end
 
--- @function DlKeypadOperationEventMask:set_lock
--- Set the value of the bit in the LOCK field to 1
DlKeypadOperationEventMask.set_lock = function(self)
  if self.value ~= nil then
    self.value = self.value | self.LOCK
  else
    self.value = self.LOCK
  end
end

--- @function DlKeypadOperationEventMask:unset_lock
--- Set the value of the bits in the LOCK field to 0
DlKeypadOperationEventMask.unset_lock = function(self)
  self.value = self.value & (~self.LOCK & self.BASE_MASK)
end
--- @function DlKeypadOperationEventMask:is_unlock_set
--- @return boolean True if the value of UNLOCK is non-zero
DlKeypadOperationEventMask.is_unlock_set = function(self)
  return (self.value & self.UNLOCK) ~= 0
end
 
--- @function DlKeypadOperationEventMask:set_unlock
--- Set the value of the bit in the UNLOCK field to 1
DlKeypadOperationEventMask.set_unlock = function(self)
  if self.value ~= nil then
    self.value = self.value | self.UNLOCK
  else
    self.value = self.UNLOCK
  end
end

--- @function DlKeypadOperationEventMask:unset_unlock
--- Set the value of the bits in the UNLOCK field to 0
DlKeypadOperationEventMask.unset_unlock = function(self)
  self.value = self.value & (~self.UNLOCK & self.BASE_MASK)
end
--- @function DlKeypadOperationEventMask:is_lock_invalidpin_set
--- @return boolean True if the value of LOCK_INVALIDPIN is non-zero
DlKeypadOperationEventMask.is_lock_invalidpin_set = function(self)
  return (self.value & self.LOCK_INVALIDPIN) ~= 0
end
 
--- @function DlKeypadOperationEventMask:set_lock_invalidpin
--- Set the value of the bit in the LOCK_INVALIDPIN field to 1
DlKeypadOperationEventMask.set_lock_invalidpin = function(self)
  if self.value ~= nil then
    self.value = self.value | self.LOCK_INVALIDPIN
  else
    self.value = self.LOCK_INVALIDPIN
  end
end

--- @function DlKeypadOperationEventMask:unset_lock_invalidpin
--- Set the value of the bits in the LOCK_INVALIDPIN field to 0
DlKeypadOperationEventMask.unset_lock_invalidpin = function(self)
  self.value = self.value & (~self.LOCK_INVALIDPIN & self.BASE_MASK)
end
--- @function DlKeypadOperationEventMask:is_lock_invalid_schedule_set
--- @return boolean True if the value of LOCK_INVALID_SCHEDULE is non-zero
DlKeypadOperationEventMask.is_lock_invalid_schedule_set = function(self)
  return (self.value & self.LOCK_INVALID_SCHEDULE) ~= 0
end
 
--- @function DlKeypadOperationEventMask:set_lock_invalid_schedule
--- Set the value of the bit in the LOCK_INVALID_SCHEDULE field to 1
DlKeypadOperationEventMask.set_lock_invalid_schedule = function(self)
  if self.value ~= nil then
    self.value = self.value | self.LOCK_INVALID_SCHEDULE
  else
    self.value = self.LOCK_INVALID_SCHEDULE
  end
end

--- @function DlKeypadOperationEventMask:unset_lock_invalid_schedule
--- Set the value of the bits in the LOCK_INVALID_SCHEDULE field to 0
DlKeypadOperationEventMask.unset_lock_invalid_schedule = function(self)
  self.value = self.value & (~self.LOCK_INVALID_SCHEDULE & self.BASE_MASK)
end
--- @function DlKeypadOperationEventMask:is_unlock_invalid_code_set
--- @return boolean True if the value of UNLOCK_INVALID_CODE is non-zero
DlKeypadOperationEventMask.is_unlock_invalid_code_set = function(self)
  return (self.value & self.UNLOCK_INVALID_CODE) ~= 0
end
 
--- @function DlKeypadOperationEventMask:set_unlock_invalid_code
--- Set the value of the bit in the UNLOCK_INVALID_CODE field to 1
DlKeypadOperationEventMask.set_unlock_invalid_code = function(self)
  if self.value ~= nil then
    self.value = self.value | self.UNLOCK_INVALID_CODE
  else
    self.value = self.UNLOCK_INVALID_CODE
  end
end

--- @function DlKeypadOperationEventMask:unset_unlock_invalid_code
--- Set the value of the bits in the UNLOCK_INVALID_CODE field to 0
DlKeypadOperationEventMask.unset_unlock_invalid_code = function(self)
  self.value = self.value & (~self.UNLOCK_INVALID_CODE & self.BASE_MASK)
end
--- @function DlKeypadOperationEventMask:is_unlock_invalid_schedule_set
--- @return boolean True if the value of UNLOCK_INVALID_SCHEDULE is non-zero
DlKeypadOperationEventMask.is_unlock_invalid_schedule_set = function(self)
  return (self.value & self.UNLOCK_INVALID_SCHEDULE) ~= 0
end
 
--- @function DlKeypadOperationEventMask:set_unlock_invalid_schedule
--- Set the value of the bit in the UNLOCK_INVALID_SCHEDULE field to 1
DlKeypadOperationEventMask.set_unlock_invalid_schedule = function(self)
  if self.value ~= nil then
    self.value = self.value | self.UNLOCK_INVALID_SCHEDULE
  else
    self.value = self.UNLOCK_INVALID_SCHEDULE
  end
end

--- @function DlKeypadOperationEventMask:unset_unlock_invalid_schedule
--- Set the value of the bits in the UNLOCK_INVALID_SCHEDULE field to 0
DlKeypadOperationEventMask.unset_unlock_invalid_schedule = function(self)
  self.value = self.value & (~self.UNLOCK_INVALID_SCHEDULE & self.BASE_MASK)
end
--- @function DlKeypadOperationEventMask:is_non_access_user_op_event_set
--- @return boolean True if the value of NON_ACCESS_USER_OP_EVENT is non-zero
DlKeypadOperationEventMask.is_non_access_user_op_event_set = function(self)
  return (self.value & self.NON_ACCESS_USER_OP_EVENT) ~= 0
end
 
--- @function DlKeypadOperationEventMask:set_non_access_user_op_event
--- Set the value of the bit in the NON_ACCESS_USER_OP_EVENT field to 1
DlKeypadOperationEventMask.set_non_access_user_op_event = function(self)
  if self.value ~= nil then
    self.value = self.value | self.NON_ACCESS_USER_OP_EVENT
  else
    self.value = self.NON_ACCESS_USER_OP_EVENT
  end
end

--- @function DlKeypadOperationEventMask:unset_non_access_user_op_event
--- Set the value of the bits in the NON_ACCESS_USER_OP_EVENT field to 0
DlKeypadOperationEventMask.unset_non_access_user_op_event = function(self)
  self.value = self.value & (~self.NON_ACCESS_USER_OP_EVENT & self.BASE_MASK)
end


DlKeypadOperationEventMask.mask_methods = {
  is_unknown_set = DlKeypadOperationEventMask.is_unknown_set,
  set_unknown = DlKeypadOperationEventMask.set_unknown,
  unset_unknown = DlKeypadOperationEventMask.unset_unknown,
  is_lock_set = DlKeypadOperationEventMask.is_lock_set,
  set_lock = DlKeypadOperationEventMask.set_lock,
  unset_lock = DlKeypadOperationEventMask.unset_lock,
  is_unlock_set = DlKeypadOperationEventMask.is_unlock_set,
  set_unlock = DlKeypadOperationEventMask.set_unlock,
  unset_unlock = DlKeypadOperationEventMask.unset_unlock,
  is_lock_invalidpin_set = DlKeypadOperationEventMask.is_lock_invalidpin_set,
  set_lock_invalidpin = DlKeypadOperationEventMask.set_lock_invalidpin,
  unset_lock_invalidpin = DlKeypadOperationEventMask.unset_lock_invalidpin,
  is_lock_invalid_schedule_set = DlKeypadOperationEventMask.is_lock_invalid_schedule_set,
  set_lock_invalid_schedule = DlKeypadOperationEventMask.set_lock_invalid_schedule,
  unset_lock_invalid_schedule = DlKeypadOperationEventMask.unset_lock_invalid_schedule,
  is_unlock_invalid_code_set = DlKeypadOperationEventMask.is_unlock_invalid_code_set,
  set_unlock_invalid_code = DlKeypadOperationEventMask.set_unlock_invalid_code,
  unset_unlock_invalid_code = DlKeypadOperationEventMask.unset_unlock_invalid_code,
  is_unlock_invalid_schedule_set = DlKeypadOperationEventMask.is_unlock_invalid_schedule_set,
  set_unlock_invalid_schedule = DlKeypadOperationEventMask.set_unlock_invalid_schedule,
  unset_unlock_invalid_schedule = DlKeypadOperationEventMask.unset_unlock_invalid_schedule,
  is_non_access_user_op_event_set = DlKeypadOperationEventMask.is_non_access_user_op_event_set,
  set_non_access_user_op_event = DlKeypadOperationEventMask.set_non_access_user_op_event,
  unset_non_access_user_op_event = DlKeypadOperationEventMask.unset_non_access_user_op_event,
}

DlKeypadOperationEventMask.augment_type = function(cls, val)
  setmetatable(val, new_mt)
end

setmetatable(DlKeypadOperationEventMask, new_mt)

return DlKeypadOperationEventMask


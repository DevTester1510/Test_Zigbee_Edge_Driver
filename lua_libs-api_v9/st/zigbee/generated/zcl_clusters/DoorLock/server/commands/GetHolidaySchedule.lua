local data_types = require "st.zigbee.data_types"
local utils = require "st.zigbee.utils"
local log = require "log"
local cluster_base = require "st.zigbee.cluster_base"
local DrlkHolidayScheduleIdType = require "st.zigbee.generated.zcl_clusters.DoorLock.types.DrlkHolidayScheduleId"

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

-----------------------------------------------------------
-- DoorLock command GetHolidaySchedule
-----------------------------------------------------------

--- @class st.zigbee.zcl.clusters.DoorLock.GetHolidaySchedule
--- @alias GetHolidaySchedule
---
--- @field public ID number 0x12 the ID of this command
--- @field public NAME string "GetHolidaySchedule" the name of this command
--- @field public holiday_schedule_id st.zigbee.zcl.clusters.DoorLock.types.DrlkHolidayScheduleId
local GetHolidaySchedule = {}
GetHolidaySchedule.NAME = "GetHolidaySchedule"
GetHolidaySchedule.ID = 0x12
GetHolidaySchedule.args_def = {
  {
    name = "holiday_schedule_id",
    optional = false,
    data_type = DrlkHolidayScheduleIdType,
    is_complex = false,
    is_array = false,
    default = 0x00,
  },
}

function GetHolidaySchedule:get_fields()
  return cluster_base.command_get_fields(self)
end

GetHolidaySchedule.get_length = utils.length_from_fields
GetHolidaySchedule._serialize = utils.serialize_from_fields
GetHolidaySchedule.pretty_print = utils.print_from_fields

--- Deserialize this command
---
--- @param buf buf the bytes of the command body
--- @return GetHolidaySchedule
function GetHolidaySchedule.deserialize(buf)
  return cluster_base.command_deserialize(GetHolidaySchedule, buf)
end

function GetHolidaySchedule:set_field_names()
  cluster_base.command_set_fields(self)
end

--- Build a version of this message as if it came from the device
---
--- @param device st.zigbee.Device the device to build the message from
--- @param holiday_schedule_id st.zigbee.zcl.clusters.DoorLock.types.DrlkHolidayScheduleId
--- @return st.zigbee.ZigbeeMessageRx The full Zigbee message containing this command body
function GetHolidaySchedule.build_test_rx(device, holiday_schedule_id)
  local args = {holiday_schedule_id}

  return cluster_base.command_build_test_rx(GetHolidaySchedule, device, args, "server")
end

--- Initialize the GetHolidaySchedule command
---
--- @param self GetHolidaySchedule the template class for this command
--- @param device st.zigbee.Device the device to build this message to
--- @param holiday_schedule_id st.zigbee.zcl.clusters.DoorLock.types.DrlkHolidayScheduleId
--- @return st.zigbee.ZigbeeMessageTx the full command addressed to the device
function GetHolidaySchedule:init(device, holiday_schedule_id)
  local args = {holiday_schedule_id}

  return cluster_base.command_init(self, device, args, "server")
end

function GetHolidaySchedule:set_parent_cluster(cluster)
  self._cluster = cluster
  return self
end

setmetatable(GetHolidaySchedule, {__call = GetHolidaySchedule.init})

return GetHolidaySchedule

local data_types = require "st.zigbee.data_types"
local utils = require "st.zigbee.utils"
local log = require "log"
local cluster_base = require "st.zigbee.cluster_base"
local ZclStatus = require "st.zigbee.generated.types.ZclStatus"
local DrlkOperatingModeType = require "st.zigbee.generated.zcl_clusters.DoorLock.types.DrlkOperatingMode"

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
-- DoorLock command GetHolidayScheduleResponse
-----------------------------------------------------------

--- @class st.zigbee.zcl.clusters.DoorLock.GetHolidayScheduleResponse
--- @alias GetHolidayScheduleResponse
---
--- @field public ID number 0x12 the ID of this command
--- @field public NAME string "GetHolidayScheduleResponse" the name of this command
--- @field public holiday_schedule_id st.zigbee.data_types.Uint8
--- @field public status st.zigbee.data_types.ZclStatus
--- @field public local_start_time st.zigbee.data_types.Uint32
--- @field public local_end_time st.zigbee.data_types.Uint32
--- @field public operating_mode_during_holiday st.zigbee.zcl.clusters.DoorLock.types.DrlkOperatingMode
local GetHolidayScheduleResponse = {}
GetHolidayScheduleResponse.NAME = "GetHolidayScheduleResponse"
GetHolidayScheduleResponse.ID = 0x12
GetHolidayScheduleResponse.args_def = {
  {
    name = "holiday_schedule_id",
    optional = false,
    data_type = data_types.Uint8,
    is_complex = false,
    is_array = false,
    default = 0x00,
  },
  {
    name = "status",
    optional = false,
    data_type = ZclStatus,
    is_complex = false,
    is_array = false,
  },
  {
    name = "local_start_time",
    optional = false,
    data_type = data_types.Uint32,
    is_complex = false,
    is_array = false,
    default = 0x00000000,
  },
  {
    name = "local_end_time",
    optional = false,
    data_type = data_types.Uint32,
    is_complex = false,
    is_array = false,
    default = 0x00000000,
  },
  {
    name = "operating_mode_during_holiday",
    optional = false,
    data_type = DrlkOperatingModeType,
    is_complex = false,
    is_array = false,
    default = 0x00,
  },
}

function GetHolidayScheduleResponse:get_fields()
  return cluster_base.command_get_fields(self)
end

GetHolidayScheduleResponse.get_length = utils.length_from_fields
GetHolidayScheduleResponse._serialize = utils.serialize_from_fields
GetHolidayScheduleResponse.pretty_print = utils.print_from_fields

--- Deserialize this command
---
--- @param buf buf the bytes of the command body
--- @return GetHolidayScheduleResponse
function GetHolidayScheduleResponse.deserialize(buf)
  return cluster_base.command_deserialize(GetHolidayScheduleResponse, buf)
end

function GetHolidayScheduleResponse:set_field_names()
  cluster_base.command_set_fields(self)
end

--- Build a version of this message as if it came from the device
---
--- @param device st.zigbee.Device the device to build the message from
--- @param holiday_schedule_id st.zigbee.data_types.Uint8
--- @param status st.zigbee.data_types.ZclStatus
--- @param local_start_time st.zigbee.data_types.Uint32
--- @param local_end_time st.zigbee.data_types.Uint32
--- @param operating_mode_during_holiday st.zigbee.zcl.clusters.DoorLock.types.DrlkOperatingMode
--- @return st.zigbee.ZigbeeMessageRx The full Zigbee message containing this command body
function GetHolidayScheduleResponse.build_test_rx(device, holiday_schedule_id, status, local_start_time, local_end_time, operating_mode_during_holiday)
  local args = {holiday_schedule_id, status, local_start_time, local_end_time, operating_mode_during_holiday}

  return cluster_base.command_build_test_rx(GetHolidayScheduleResponse, device, args, "client")
end

--- Initialize the GetHolidayScheduleResponse command
---
--- @param self GetHolidayScheduleResponse the template class for this command
--- @param device st.zigbee.Device the device to build this message to
--- @param holiday_schedule_id st.zigbee.data_types.Uint8
--- @param status st.zigbee.data_types.ZclStatus
--- @param local_start_time st.zigbee.data_types.Uint32
--- @param local_end_time st.zigbee.data_types.Uint32
--- @param operating_mode_during_holiday st.zigbee.zcl.clusters.DoorLock.types.DrlkOperatingMode
--- @return st.zigbee.ZigbeeMessageTx the full command addressed to the device
function GetHolidayScheduleResponse:init(device, holiday_schedule_id, status, local_start_time, local_end_time, operating_mode_during_holiday)
  local args = {holiday_schedule_id, status, local_start_time, local_end_time, operating_mode_during_holiday}

  return cluster_base.command_init(self, device, args, "client")
end

function GetHolidayScheduleResponse:set_parent_cluster(cluster)
  self._cluster = cluster
  return self
end

setmetatable(GetHolidayScheduleResponse, {__call = GetHolidayScheduleResponse.init})

return GetHolidayScheduleResponse

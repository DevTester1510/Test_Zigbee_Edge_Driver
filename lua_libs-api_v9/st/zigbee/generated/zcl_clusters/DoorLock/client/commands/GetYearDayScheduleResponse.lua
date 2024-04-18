local data_types = require "st.zigbee.data_types"
local utils = require "st.zigbee.utils"
local log = require "log"
local cluster_base = require "st.zigbee.cluster_base"
local ZclStatus = require "st.zigbee.generated.types.ZclStatus"

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
-- DoorLock command GetYearDayScheduleResponse
-----------------------------------------------------------

--- @class st.zigbee.zcl.clusters.DoorLock.GetYearDayScheduleResponse
--- @alias GetYearDayScheduleResponse
---
--- @field public ID number 0x0F the ID of this command
--- @field public NAME string "GetYearDayScheduleResponse" the name of this command
--- @field public schedule_id st.zigbee.data_types.Uint8
--- @field public user_id st.zigbee.data_types.Uint16
--- @field public status st.zigbee.data_types.ZclStatus
--- @field public local_start_time st.zigbee.data_types.Uint32
--- @field public local_end_time st.zigbee.data_types.Uint32
local GetYearDayScheduleResponse = {}
GetYearDayScheduleResponse.NAME = "GetYearDayScheduleResponse"
GetYearDayScheduleResponse.ID = 0x0F
GetYearDayScheduleResponse.args_def = {
  {
    name = "schedule_id",
    optional = false,
    data_type = data_types.Uint8,
    is_complex = false,
    is_array = false,
    default = 0x00,
  },
  {
    name = "user_id",
    optional = false,
    data_type = data_types.Uint16,
    is_complex = false,
    is_array = false,
    default = 0x0000,
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
}

function GetYearDayScheduleResponse:get_fields()
  return cluster_base.command_get_fields(self)
end

GetYearDayScheduleResponse.get_length = utils.length_from_fields
GetYearDayScheduleResponse._serialize = utils.serialize_from_fields
GetYearDayScheduleResponse.pretty_print = utils.print_from_fields

--- Deserialize this command
---
--- @param buf buf the bytes of the command body
--- @return GetYearDayScheduleResponse
function GetYearDayScheduleResponse.deserialize(buf)
  return cluster_base.command_deserialize(GetYearDayScheduleResponse, buf)
end

function GetYearDayScheduleResponse:set_field_names()
  cluster_base.command_set_fields(self)
end

--- Build a version of this message as if it came from the device
---
--- @param device st.zigbee.Device the device to build the message from
--- @param schedule_id st.zigbee.data_types.Uint8
--- @param user_id st.zigbee.data_types.Uint16
--- @param status st.zigbee.data_types.ZclStatus
--- @param local_start_time st.zigbee.data_types.Uint32
--- @param local_end_time st.zigbee.data_types.Uint32
--- @return st.zigbee.ZigbeeMessageRx The full Zigbee message containing this command body
function GetYearDayScheduleResponse.build_test_rx(device, schedule_id, user_id, status, local_start_time, local_end_time)
  local args = {schedule_id, user_id, status, local_start_time, local_end_time}

  return cluster_base.command_build_test_rx(GetYearDayScheduleResponse, device, args, "client")
end

--- Initialize the GetYearDayScheduleResponse command
---
--- @param self GetYearDayScheduleResponse the template class for this command
--- @param device st.zigbee.Device the device to build this message to
--- @param schedule_id st.zigbee.data_types.Uint8
--- @param user_id st.zigbee.data_types.Uint16
--- @param status st.zigbee.data_types.ZclStatus
--- @param local_start_time st.zigbee.data_types.Uint32
--- @param local_end_time st.zigbee.data_types.Uint32
--- @return st.zigbee.ZigbeeMessageTx the full command addressed to the device
function GetYearDayScheduleResponse:init(device, schedule_id, user_id, status, local_start_time, local_end_time)
  local args = {schedule_id, user_id, status, local_start_time, local_end_time}

  return cluster_base.command_init(self, device, args, "client")
end

function GetYearDayScheduleResponse:set_parent_cluster(cluster)
  self._cluster = cluster
  return self
end

setmetatable(GetYearDayScheduleResponse, {__call = GetYearDayScheduleResponse.init})

return GetYearDayScheduleResponse

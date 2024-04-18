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
-- Alarms command GetAlarmResponse
-----------------------------------------------------------

--- @class st.zigbee.zcl.clusters.Alarms.GetAlarmResponse
--- @alias GetAlarmResponse
---
--- @field public ID number 0x01 the ID of this command
--- @field public NAME string "GetAlarmResponse" the name of this command
--- @field public status st.zigbee.data_types.ZclStatus
--- @field public alarm_code st.zigbee.data_types.Enum8
--- @field public cluster_identifier st.zigbee.data_types.ClusterId
--- @field public time_stamp st.zigbee.data_types.Uint32
local GetAlarmResponse = {}
GetAlarmResponse.NAME = "GetAlarmResponse"
GetAlarmResponse.ID = 0x01
GetAlarmResponse.args_def = {
  {
    name = "status",
    optional = false,
    data_type = ZclStatus,
    is_complex = false,
    is_array = false,
  },
  {
    name = "alarm_code",
    optional = false,
    data_type = data_types.Enum8,
    is_complex = false,
    is_array = false,
    default = 0x00,
  },
  {
    name = "cluster_identifier",
    optional = false,
    data_type = data_types.ClusterId,
    is_complex = false,
    is_array = false,
  },
  {
    name = "time_stamp",
    optional = false,
    data_type = data_types.Uint32,
    is_complex = false,
    is_array = false,
    default = 0x00000000,
  },
}

function GetAlarmResponse:get_fields()
  return cluster_base.command_get_fields(self)
end

GetAlarmResponse.get_length = utils.length_from_fields
GetAlarmResponse._serialize = utils.serialize_from_fields
GetAlarmResponse.pretty_print = utils.print_from_fields

--- Deserialize this command
---
--- @param buf buf the bytes of the command body
--- @return GetAlarmResponse
function GetAlarmResponse.deserialize(buf)
  return cluster_base.command_deserialize(GetAlarmResponse, buf)
end

function GetAlarmResponse:set_field_names()
  cluster_base.command_set_fields(self)
end

--- Build a version of this message as if it came from the device
---
--- @param device st.zigbee.Device the device to build the message from
--- @param status st.zigbee.data_types.ZclStatus
--- @param alarm_code st.zigbee.data_types.Enum8
--- @param cluster_identifier st.zigbee.data_types.ClusterId
--- @param time_stamp st.zigbee.data_types.Uint32
--- @return st.zigbee.ZigbeeMessageRx The full Zigbee message containing this command body
function GetAlarmResponse.build_test_rx(device, status, alarm_code, cluster_identifier, time_stamp)
  local args = {status, alarm_code, cluster_identifier, time_stamp}

  return cluster_base.command_build_test_rx(GetAlarmResponse, device, args, "client")
end

--- Initialize the GetAlarmResponse command
---
--- @param self GetAlarmResponse the template class for this command
--- @param device st.zigbee.Device the device to build this message to
--- @param status st.zigbee.data_types.ZclStatus
--- @param alarm_code st.zigbee.data_types.Enum8
--- @param cluster_identifier st.zigbee.data_types.ClusterId
--- @param time_stamp st.zigbee.data_types.Uint32
--- @return st.zigbee.ZigbeeMessageTx the full command addressed to the device
function GetAlarmResponse:init(device, status, alarm_code, cluster_identifier, time_stamp)
  local args = {status, alarm_code, cluster_identifier, time_stamp}

  return cluster_base.command_init(self, device, args, "client")
end

function GetAlarmResponse:set_parent_cluster(cluster)
  self._cluster = cluster
  return self
end

setmetatable(GetAlarmResponse, {__call = GetAlarmResponse.init})

return GetAlarmResponse

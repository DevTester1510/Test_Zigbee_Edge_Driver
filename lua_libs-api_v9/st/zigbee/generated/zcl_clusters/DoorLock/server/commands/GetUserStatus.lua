local data_types = require "st.zigbee.data_types"
local utils = require "st.zigbee.utils"
local log = require "log"
local cluster_base = require "st.zigbee.cluster_base"
local DrlkTotalUserIdType = require "st.zigbee.generated.zcl_clusters.DoorLock.types.DrlkTotalUserId"

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
-- DoorLock command GetUserStatus
-----------------------------------------------------------

--- @class st.zigbee.zcl.clusters.DoorLock.GetUserStatus
--- @alias GetUserStatus
---
--- @field public ID number 0x0A the ID of this command
--- @field public NAME string "GetUserStatus" the name of this command
--- @field public user_id st.zigbee.zcl.clusters.DoorLock.types.DrlkTotalUserId
local GetUserStatus = {}
GetUserStatus.NAME = "GetUserStatus"
GetUserStatus.ID = 0x0A
GetUserStatus.args_def = {
  {
    name = "user_id",
    optional = false,
    data_type = DrlkTotalUserIdType,
    is_complex = false,
    is_array = false,
    default = 0x0000,
  },
}

function GetUserStatus:get_fields()
  return cluster_base.command_get_fields(self)
end

GetUserStatus.get_length = utils.length_from_fields
GetUserStatus._serialize = utils.serialize_from_fields
GetUserStatus.pretty_print = utils.print_from_fields

--- Deserialize this command
---
--- @param buf buf the bytes of the command body
--- @return GetUserStatus
function GetUserStatus.deserialize(buf)
  return cluster_base.command_deserialize(GetUserStatus, buf)
end

function GetUserStatus:set_field_names()
  cluster_base.command_set_fields(self)
end

--- Build a version of this message as if it came from the device
---
--- @param device st.zigbee.Device the device to build the message from
--- @param user_id st.zigbee.zcl.clusters.DoorLock.types.DrlkTotalUserId
--- @return st.zigbee.ZigbeeMessageRx The full Zigbee message containing this command body
function GetUserStatus.build_test_rx(device, user_id)
  local args = {user_id}

  return cluster_base.command_build_test_rx(GetUserStatus, device, args, "server")
end

--- Initialize the GetUserStatus command
---
--- @param self GetUserStatus the template class for this command
--- @param device st.zigbee.Device the device to build this message to
--- @param user_id st.zigbee.zcl.clusters.DoorLock.types.DrlkTotalUserId
--- @return st.zigbee.ZigbeeMessageTx the full command addressed to the device
function GetUserStatus:init(device, user_id)
  local args = {user_id}

  return cluster_base.command_init(self, device, args, "server")
end

function GetUserStatus:set_parent_cluster(cluster)
  self._cluster = cluster
  return self
end

setmetatable(GetUserStatus, {__call = GetUserStatus.init})

return GetUserStatus
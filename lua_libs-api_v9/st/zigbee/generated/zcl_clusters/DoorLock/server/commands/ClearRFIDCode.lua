local data_types = require "st.zigbee.data_types"
local utils = require "st.zigbee.utils"
local log = require "log"
local cluster_base = require "st.zigbee.cluster_base"
local DrlkRfidUserIdType = require "st.zigbee.generated.zcl_clusters.DoorLock.types.DrlkRfidUserId"

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
-- DoorLock command ClearRFIDCode
-----------------------------------------------------------

--- @class st.zigbee.zcl.clusters.DoorLock.ClearRFIDCode
--- @alias ClearRFIDCode
---
--- @field public ID number 0x18 the ID of this command
--- @field public NAME string "ClearRFIDCode" the name of this command
--- @field public user_id st.zigbee.zcl.clusters.DoorLock.types.DrlkRfidUserId
local ClearRFIDCode = {}
ClearRFIDCode.NAME = "ClearRFIDCode"
ClearRFIDCode.ID = 0x18
ClearRFIDCode.args_def = {
  {
    name = "user_id",
    optional = false,
    data_type = DrlkRfidUserIdType,
    is_complex = false,
    is_array = false,
    default = 0x0000,
  },
}

function ClearRFIDCode:get_fields()
  return cluster_base.command_get_fields(self)
end

ClearRFIDCode.get_length = utils.length_from_fields
ClearRFIDCode._serialize = utils.serialize_from_fields
ClearRFIDCode.pretty_print = utils.print_from_fields

--- Deserialize this command
---
--- @param buf buf the bytes of the command body
--- @return ClearRFIDCode
function ClearRFIDCode.deserialize(buf)
  return cluster_base.command_deserialize(ClearRFIDCode, buf)
end

function ClearRFIDCode:set_field_names()
  cluster_base.command_set_fields(self)
end

--- Build a version of this message as if it came from the device
---
--- @param device st.zigbee.Device the device to build the message from
--- @param user_id st.zigbee.zcl.clusters.DoorLock.types.DrlkRfidUserId
--- @return st.zigbee.ZigbeeMessageRx The full Zigbee message containing this command body
function ClearRFIDCode.build_test_rx(device, user_id)
  local args = {user_id}

  return cluster_base.command_build_test_rx(ClearRFIDCode, device, args, "server")
end

--- Initialize the ClearRFIDCode command
---
--- @param self ClearRFIDCode the template class for this command
--- @param device st.zigbee.Device the device to build this message to
--- @param user_id st.zigbee.zcl.clusters.DoorLock.types.DrlkRfidUserId
--- @return st.zigbee.ZigbeeMessageTx the full command addressed to the device
function ClearRFIDCode:init(device, user_id)
  local args = {user_id}

  return cluster_base.command_init(self, device, args, "server")
end

function ClearRFIDCode:set_parent_cluster(cluster)
  self._cluster = cluster
  return self
end

setmetatable(ClearRFIDCode, {__call = ClearRFIDCode.init})

return ClearRFIDCode
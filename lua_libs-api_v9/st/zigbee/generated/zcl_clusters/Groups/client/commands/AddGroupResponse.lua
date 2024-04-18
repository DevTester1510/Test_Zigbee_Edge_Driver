local data_types = require "st.zigbee.data_types"
local utils = require "st.zigbee.utils"
local log = require "log"
local cluster_base = require "st.zigbee.cluster_base"

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
-- Groups command AddGroupResponse
-----------------------------------------------------------

--- @class st.zigbee.zcl.clusters.Groups.AddGroupResponse
--- @alias AddGroupResponse
---
--- @field public ID number 0x00 the ID of this command
--- @field public NAME string "AddGroupResponse" the name of this command
--- @field public status st.zigbee.data_types.Enum8
--- @field public group_id st.zigbee.data_types.Uint16
local AddGroupResponse = {}
AddGroupResponse.NAME = "AddGroupResponse"
AddGroupResponse.ID = 0x00
AddGroupResponse.args_def = {
  {
    name = "status",
    optional = false,
    data_type = data_types.Enum8,
    is_complex = false,
    is_array = false,
    default = 0x00,
  },
  {
    name = "group_id",
    optional = false,
    data_type = data_types.Uint16,
    is_complex = false,
    is_array = false,
    default = 0x0000,
  },
}

function AddGroupResponse:get_fields()
  return cluster_base.command_get_fields(self)
end

AddGroupResponse.get_length = utils.length_from_fields
AddGroupResponse._serialize = utils.serialize_from_fields
AddGroupResponse.pretty_print = utils.print_from_fields

--- Deserialize this command
---
--- @param buf buf the bytes of the command body
--- @return AddGroupResponse
function AddGroupResponse.deserialize(buf)
  return cluster_base.command_deserialize(AddGroupResponse, buf)
end

function AddGroupResponse:set_field_names()
  cluster_base.command_set_fields(self)
end

--- Build a version of this message as if it came from the device
---
--- @param device st.zigbee.Device the device to build the message from
--- @param status st.zigbee.data_types.Enum8
--- @param group_id st.zigbee.data_types.Uint16
--- @return st.zigbee.ZigbeeMessageRx The full Zigbee message containing this command body
function AddGroupResponse.build_test_rx(device, status, group_id)
  local args = {status, group_id}

  return cluster_base.command_build_test_rx(AddGroupResponse, device, args, "client")
end

--- Initialize the AddGroupResponse command
---
--- @param self AddGroupResponse the template class for this command
--- @param device st.zigbee.Device the device to build this message to
--- @param status st.zigbee.data_types.Enum8
--- @param group_id st.zigbee.data_types.Uint16
--- @return st.zigbee.ZigbeeMessageTx the full command addressed to the device
function AddGroupResponse:init(device, status, group_id)
  local args = {status, group_id}

  return cluster_base.command_init(self, device, args, "client")
end

function AddGroupResponse:set_parent_cluster(cluster)
  self._cluster = cluster
  return self
end

setmetatable(AddGroupResponse, {__call = AddGroupResponse.init})

return AddGroupResponse

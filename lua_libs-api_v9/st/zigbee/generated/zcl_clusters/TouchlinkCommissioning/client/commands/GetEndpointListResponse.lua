local data_types = require "st.zigbee.data_types"
local utils = require "st.zigbee.utils"
local log = require "log"
local cluster_base = require "st.zigbee.cluster_base"
local TlEndpointInformationRecordType = require "st.zigbee.generated.zcl_clusters.TouchlinkCommissioning.types.TlEndpointInformationRecord"

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
-- TouchlinkCommissioning command GetEndpointListResponse
-----------------------------------------------------------

--- @class st.zigbee.zcl.clusters.TouchlinkCommissioning.GetEndpointListResponse
--- @alias GetEndpointListResponse
---
--- @field public ID number 0x42 the ID of this command
--- @field public NAME string "GetEndpointListResponse" the name of this command
--- @field public total st.zigbee.data_types.Uint8
--- @field public start_index st.zigbee.data_types.Uint8
--- @field public endpoint_information_record_list_list st.zigbee.zcl.clusters.TouchlinkCommissioning.types.TlEndpointInformationRecord[]
local GetEndpointListResponse = {}
GetEndpointListResponse.NAME = "GetEndpointListResponse"
GetEndpointListResponse.ID = 0x42
GetEndpointListResponse.args_def = {
  {
    name = "total",
    optional = false,
    data_type = data_types.Uint8,
    is_complex = false,
    is_array = false,
    default = 0x00,
  },
  {
    name = "start_index",
    optional = false,
    data_type = data_types.Uint8,
    is_complex = false,
    is_array = false,
    default = 0x00,
  },
  {
    name = "endpoint_information_record_list",
    optional = false,
    data_type = TlEndpointInformationRecordType,
    is_complex = false,
    is_array = true,
  },
}

function GetEndpointListResponse:get_fields()
  return cluster_base.command_get_fields(self)
end

GetEndpointListResponse.get_length = utils.length_from_fields
GetEndpointListResponse._serialize = utils.serialize_from_fields
GetEndpointListResponse.pretty_print = utils.print_from_fields

--- Deserialize this command
---
--- @param buf buf the bytes of the command body
--- @return GetEndpointListResponse
function GetEndpointListResponse.deserialize(buf)
  return cluster_base.command_deserialize(GetEndpointListResponse, buf)
end

function GetEndpointListResponse:set_field_names()
  cluster_base.command_set_fields(self)
end

--- Build a version of this message as if it came from the device
---
--- @param device st.zigbee.Device the device to build the message from
--- @param total st.zigbee.data_types.Uint8
--- @param start_index st.zigbee.data_types.Uint8
--- @param endpoint_information_record_list st.zigbee.zcl.clusters.TouchlinkCommissioning.types.TlEndpointInformationRecord[]
--- @return st.zigbee.ZigbeeMessageRx The full Zigbee message containing this command body
function GetEndpointListResponse.build_test_rx(device, total, start_index, endpoint_information_record_list)
  local args = {total, start_index, endpoint_information_record_list}

  return cluster_base.command_build_test_rx(GetEndpointListResponse, device, args, "client")
end

--- Initialize the GetEndpointListResponse command
---
--- @param self GetEndpointListResponse the template class for this command
--- @param device st.zigbee.Device the device to build this message to
--- @param total st.zigbee.data_types.Uint8
--- @param start_index st.zigbee.data_types.Uint8
--- @param endpoint_information_record_list st.zigbee.zcl.clusters.TouchlinkCommissioning.types.TlEndpointInformationRecord[]
--- @return st.zigbee.ZigbeeMessageTx the full command addressed to the device
function GetEndpointListResponse:init(device, total, start_index, endpoint_information_record_list)
  local args = {total, start_index, endpoint_information_record_list}

  return cluster_base.command_init(self, device, args, "client")
end

function GetEndpointListResponse:set_parent_cluster(cluster)
  self._cluster = cluster
  return self
end

setmetatable(GetEndpointListResponse, {__call = GetEndpointListResponse.init})

return GetEndpointListResponse

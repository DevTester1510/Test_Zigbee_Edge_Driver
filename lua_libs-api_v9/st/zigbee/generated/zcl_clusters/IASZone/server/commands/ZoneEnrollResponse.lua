local data_types = require "st.zigbee.data_types"
local utils = require "st.zigbee.utils"
local log = require "log"
local cluster_base = require "st.zigbee.cluster_base"
local EnrollResponseCodeType = require "st.zigbee.generated.zcl_clusters.IASZone.types.EnrollResponseCode"

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
-- IASZone command ZoneEnrollResponse
-----------------------------------------------------------

--- @class st.zigbee.zcl.clusters.IASZone.ZoneEnrollResponse
--- @alias ZoneEnrollResponse
---
--- @field public ID number 0x00 the ID of this command
--- @field public NAME string "ZoneEnrollResponse" the name of this command
--- @field public enroll_response_code st.zigbee.zcl.clusters.IASZone.types.EnrollResponseCode
--- @field public zone_id st.zigbee.data_types.Uint8
local ZoneEnrollResponse = {}
ZoneEnrollResponse.NAME = "ZoneEnrollResponse"
ZoneEnrollResponse.ID = 0x00
ZoneEnrollResponse.args_def = {
  {
    name = "enroll_response_code",
    optional = false,
    data_type = EnrollResponseCodeType,
    is_complex = false,
    is_array = false,
  },
  {
    name = "zone_id",
    optional = false,
    data_type = data_types.Uint8,
    is_complex = false,
    is_array = false,
    default = 0x00,
  },
}

function ZoneEnrollResponse:get_fields()
  return cluster_base.command_get_fields(self)
end

ZoneEnrollResponse.get_length = utils.length_from_fields
ZoneEnrollResponse._serialize = utils.serialize_from_fields
ZoneEnrollResponse.pretty_print = utils.print_from_fields

--- Deserialize this command
---
--- @param buf buf the bytes of the command body
--- @return ZoneEnrollResponse
function ZoneEnrollResponse.deserialize(buf)
  return cluster_base.command_deserialize(ZoneEnrollResponse, buf)
end

function ZoneEnrollResponse:set_field_names()
  cluster_base.command_set_fields(self)
end

--- Build a version of this message as if it came from the device
---
--- @param device st.zigbee.Device the device to build the message from
--- @param enroll_response_code st.zigbee.zcl.clusters.IASZone.types.EnrollResponseCode
--- @param zone_id st.zigbee.data_types.Uint8
--- @return st.zigbee.ZigbeeMessageRx The full Zigbee message containing this command body
function ZoneEnrollResponse.build_test_rx(device, enroll_response_code, zone_id)
  local args = {enroll_response_code, zone_id}

  return cluster_base.command_build_test_rx(ZoneEnrollResponse, device, args, "server")
end

--- Initialize the ZoneEnrollResponse command
---
--- @param self ZoneEnrollResponse the template class for this command
--- @param device st.zigbee.Device the device to build this message to
--- @param enroll_response_code st.zigbee.zcl.clusters.IASZone.types.EnrollResponseCode
--- @param zone_id st.zigbee.data_types.Uint8
--- @return st.zigbee.ZigbeeMessageTx the full command addressed to the device
function ZoneEnrollResponse:init(device, enroll_response_code, zone_id)
  local args = {enroll_response_code, zone_id}

  return cluster_base.command_init(self, device, args, "server")
end

function ZoneEnrollResponse:set_parent_cluster(cluster)
  self._cluster = cluster
  return self
end

setmetatable(ZoneEnrollResponse, {__call = ZoneEnrollResponse.init})

return ZoneEnrollResponse
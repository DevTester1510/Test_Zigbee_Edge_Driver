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
-- ElectricalMeasurement command GetMeasurementProfile
-----------------------------------------------------------

--- @class st.zigbee.zcl.clusters.ElectricalMeasurement.GetMeasurementProfile
--- @alias GetMeasurementProfile
---
--- @field public ID number 0x01 the ID of this command
--- @field public NAME string "GetMeasurementProfile" the name of this command
--- @field public attribute_id st.zigbee.data_types.AttributeId
--- @field public start_time st.zigbee.data_types.UtcTime
--- @field public number_of_intervals st.zigbee.data_types.Uint8
local GetMeasurementProfile = {}
GetMeasurementProfile.NAME = "GetMeasurementProfile"
GetMeasurementProfile.ID = 0x01
GetMeasurementProfile.args_def = {
  {
    name = "attribute_id",
    optional = false,
    data_type = data_types.AttributeId,
    is_complex = false,
    is_array = false,
  },
  {
    name = "start_time",
    optional = false,
    data_type = data_types.UtcTime,
    is_complex = false,
    is_array = false,
  },
  {
    name = "number_of_intervals",
    optional = false,
    data_type = data_types.Uint8,
    is_complex = false,
    is_array = false,
    default = 0x00,
  },
}

function GetMeasurementProfile:get_fields()
  return cluster_base.command_get_fields(self)
end

GetMeasurementProfile.get_length = utils.length_from_fields
GetMeasurementProfile._serialize = utils.serialize_from_fields
GetMeasurementProfile.pretty_print = utils.print_from_fields

--- Deserialize this command
---
--- @param buf buf the bytes of the command body
--- @return GetMeasurementProfile
function GetMeasurementProfile.deserialize(buf)
  return cluster_base.command_deserialize(GetMeasurementProfile, buf)
end

function GetMeasurementProfile:set_field_names()
  cluster_base.command_set_fields(self)
end

--- Build a version of this message as if it came from the device
---
--- @param device st.zigbee.Device the device to build the message from
--- @param attribute_id st.zigbee.data_types.AttributeId
--- @param start_time st.zigbee.data_types.UtcTime
--- @param number_of_intervals st.zigbee.data_types.Uint8
--- @return st.zigbee.ZigbeeMessageRx The full Zigbee message containing this command body
function GetMeasurementProfile.build_test_rx(device, attribute_id, start_time, number_of_intervals)
  local args = {attribute_id, start_time, number_of_intervals}

  return cluster_base.command_build_test_rx(GetMeasurementProfile, device, args, "server")
end

--- Initialize the GetMeasurementProfile command
---
--- @param self GetMeasurementProfile the template class for this command
--- @param device st.zigbee.Device the device to build this message to
--- @param attribute_id st.zigbee.data_types.AttributeId
--- @param start_time st.zigbee.data_types.UtcTime
--- @param number_of_intervals st.zigbee.data_types.Uint8
--- @return st.zigbee.ZigbeeMessageTx the full command addressed to the device
function GetMeasurementProfile:init(device, attribute_id, start_time, number_of_intervals)
  local args = {attribute_id, start_time, number_of_intervals}

  return cluster_base.command_init(self, device, args, "server")
end

function GetMeasurementProfile:set_parent_cluster(cluster)
  self._cluster = cluster
  return self
end

setmetatable(GetMeasurementProfile, {__call = GetMeasurementProfile.init})

return GetMeasurementProfile
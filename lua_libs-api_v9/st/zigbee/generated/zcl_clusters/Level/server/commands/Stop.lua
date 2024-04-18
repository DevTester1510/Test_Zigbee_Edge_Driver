local data_types = require "st.zigbee.data_types"
local utils = require "st.zigbee.utils"
local log = require "log"
local cluster_base = require "st.zigbee.cluster_base"
local LevelOptionsType = require "st.zigbee.generated.zcl_clusters.Level.types.LevelOptions"

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
-- Level command Stop
-----------------------------------------------------------

--- @class st.zigbee.zcl.clusters.Level.Stop
--- @alias Stop
---
--- @field public ID number 0x03 the ID of this command
--- @field public NAME string "Stop" the name of this command
--- @field public options_mask st.zigbee.zcl.clusters.Level.types.LevelOptions
--- @field public options_override st.zigbee.zcl.clusters.Level.types.LevelOptions
local Stop = {}
Stop.NAME = "Stop"
Stop.ID = 0x03
Stop.args_def = {
  {
    name = "options_mask",
    optional = false,
    data_type = LevelOptionsType,
    is_complex = false,
    is_array = false,
    default = 0x00,
  },
  {
    name = "options_override",
    optional = false,
    data_type = LevelOptionsType,
    is_complex = false,
    is_array = false,
    default = 0x00,
  },
}

function Stop:get_fields()
  return cluster_base.command_get_fields(self)
end

Stop.get_length = utils.length_from_fields
Stop._serialize = utils.serialize_from_fields
Stop.pretty_print = utils.print_from_fields

--- Deserialize this command
---
--- @param buf buf the bytes of the command body
--- @return Stop
function Stop.deserialize(buf)
  return cluster_base.command_deserialize(Stop, buf)
end

function Stop:set_field_names()
  cluster_base.command_set_fields(self)
end

--- Build a version of this message as if it came from the device
---
--- @param device st.zigbee.Device the device to build the message from
--- @param options_mask st.zigbee.zcl.clusters.Level.types.LevelOptions
--- @param options_override st.zigbee.zcl.clusters.Level.types.LevelOptions
--- @return st.zigbee.ZigbeeMessageRx The full Zigbee message containing this command body
function Stop.build_test_rx(device, options_mask, options_override)
  local args = {options_mask, options_override}

  return cluster_base.command_build_test_rx(Stop, device, args, "server")
end

--- Initialize the Stop command
---
--- @param self Stop the template class for this command
--- @param device st.zigbee.Device the device to build this message to
--- @param options_mask st.zigbee.zcl.clusters.Level.types.LevelOptions
--- @param options_override st.zigbee.zcl.clusters.Level.types.LevelOptions
--- @return st.zigbee.ZigbeeMessageTx the full command addressed to the device
function Stop:init(device, options_mask, options_override)
  local args = {options_mask, options_override}

  return cluster_base.command_init(self, device, args, "server")
end

function Stop:set_parent_cluster(cluster)
  self._cluster = cluster
  return self
end

setmetatable(Stop, {__call = Stop.init})

return Stop
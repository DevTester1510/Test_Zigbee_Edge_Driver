local cluster_base = require "st.zigbee.cluster_base"
local BasicInputClientAttributes = require "st.zigbee.generated.zcl_clusters.BasicInput.client.attributes"
local BasicInputServerAttributes = require "st.zigbee.generated.zcl_clusters.BasicInput.server.attributes"
local BasicInputClientCommands = require "st.zigbee.generated.zcl_clusters.BasicInput.client.commands"
local BasicInputServerCommands = require "st.zigbee.generated.zcl_clusters.BasicInput.server.commands"
local BasicInputTypes = require "st.zigbee.generated.zcl_clusters.BasicInput.types"

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
-- This is generated from an incomplete definition and is not a complete description of the cluster.

--- @class st.zigbee.zcl.clusters.BasicInput
--- @alias BasicInput
---
--- @field public ID number 0x000f the ID of this cluster
--- @field public NAME string "BasicInput" the name of this cluster
--- @field public attributes st.zigbee.zcl.clusters.BasicInputServerAttributes | st.zigbee.zcl.clusters.BasicInputClientAttributes
--- @field public commands st.zigbee.zcl.clusters.BasicInputServerCommands | st.zigbee.zcl.clusters.BasicInputClientCommands
--- @field public types st.zigbee.zcl.clusters.BasicInputTypes
local BasicInput = {}

BasicInput.ID = 0x000f
BasicInput.NAME = "BasicInput"
BasicInput.server = {}
BasicInput.client = {}
BasicInput.server.attributes = BasicInputServerAttributes:set_parent_cluster(BasicInput)
BasicInput.client.attributes = BasicInputClientAttributes:set_parent_cluster(BasicInput)
BasicInput.server.commands = BasicInputServerCommands:set_parent_cluster(BasicInput)
BasicInput.client.commands = BasicInputClientCommands:set_parent_cluster(BasicInput)
BasicInput.types = BasicInputTypes

function BasicInput.attr_id_map()
    return {
    [0x0004] = "ActiveText",
    [0x001C] = "Description",
    [0x002E] = "InactiveText",
    [0x0051] = "OutOfService",
    [0x0054] = "Polarity",
    [0x0055] = "PresentValue",
    [0x0067] = "Reliability",
    [0x006F] = "StatusFlags",
    [0x0100] = "ApplicationType",
  }
end

function BasicInput.server_id_map()
    return {
  }
end

function BasicInput.client_id_map()
    return {
  }
end

BasicInput.attribute_direction_map = {
  ["ActiveText"] = "server",
  ["Description"] = "server",
  ["InactiveText"] = "server",
  ["OutOfService"] = "server",
  ["Polarity"] = "server",
  ["PresentValue"] = "server",
  ["Reliability"] = "server",
  ["StatusFlags"] = "server",
  ["ApplicationType"] = "server",
}
BasicInput.command_direction_map = {}

setmetatable(BasicInput, {__index = cluster_base})

BasicInput:init_attributes_table()
BasicInput:init_commands_table()

return BasicInput

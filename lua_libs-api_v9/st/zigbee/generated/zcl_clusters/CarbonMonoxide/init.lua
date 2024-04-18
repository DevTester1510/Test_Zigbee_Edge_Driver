local cluster_base = require "st.zigbee.cluster_base"
local CarbonMonoxideClientAttributes = require "st.zigbee.generated.zcl_clusters.CarbonMonoxide.client.attributes"
local CarbonMonoxideServerAttributes = require "st.zigbee.generated.zcl_clusters.CarbonMonoxide.server.attributes"
local CarbonMonoxideClientCommands = require "st.zigbee.generated.zcl_clusters.CarbonMonoxide.client.commands"
local CarbonMonoxideServerCommands = require "st.zigbee.generated.zcl_clusters.CarbonMonoxide.server.commands"
local CarbonMonoxideTypes = require "st.zigbee.generated.zcl_clusters.CarbonMonoxide.types"

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

--- @class st.zigbee.zcl.clusters.CarbonMonoxide
--- @alias CarbonMonoxide
---
--- @field public ID number 0x040C the ID of this cluster
--- @field public NAME string "CarbonMonoxide" the name of this cluster
--- @field public attributes st.zigbee.zcl.clusters.CarbonMonoxideServerAttributes | st.zigbee.zcl.clusters.CarbonMonoxideClientAttributes
--- @field public commands st.zigbee.zcl.clusters.CarbonMonoxideServerCommands | st.zigbee.zcl.clusters.CarbonMonoxideClientCommands
--- @field public types st.zigbee.zcl.clusters.CarbonMonoxideTypes
local CarbonMonoxide = {}

CarbonMonoxide.ID = 0x040C
CarbonMonoxide.NAME = "CarbonMonoxide"
CarbonMonoxide.server = {}
CarbonMonoxide.client = {}
CarbonMonoxide.server.attributes = CarbonMonoxideServerAttributes:set_parent_cluster(CarbonMonoxide)
CarbonMonoxide.client.attributes = CarbonMonoxideClientAttributes:set_parent_cluster(CarbonMonoxide)
CarbonMonoxide.server.commands = CarbonMonoxideServerCommands:set_parent_cluster(CarbonMonoxide)
CarbonMonoxide.client.commands = CarbonMonoxideClientCommands:set_parent_cluster(CarbonMonoxide)
CarbonMonoxide.types = CarbonMonoxideTypes

function CarbonMonoxide.attr_id_map()
    return {
    [0x0000] = "MeasuredValue",
    [0x0001] = "MinMeasuredValue",
    [0x0002] = "MaxMeasuredValue",
    [0x0003] = "Tolerance",
  }
end

function CarbonMonoxide.server_id_map()
    return {
  }
end

function CarbonMonoxide.client_id_map()
    return {
  }
end

CarbonMonoxide.attribute_direction_map = {
  ["MeasuredValue"] = "server",
  ["MinMeasuredValue"] = "server",
  ["MaxMeasuredValue"] = "server",
  ["Tolerance"] = "server",
}
CarbonMonoxide.command_direction_map = {}

setmetatable(CarbonMonoxide, {__index = cluster_base})

CarbonMonoxide:init_attributes_table()
CarbonMonoxide:init_commands_table()

return CarbonMonoxide
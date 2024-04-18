local cluster_base = require "st.zigbee.cluster_base"
local MeterIdentificationClientAttributes = require "st.zigbee.generated.zcl_clusters.MeterIdentification.client.attributes"
local MeterIdentificationServerAttributes = require "st.zigbee.generated.zcl_clusters.MeterIdentification.server.attributes"
local MeterIdentificationClientCommands = require "st.zigbee.generated.zcl_clusters.MeterIdentification.client.commands"
local MeterIdentificationServerCommands = require "st.zigbee.generated.zcl_clusters.MeterIdentification.server.commands"
local MeterIdentificationTypes = require "st.zigbee.generated.zcl_clusters.MeterIdentification.types"

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

--- @class st.zigbee.zcl.clusters.MeterIdentification
--- @alias MeterIdentification
---
--- @field public ID number 0x0B01 the ID of this cluster
--- @field public NAME string "MeterIdentification" the name of this cluster
--- @field public attributes st.zigbee.zcl.clusters.MeterIdentificationServerAttributes | st.zigbee.zcl.clusters.MeterIdentificationClientAttributes
--- @field public commands st.zigbee.zcl.clusters.MeterIdentificationServerCommands | st.zigbee.zcl.clusters.MeterIdentificationClientCommands
--- @field public types st.zigbee.zcl.clusters.MeterIdentificationTypes
local MeterIdentification = {}

MeterIdentification.ID = 0x0B01
MeterIdentification.NAME = "MeterIdentification"
MeterIdentification.server = {}
MeterIdentification.client = {}
MeterIdentification.server.attributes = MeterIdentificationServerAttributes:set_parent_cluster(MeterIdentification)
MeterIdentification.client.attributes = MeterIdentificationClientAttributes:set_parent_cluster(MeterIdentification)
MeterIdentification.server.commands = MeterIdentificationServerCommands:set_parent_cluster(MeterIdentification)
MeterIdentification.client.commands = MeterIdentificationClientCommands:set_parent_cluster(MeterIdentification)
MeterIdentification.types = MeterIdentificationTypes

function MeterIdentification.attr_id_map()
    return {
    [0x0000] = "CompanyName",
    [0x0001] = "MeterTypeID",
    [0x0004] = "DataQualityID",
    [0x0005] = "CustomerName",
    [0x0006] = "Model",
    [0x0007] = "PartNumber",
    [0x0008] = "ProductRevision",
    [0x000A] = "SoftwareRevision",
    [0x000B] = "UtilityName",
    [0x000C] = "POD",
    [0x000D] = "AvailablePower",
    [0x000E] = "PowerThreshold",
  }
end

function MeterIdentification.server_id_map()
    return {
  }
end

function MeterIdentification.client_id_map()
    return {
  }
end

MeterIdentification.attribute_direction_map = {
  ["CompanyName"] = "server",
  ["MeterTypeID"] = "server",
  ["DataQualityID"] = "server",
  ["CustomerName"] = "server",
  ["Model"] = "server",
  ["PartNumber"] = "server",
  ["ProductRevision"] = "server",
  ["SoftwareRevision"] = "server",
  ["UtilityName"] = "server",
  ["POD"] = "server",
  ["AvailablePower"] = "server",
  ["PowerThreshold"] = "server",
}
MeterIdentification.command_direction_map = {}

setmetatable(MeterIdentification, {__index = cluster_base})

MeterIdentification:init_attributes_table()
MeterIdentification:init_commands_table()

return MeterIdentification

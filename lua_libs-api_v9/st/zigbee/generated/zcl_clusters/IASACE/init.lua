local cluster_base = require "st.zigbee.cluster_base"
local IASACEClientAttributes = require "st.zigbee.generated.zcl_clusters.IASACE.client.attributes"
local IASACEServerAttributes = require "st.zigbee.generated.zcl_clusters.IASACE.server.attributes"
local IASACEClientCommands = require "st.zigbee.generated.zcl_clusters.IASACE.client.commands"
local IASACEServerCommands = require "st.zigbee.generated.zcl_clusters.IASACE.server.commands"
local IASACETypes = require "st.zigbee.generated.zcl_clusters.IASACE.types"

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

--- @class st.zigbee.zcl.clusters.IASACE
--- @alias IASACE
---
--- @field public ID number 0x0501 the ID of this cluster
--- @field public NAME string "IASACE" the name of this cluster
--- @field public attributes st.zigbee.zcl.clusters.IASACEServerAttributes | st.zigbee.zcl.clusters.IASACEClientAttributes
--- @field public commands st.zigbee.zcl.clusters.IASACEServerCommands | st.zigbee.zcl.clusters.IASACEClientCommands
--- @field public types st.zigbee.zcl.clusters.IASACETypes
local IASACE = {}

IASACE.ID = 0x0501
IASACE.NAME = "IASACE"
IASACE.server = {}
IASACE.client = {}
IASACE.server.attributes = IASACEServerAttributes:set_parent_cluster(IASACE)
IASACE.client.attributes = IASACEClientAttributes:set_parent_cluster(IASACE)
IASACE.server.commands = IASACEServerCommands:set_parent_cluster(IASACE)
IASACE.client.commands = IASACEClientCommands:set_parent_cluster(IASACE)
IASACE.types = IASACETypes

function IASACE.attr_id_map()
    return {
  }
end

function IASACE.server_id_map()
    return {
    [0x00] = "Arm",
    [0x01] = "Bypass",
    [0x02] = "Emergency",
    [0x03] = "Fire",
    [0x04] = "Panic",
    [0x05] = "GetZoneIDMap",
    [0x06] = "GetZoneInformation",
    [0x07] = "GetPanelStatus",
    [0x08] = "GetBypassedZoneList",
    [0x09] = "GetZoneStatus",
  }
end

function IASACE.client_id_map()
    return {
    [0x00] = "ArmResponse",
    [0x01] = "GetZoneIDMapResponse",
    [0x02] = "GetZoneInformationResponse",
    [0x03] = "ZoneStatusChanged",
    [0x04] = "PanelStatusChanged",
    [0x05] = "GetPanelStatusResponse",
    [0x06] = "SetBypassedZoneList",
    [0x07] = "BypassResponse",
    [0x08] = "GetZoneStatusResponse",
  }
end

IASACE.attribute_direction_map = {}
IASACE.command_direction_map = {
  ["ArmResponse"] = "client",
  ["GetZoneIDMapResponse"] = "client",
  ["GetZoneInformationResponse"] = "client",
  ["ZoneStatusChanged"] = "client",
  ["PanelStatusChanged"] = "client",
  ["GetPanelStatusResponse"] = "client",
  ["SetBypassedZoneList"] = "client",
  ["BypassResponse"] = "client",
  ["GetZoneStatusResponse"] = "client",
  ["Arm"] = "server",
  ["Bypass"] = "server",
  ["Emergency"] = "server",
  ["Fire"] = "server",
  ["Panic"] = "server",
  ["GetZoneIDMap"] = "server",
  ["GetZoneInformation"] = "server",
  ["GetPanelStatus"] = "server",
  ["GetBypassedZoneList"] = "server",
  ["GetZoneStatus"] = "server",
}

setmetatable(IASACE, {__index = cluster_base})

IASACE:init_attributes_table()
IASACE:init_commands_table()

return IASACE
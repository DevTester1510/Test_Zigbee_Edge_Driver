local cluster_base = require "st.zigbee.cluster_base"
local DiagnosticsClientAttributes = require "st.zigbee.generated.zcl_clusters.Diagnostics.client.attributes"
local DiagnosticsServerAttributes = require "st.zigbee.generated.zcl_clusters.Diagnostics.server.attributes"
local DiagnosticsClientCommands = require "st.zigbee.generated.zcl_clusters.Diagnostics.client.commands"
local DiagnosticsServerCommands = require "st.zigbee.generated.zcl_clusters.Diagnostics.server.commands"
local DiagnosticsTypes = require "st.zigbee.generated.zcl_clusters.Diagnostics.types"

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

--- @class st.zigbee.zcl.clusters.Diagnostics
--- @alias Diagnostics
---
--- @field public ID number 0x0B05 the ID of this cluster
--- @field public NAME string "Diagnostics" the name of this cluster
--- @field public attributes st.zigbee.zcl.clusters.DiagnosticsServerAttributes | st.zigbee.zcl.clusters.DiagnosticsClientAttributes
--- @field public commands st.zigbee.zcl.clusters.DiagnosticsServerCommands | st.zigbee.zcl.clusters.DiagnosticsClientCommands
--- @field public types st.zigbee.zcl.clusters.DiagnosticsTypes
local Diagnostics = {}

Diagnostics.ID = 0x0B05
Diagnostics.NAME = "Diagnostics"
Diagnostics.server = {}
Diagnostics.client = {}
Diagnostics.server.attributes = DiagnosticsServerAttributes:set_parent_cluster(Diagnostics)
Diagnostics.client.attributes = DiagnosticsClientAttributes:set_parent_cluster(Diagnostics)
Diagnostics.server.commands = DiagnosticsServerCommands:set_parent_cluster(Diagnostics)
Diagnostics.client.commands = DiagnosticsClientCommands:set_parent_cluster(Diagnostics)
Diagnostics.types = DiagnosticsTypes

function Diagnostics.attr_id_map()
    return {
    [0x0000] = "NumberOfResets",
    [0x0001] = "PersistentMemoryWrites",
    [0x0100] = "MacRxBcast",
    [0x0101] = "MacTxBcast",
    [0x0102] = "MacRxUcast",
    [0x0103] = "MacTxUcast",
    [0x0104] = "MacTxUcastRetry",
    [0x0105] = "MacTxUcastFail",
    [0x0106] = "APSRxBcast",
    [0x0107] = "APSTxBcast",
    [0x0108] = "APSRxUcast",
    [0x0109] = "APSTxUcastSuccess",
    [0x010A] = "APSTxUcastRetry",
    [0x010B] = "APSTxUcastFail",
    [0x010C] = "RouteDiscInitiated",
    [0x010D] = "NeighborAdded",
    [0x010E] = "NeighborRemoved",
    [0x010F] = "NeighborStale",
    [0x0110] = "JoinIndication",
    [0x0111] = "ChildMoved",
    [0x0112] = "NWKFCFailure",
    [0x0113] = "APSFCFailure",
    [0x0114] = "APSUnauthorizedKey",
    [0x0115] = "NWKDecryptFailures",
    [0x0116] = "APSDecryptFailures",
    [0x0117] = "PacketBufferAllocateFailures",
    [0x0118] = "RelayedUcast",
    [0x0119] = "PHYToMACQueueLimitReached",
    [0x011A] = "PacketValidateDropCount",
    [0x011B] = "AverageMACRetryPerAPSMessageSent",
    [0x011C] = "LastMessageLQI",
    [0x011D] = "LastMessageRSSI",
  }
end

function Diagnostics.server_id_map()
    return {
  }
end

function Diagnostics.client_id_map()
    return {
  }
end

Diagnostics.attribute_direction_map = {
  ["NumberOfResets"] = "server",
  ["PersistentMemoryWrites"] = "server",
  ["MacRxBcast"] = "server",
  ["MacTxBcast"] = "server",
  ["MacRxUcast"] = "server",
  ["MacTxUcast"] = "server",
  ["MacTxUcastRetry"] = "server",
  ["MacTxUcastFail"] = "server",
  ["APSRxBcast"] = "server",
  ["APSTxBcast"] = "server",
  ["APSRxUcast"] = "server",
  ["APSTxUcastSuccess"] = "server",
  ["APSTxUcastRetry"] = "server",
  ["APSTxUcastFail"] = "server",
  ["RouteDiscInitiated"] = "server",
  ["NeighborAdded"] = "server",
  ["NeighborRemoved"] = "server",
  ["NeighborStale"] = "server",
  ["JoinIndication"] = "server",
  ["ChildMoved"] = "server",
  ["NWKFCFailure"] = "server",
  ["APSFCFailure"] = "server",
  ["APSUnauthorizedKey"] = "server",
  ["NWKDecryptFailures"] = "server",
  ["APSDecryptFailures"] = "server",
  ["PacketBufferAllocateFailures"] = "server",
  ["RelayedUcast"] = "server",
  ["PHYToMACQueueLimitReached"] = "server",
  ["PacketValidateDropCount"] = "server",
  ["AverageMACRetryPerAPSMessageSent"] = "server",
  ["LastMessageLQI"] = "server",
  ["LastMessageRSSI"] = "server",
}
Diagnostics.command_direction_map = {}

setmetatable(Diagnostics, {__index = cluster_base})

Diagnostics:init_attributes_table()
Diagnostics:init_commands_table()

return Diagnostics

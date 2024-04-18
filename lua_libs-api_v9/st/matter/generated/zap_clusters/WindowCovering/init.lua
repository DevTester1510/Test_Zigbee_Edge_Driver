-- Copyright 2022 SmartThings
--
-- Licensed under the Apache License, Version 2.0 (the "License");
-- you may not use this file except in compliance with the License.
-- You may obtain a copy of the License at
--
-- http://www.apache.org/licenses/LICENSE-2.0
--
-- Unless required by applicable law or agreed to in writing, software
-- distributed under the License is distributed on an "AS IS" BASIS,
-- WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
-- See the License for the specific language governing permissions and
-- limitations under the License.

-- DO NOT EDIT: this code is automatically generated by ZCL Advanced Platform generator.

local cluster_base = require "st.matter.cluster_base"
local WindowCoveringServerAttributes = require "st.matter.generated.zap_clusters.WindowCovering.server.attributes"
local WindowCoveringServerCommands = require "st.matter.generated.zap_clusters.WindowCovering.server.commands"
local WindowCoveringTypes = require "st.matter.generated.zap_clusters.WindowCovering.types"

--- @class st.matter.generated.zap_clusters.WindowCovering
--- @alias WindowCovering
---
--- @field public ID number 0x0102 the ID of this cluster
--- @field public NAME string "WindowCovering" the name of this cluster
--- @field public attributes st.matter.generated.zap_clusters.WindowCoveringServerAttributes | st.matter.generated.zap_clusters.WindowCoveringClientAttributes
--- @field public commands st.matter.generated.zap_clusters.WindowCoveringServerCommands | st.matter.generated.zap_clusters.WindowCoveringClientCommands
--- @field public types st.matter.generated.zap_clusters.WindowCoveringTypes

local WindowCovering = {}

WindowCovering.ID = 0x0102
WindowCovering.NAME = "WindowCovering"
WindowCovering.server = {}
WindowCovering.client = {}
WindowCovering.server.attributes = WindowCoveringServerAttributes:set_parent_cluster(WindowCovering)
WindowCovering.server.commands = WindowCoveringServerCommands:set_parent_cluster(WindowCovering)
WindowCovering.types = WindowCoveringTypes

-- Global Attributes Metadata
local GLOBAL_CLUSTER_REVISION_ATTRIBUTE = 0xFFFD

-- Represent the global attributes
local global_attr_id_map = {
  [GLOBAL_CLUSTER_REVISION_ATTRIBUTE] = {"cluster revision"},
}

--- Find an attribute by id
---
--- @param attr_id number
function WindowCovering:get_attribute_by_id(attr_id)
  local attr_id_map = {
    [0x0000] = "Type",
    [0x0001] = "PhysicalClosedLimitLift",
    [0x0002] = "PhysicalClosedLimitTilt",
    [0x0003] = "CurrentPositionLift",
    [0x0004] = "CurrentPositionTilt",
    [0x0005] = "NumberOfActuationsLift",
    [0x0006] = "NumberOfActuationsTilt",
    [0x0007] = "ConfigStatus",
    [0x0008] = "CurrentPositionLiftPercentage",
    [0x0009] = "CurrentPositionTiltPercentage",
    [0x000A] = "OperationalStatus",
    [0x000B] = "TargetPositionLiftPercent100ths",
    [0x000C] = "TargetPositionTiltPercent100ths",
    [0x000D] = "EndProductType",
    [0x000E] = "CurrentPositionLiftPercent100ths",
    [0x000F] = "CurrentPositionTiltPercent100ths",
    [0x0010] = "InstalledOpenLimitLift",
    [0x0011] = "InstalledClosedLimitLift",
    [0x0012] = "InstalledOpenLimitTilt",
    [0x0013] = "InstalledClosedLimitTilt",
    [0x0017] = "Mode",
    [0x001A] = "SafetyStatus",
    [0xFFF9] = "AcceptedCommandList",
    [0xFFFB] = "AttributeList",
  }
  local attr_name = attr_id_map[attr_id]
  if attr_name ~= nil then
    return self.attributes[attr_name]
  end
  return nil
end

--- Find a server command by id
---
--- @param command_id number
function WindowCovering:get_server_command_by_id(command_id)
  local server_id_map = {
    [0x0000] = "UpOrOpen",
    [0x0001] = "DownOrClose",
    [0x0002] = "StopMotion",
    [0x0004] = "GoToLiftValue",
    [0x0005] = "GoToLiftPercentage",
    [0x0007] = "GoToTiltValue",
    [0x0008] = "GoToTiltPercentage",
  }
  if server_id_map[command_id] ~= nil then
    return self.server.commands[server_id_map[command_id]]
  end
  return nil
end


-- Attribute Mapping
WindowCovering.attribute_direction_map = {
  ["Type"] = "server",
  ["PhysicalClosedLimitLift"] = "server",
  ["PhysicalClosedLimitTilt"] = "server",
  ["CurrentPositionLift"] = "server",
  ["CurrentPositionTilt"] = "server",
  ["NumberOfActuationsLift"] = "server",
  ["NumberOfActuationsTilt"] = "server",
  ["ConfigStatus"] = "server",
  ["CurrentPositionLiftPercentage"] = "server",
  ["CurrentPositionTiltPercentage"] = "server",
  ["OperationalStatus"] = "server",
  ["TargetPositionLiftPercent100ths"] = "server",
  ["TargetPositionTiltPercent100ths"] = "server",
  ["EndProductType"] = "server",
  ["CurrentPositionLiftPercent100ths"] = "server",
  ["CurrentPositionTiltPercent100ths"] = "server",
  ["InstalledOpenLimitLift"] = "server",
  ["InstalledClosedLimitLift"] = "server",
  ["InstalledOpenLimitTilt"] = "server",
  ["InstalledClosedLimitTilt"] = "server",
  ["Mode"] = "server",
  ["SafetyStatus"] = "server",
  ["AcceptedCommandList"] = "server",
  ["AttributeList"] = "server",
}

-- Command Mapping
WindowCovering.command_direction_map = {
  ["UpOrOpen"] = "server",
  ["DownOrClose"] = "server",
  ["StopMotion"] = "server",
  ["GoToLiftValue"] = "server",
  ["GoToLiftPercentage"] = "server",
  ["GoToTiltValue"] = "server",
  ["GoToTiltPercentage"] = "server",
}

-- Cluster Completion
local attribute_helper_mt = {}
attribute_helper_mt.__index = function(self, key)
  local direction = WindowCovering.attribute_direction_map[key]
  if direction == nil then
    error(string.format("Referenced unknown attribute %s on cluster %s", key, WindowCovering.NAME))
  end
  return WindowCovering[direction].attributes[key]
end
WindowCovering.attributes = {}
setmetatable(WindowCovering.attributes, attribute_helper_mt)

local command_helper_mt = {}
command_helper_mt.__index = function(self, key)
  local direction = WindowCovering.command_direction_map[key]
  if direction == nil then
    error(string.format("Referenced unknown command %s on cluster %s", key, WindowCovering.NAME))
  end
  return WindowCovering[direction].commands[key] 
end
WindowCovering.commands = {}
setmetatable(WindowCovering.commands, command_helper_mt)

local event_helper_mt = {}
event_helper_mt.__index = function(self, key)
  return WindowCovering.server.events[key]
end
WindowCovering.events = {}
setmetatable(WindowCovering.events, event_helper_mt)

setmetatable(WindowCovering, {__index = cluster_base})  

return WindowCovering


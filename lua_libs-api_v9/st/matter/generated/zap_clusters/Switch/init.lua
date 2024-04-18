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
local SwitchServerAttributes = require "st.matter.generated.zap_clusters.Switch.server.attributes"
local SwitchServerCommands = require "st.matter.generated.zap_clusters.Switch.server.commands"
local SwitchEvents = require "st.matter.generated.zap_clusters.Switch.server.events"
local SwitchTypes = require "st.matter.generated.zap_clusters.Switch.types"

--- @class st.matter.generated.zap_clusters.Switch
--- @alias Switch
---
--- @field public ID number 0x003B the ID of this cluster
--- @field public NAME string "Switch" the name of this cluster
--- @field public attributes st.matter.generated.zap_clusters.SwitchServerAttributes | st.matter.generated.zap_clusters.SwitchClientAttributes
--- @field public commands st.matter.generated.zap_clusters.SwitchServerCommands | st.matter.generated.zap_clusters.SwitchClientCommands
--- @field public types st.matter.generated.zap_clusters.SwitchTypes

local Switch = {}

Switch.ID = 0x003B
Switch.NAME = "Switch"
Switch.server = {}
Switch.client = {}
Switch.server.attributes = SwitchServerAttributes:set_parent_cluster(Switch)
Switch.server.commands = SwitchServerCommands:set_parent_cluster(Switch)
Switch.server.events = SwitchEvents:set_parent_cluster(Switch)
Switch.types = SwitchTypes

-- Global Attributes Metadata
local GLOBAL_CLUSTER_REVISION_ATTRIBUTE = 0xFFFD

-- Represent the global attributes
local global_attr_id_map = {
  [GLOBAL_CLUSTER_REVISION_ATTRIBUTE] = {"cluster revision"},
}

--- Find an attribute by id
---
--- @param attr_id number
function Switch:get_attribute_by_id(attr_id)
  local attr_id_map = {
    [0x0000] = "NumberOfPositions",
    [0x0001] = "CurrentPosition",
    [0x0002] = "MultiPressMax",
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
function Switch:get_server_command_by_id(command_id)
  local server_id_map = {
  }
  if server_id_map[command_id] ~= nil then
    return self.server.commands[server_id_map[command_id]]
  end
  return nil
end


--- Find an event by id
---
--- @param event_id number
function Switch:get_event_by_id(event_id)
  local event_id_map = {
    [0x0000] = "SwitchLatched",
    [0x0001] = "InitialPress",
    [0x0002] = "LongPress",
    [0x0003] = "ShortRelease",
    [0x0004] = "LongRelease",
    [0x0005] = "MultiPressOngoing",
    [0x0006] = "MultiPressComplete",
  }
  if event_id_map[event_id] ~= nil then
    return self.server.events[event_id_map[event_id]]
  end
  return nil
end
-- Attribute Mapping
Switch.attribute_direction_map = {
  ["NumberOfPositions"] = "server",
  ["CurrentPosition"] = "server",
  ["MultiPressMax"] = "server",
  ["AcceptedCommandList"] = "server",
  ["AttributeList"] = "server",
}

-- Command Mapping
Switch.command_direction_map = {
}

Switch.FeatureMap = Switch.types.SwitchFeature

function Switch.are_features_supported(feature, feature_map)
  if (Switch.FeatureMap.bits_are_valid(feature)) then
    return (feature & feature_map) == feature
  end
  return false
end

-- Cluster Completion
local attribute_helper_mt = {}
attribute_helper_mt.__index = function(self, key)
  local direction = Switch.attribute_direction_map[key]
  if direction == nil then
    error(string.format("Referenced unknown attribute %s on cluster %s", key, Switch.NAME))
  end
  return Switch[direction].attributes[key]
end
Switch.attributes = {}
setmetatable(Switch.attributes, attribute_helper_mt)

local command_helper_mt = {}
command_helper_mt.__index = function(self, key)
  local direction = Switch.command_direction_map[key]
  if direction == nil then
    error(string.format("Referenced unknown command %s on cluster %s", key, Switch.NAME))
  end
  return Switch[direction].commands[key] 
end
Switch.commands = {}
setmetatable(Switch.commands, command_helper_mt)

local event_helper_mt = {}
event_helper_mt.__index = function(self, key)
  return Switch.server.events[key]
end
Switch.events = {}
setmetatable(Switch.events, event_helper_mt)

setmetatable(Switch, {__index = cluster_base})  

return Switch


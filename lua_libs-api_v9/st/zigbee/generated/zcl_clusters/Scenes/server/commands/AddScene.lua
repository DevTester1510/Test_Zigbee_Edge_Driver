local data_types = require "st.zigbee.data_types"
local utils = require "st.zigbee.utils"
local log = require "log"
local cluster_base = require "st.zigbee.cluster_base"
local SExtensionFieldSetListType = require "st.zigbee.generated.zcl_clusters.Scenes.types.SExtensionFieldSetList"
local SSceneNameType = require "st.zigbee.generated.zcl_clusters.Scenes.types.SSceneName"
local SGroupIdType = require "st.zigbee.generated.zcl_clusters.Scenes.types.SGroupId"

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
-- Scenes command AddScene
-----------------------------------------------------------

--- @class st.zigbee.zcl.clusters.Scenes.AddScene
--- @alias AddScene
---
--- @field public ID number 0x00 the ID of this command
--- @field public NAME string "AddScene" the name of this command
--- @field public group_id st.zigbee.zcl.clusters.Scenes.types.SGroupId
--- @field public scene_id st.zigbee.data_types.Uint8
--- @field public transition_time st.zigbee.data_types.Uint16
--- @field public scene_name st.zigbee.zcl.clusters.Scenes.types.SSceneName
--- @field public extension_field_sets_list st.zigbee.zcl.clusters.Scenes.types.SExtensionFieldSetList[]
local AddScene = {}
AddScene.NAME = "AddScene"
AddScene.ID = 0x00
AddScene.args_def = {
  {
    name = "group_id",
    optional = false,
    data_type = SGroupIdType,
    is_complex = false,
    is_array = false,
    default = 0x0000,
  },
  {
    name = "scene_id",
    optional = false,
    data_type = data_types.Uint8,
    is_complex = false,
    is_array = false,
    default = 0x00,
  },
  {
    name = "transition_time",
    optional = false,
    data_type = data_types.Uint16,
    is_complex = false,
    is_array = false,
    default = 0x0000,
  },
  {
    name = "scene_name",
    optional = false,
    data_type = SSceneNameType,
    is_complex = false,
    is_array = false,
    default = "",
  },
  {
    name = "extension_field_sets",
    optional = false,
    data_type = SExtensionFieldSetListType,
    is_complex = false,
    is_array = true,
    array_length_size = 0,
  },
}

function AddScene:get_fields()
  return cluster_base.command_get_fields(self)
end

AddScene.get_length = utils.length_from_fields
AddScene._serialize = utils.serialize_from_fields
AddScene.pretty_print = utils.print_from_fields

--- Deserialize this command
---
--- @param buf buf the bytes of the command body
--- @return AddScene
function AddScene.deserialize(buf)
  return cluster_base.command_deserialize(AddScene, buf)
end

function AddScene:set_field_names()
  cluster_base.command_set_fields(self)
end

--- Build a version of this message as if it came from the device
---
--- @param device st.zigbee.Device the device to build the message from
--- @param group_id st.zigbee.zcl.clusters.Scenes.types.SGroupId
--- @param scene_id st.zigbee.data_types.Uint8
--- @param transition_time st.zigbee.data_types.Uint16
--- @param scene_name st.zigbee.zcl.clusters.Scenes.types.SSceneName
--- @param extension_field_sets st.zigbee.zcl.clusters.Scenes.types.SExtensionFieldSetList[]
--- @return st.zigbee.ZigbeeMessageRx The full Zigbee message containing this command body
function AddScene.build_test_rx(device, group_id, scene_id, transition_time, scene_name, extension_field_sets)
  local args = {group_id, scene_id, transition_time, scene_name, extension_field_sets}

  return cluster_base.command_build_test_rx(AddScene, device, args, "server")
end

--- Initialize the AddScene command
---
--- @param self AddScene the template class for this command
--- @param device st.zigbee.Device the device to build this message to
--- @param group_id st.zigbee.zcl.clusters.Scenes.types.SGroupId
--- @param scene_id st.zigbee.data_types.Uint8
--- @param transition_time st.zigbee.data_types.Uint16
--- @param scene_name st.zigbee.zcl.clusters.Scenes.types.SSceneName
--- @param extension_field_sets st.zigbee.zcl.clusters.Scenes.types.SExtensionFieldSetList[]
--- @return st.zigbee.ZigbeeMessageTx the full command addressed to the device
function AddScene:init(device, group_id, scene_id, transition_time, scene_name, extension_field_sets)
  local args = {group_id, scene_id, transition_time, scene_name, extension_field_sets}

  return cluster_base.command_init(self, device, args, "server")
end

function AddScene:set_parent_cluster(cluster)
  self._cluster = cluster
  return self
end

setmetatable(AddScene, {__call = AddScene.init})

return AddScene
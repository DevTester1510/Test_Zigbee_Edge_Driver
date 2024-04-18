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

local data_types = require "st.matter.data_types"
local log = require "log"
local TLVParser = require "st.matter.TLV.TLVParser"
local MediaPlaybackStatusEnumType = require "st.matter.generated.zap_clusters.MediaPlayback.types.MediaPlaybackStatusEnum"

-----------------------------------------------------------
-- MediaPlayback command PlaybackResponse
-----------------------------------------------------------

--- @class st.matter.clusters.MediaPlayback.PlaybackResponse
--- @alias PlaybackResponse
---
--- @field public ID number 0x000A the ID of this command
--- @field public NAME string "PlaybackResponse" the name of this command
--- @field public status st.matter.clusters.MediaPlayback.types.MediaPlaybackStatusEnum
--- @field public data data_types.UTF8String1
local PlaybackResponse = {}

PlaybackResponse.NAME = "PlaybackResponse"
PlaybackResponse.ID = 0x000A
PlaybackResponse.field_defs = {
  {
    name = "status",
    field_id = 0,
    optional = false,
    is_nullable = false,
    data_type = MediaPlaybackStatusEnumType,
  },
  {
    name = "data",
    field_id = 1,
    optional = true,
    is_nullable = false,
    data_type = data_types.UTF8String1,
  },
}

--- Add field names to each command field
---
--- @param base_type_obj st.matter.data_types.Structure
function PlaybackResponse:augment_type(base_type_obj)
  local elems = {}
  for _, v in ipairs(base_type_obj.elements) do
    for _, field_def in ipairs(self.field_defs) do
      if field_def.field_id == v.field_id and
         field_def.is_nullable and
         (v.value == nil and v.elements == nil) then
        elems[field_def.name] = data_types.validate_or_build_type(v, data_types.Null, field_def.field_name)
      elseif field_def.field_id == v.field_id and not
        (field_def.is_optional and v.value == nil) then
        elems[field_def.name] = data_types.validate_or_build_type(v, field_def.data_type, field_def.field_name)
        if field_def.array_type ~= nil then
          for i, e in ipairs(elems[field_def.name].elements) do
            elems[field_def.name].elements[i] = data_types.validate_or_build_type(e, field_def.array_type)
          end
        end
      end
    end
  end
  base_type_obj.elements = elems
end

--- Builds an PlaybackResponse test command reponse for the driver integration testing framework
---
--- @param device st.matter.Device the device to build this message to
--- @param endpoint_id number|nil
--- @param status st.matter.clusters.MediaPlayback.types.MediaPlaybackStatusEnum
--- @param data data_types.UTF8String1
--- @return st.matter.st.matter.interaction_model.InteractionResponse of type COMMAND_RESPONSE
function PlaybackResponse:build_test_command_response(device, endpoint_id, status, data, interaction_status)
  local function init(self, device, endpoint_id, status, data)
    local out = {}
    local args = {status, data}
    if #args > #self.field_defs then
      error(self.NAME .. " received too many arguments")
    end
    for i,v in ipairs(self.field_defs) do
      if v.optional and args[i] == nil then
        out[v.name] = nil
      elseif v.is_nullable and args[i] == nil then
        out[v.name] = data_types.validate_or_build_type(args[i], data_types.Null, v.name)
        out[v.name].field_id = v.field_id
      elseif not v.optional and args[i] == nil then
        out[v.name] = data_types.validate_or_build_type(v.default, v.data_type, v.name)
        out[v.name].field_id = v.field_id
      else
        out[v.name] = data_types.validate_or_build_type(args[i], v.data_type, v.name)
        out[v.name].field_id = v.field_id
      end
    end
    setmetatable(out, {
      __index = PlaybackResponse,
      __tostring = PlaybackResponse.pretty_print
    })
    return self._cluster:build_cluster_command(
      device,
      out,
      endpoint_id,
      self._cluster.ID,
      self.ID
    )
  end
  local self_request =  init(self, device, endpoint_id, status, data)
  return self._cluster:build_test_command_response(
    device,
    endpoint_id,
    self._cluster.ID,
    self.ID,
    self_request.info_blocks[1].tlv,
    interaction_status
  )
end

--- Initialize the PlaybackResponse command
---
--- @return nil
function PlaybackResponse:init()
  return nil
end

function PlaybackResponse:set_parent_cluster(cluster)
  self._cluster = cluster
  return self
end

function PlaybackResponse:deserialize(tlv_buf)
  local data = TLVParser.decode_tlv(tlv_buf)
  self:augment_type(data)
  return data
end

setmetatable(PlaybackResponse, {__call = PlaybackResponse.init})

return PlaybackResponse
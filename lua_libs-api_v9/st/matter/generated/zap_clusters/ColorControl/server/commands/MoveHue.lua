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
local HueMoveModeType = require "st.matter.generated.zap_clusters.ColorControl.types.HueMoveMode"

-----------------------------------------------------------
-- ColorControl command MoveHue
-----------------------------------------------------------

--- @class st.matter.clusters.ColorControl.MoveHue
--- @alias MoveHue
---
--- @field public ID number 0x0001 the ID of this command
--- @field public NAME string "MoveHue" the name of this command
--- @field public move_mode st.matter.clusters.ColorControl.types.HueMoveMode
--- @field public rate data_types.Uint8
--- @field public options_mask data_types.Uint8
--- @field public options_override data_types.Uint8
local MoveHue = {}

MoveHue.NAME = "MoveHue"
MoveHue.ID = 0x0001
MoveHue.field_defs = {
  {
    name = "move_mode",
    field_id = 0,
    optional = false,
    nullable = false,
    data_type = HueMoveModeType,
  },
  {
    name = "rate",
    field_id = 1,
    optional = false,
    nullable = false,
    data_type = data_types.Uint8,
  },
  {
    name = "options_mask",
    field_id = 2,
    optional = false,
    nullable = false,
    data_type = data_types.Uint8,
  },
  {
    name = "options_override",
    field_id = 3,
    optional = false,
    nullable = false,
    data_type = data_types.Uint8,
  },
}

--- Builds an MoveHue test command reponse for the driver integration testing framework
---
--- @param device st.matter.Device the device to build this message to
--- @param endpoint_id number|nil
--- @param status string Interaction status associated with the path
--- @return st.matter.st.matter.interaction_model.InteractionResponse of type COMMAND_RESPONSE
function MoveHue:build_test_command_response(device, endpoint_id, status)
  return self._cluster:build_test_command_response(
    device,
    endpoint_id,
    self._cluster.ID,
    self.ID,
    nil, --tlv
    status
  )
end

--- Initialize the MoveHue command
---
--- @param self MoveHue the template class for this command
--- @param device st.matter.Device the device to build this message to
--- @param move_mode st.matter.clusters.ColorControl.types.HueMoveMode
--- @param rate st.matter.data_types.Uint8
--- @param options_mask st.matter.data_types.Uint8
--- @param options_override st.matter.data_types.Uint8

--- @return st.matter.interaction_model.InteractionRequest of type INVOKE
function MoveHue:init(device, endpoint_id, move_mode, rate, options_mask, options_override)
  local out = {}
  local args = {move_mode, rate, options_mask, options_override}
  if #args > #self.field_defs then
    error(self.NAME .. " received too many arguments")
  end
  for i,v in ipairs(self.field_defs) do
    if v.optional and args[i] == nil then
      out[v.name] = nil
    elseif v.nullable and args[i] == nil then
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
    __index = MoveHue,
    __tostring = MoveHue.pretty_print
  })
  return self._cluster:build_cluster_command(
    device,
    out,
    endpoint_id,
    self._cluster.ID,
    self.ID
  )
end

function MoveHue:set_parent_cluster(cluster)
  self._cluster = cluster
  return self
end

--- Add field names to each command field
---
--- @param base_type_obj st.matter.data_types.Structure
function MoveHue:augment_type(base_type_obj)
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
      end
    end
  end
  base_type_obj.elements = elems
end

function MoveHue:deserialize(tlv_buf)
  return TLVParser.decode_tlv(tlv_buf)
end

setmetatable(MoveHue, {__call = MoveHue.init})

return MoveHue


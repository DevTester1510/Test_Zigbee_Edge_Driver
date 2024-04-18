local data_types = require "st.zigbee.data_types"
local utils = require "st.zigbee.utils"


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

--- @class st.zigbee.zcl.clusters.PumpConfigurationAndControl.types.PumpControlMode
--- @alias PumpControlMode
--- @field public NAME PumpControlMode
local PumpControlMode = {}
PumpControlMode.NAME = "PumpControlMode"
PumpControlMode.get_fields = function(self)
  local out = {}
  return out
end
PumpControlMode.set_field_names = function(self)
end

--- @function PumpControlMode:get_length
--- @return number the length in bytes of this frame
PumpControlMode.get_length = utils.length_from_fields

--- @function PumpControlMode:_serialize
--- @return string this class serialized to bytes
PumpControlMode._serialize = utils.serialize_from_fields

--- @function PumpControlMode:pretty_print
--- @return string this class in a human readable format
PumpControlMode.pretty_print = utils.print_from_fields

--- @function PumpControlMode.deserialize
--- @param buf Reader the buf to parse this class from
--- @return number the length in bytes of this frame
PumpControlMode.deserialize = function(buf)
  local o = {}
  setmetatable(o, {
    __index = PumpControlMode,
    __tostring = PumpControlMode.pretty_print,
  })
  o:set_field_names()
  return o
end

--- @function PumpControlMode.init
PumpControlMode.init = function(orig)
  local o = {}
  setmetatable(o, {
    __index = orig,
    __tostring = orig.pretty_print
  })
  o:set_field_names()
  return o
end

setmetatable(PumpControlMode, {__call = PumpControlMode.init})
return PumpControlMode

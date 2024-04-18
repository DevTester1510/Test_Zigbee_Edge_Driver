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

local types_mt = {}
types_mt.__types_cache = {}
types_mt.__index = function(self, key)
  if types_mt.__types_cache[key] == nil then
    local req_loc = string.format("st.zigbee.generated.zcl_clusters.PowerConfiguration.types.%s", key)
    local cluster_type = require(req_loc)
    types_mt.__types_cache[key] = cluster_type
  end
  return types_mt.__types_cache[key]
end


--- @class st.zigbee.zcl.clusters.PowerConfigurationTypes
---
--- @field public BatterySize st.zigbee.zcl.clusters.PowerConfiguration.types.BatterySize
--- @field public BatteryAlarmMask st.zigbee.zcl.clusters.PowerConfiguration.types.BatteryAlarmMask
--- @field public BatteryAlarmState st.zigbee.zcl.clusters.PowerConfiguration.types.BatteryAlarmState

local PowerConfigurationTypes = {}

setmetatable(PowerConfigurationTypes, types_mt)

return PowerConfigurationTypes

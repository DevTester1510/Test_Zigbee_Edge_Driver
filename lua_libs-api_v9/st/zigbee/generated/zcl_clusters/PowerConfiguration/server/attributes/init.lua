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

local attr_mt = {}
attr_mt.__attr_cache = {}
attr_mt.__index = function(self, key)
  if attr_mt.__attr_cache[key] == nil then
    local req_loc = string.format("st.zigbee.generated.zcl_clusters.PowerConfiguration.server.attributes.%s", key)
    local raw_def = require(req_loc)
    local cluster = rawget(self, "_cluster")
    raw_def:set_parent_cluster(cluster)
    attr_mt.__attr_cache[key] = raw_def
  end
  return attr_mt.__attr_cache[key]
end


--- @class st.zigbee.zcl.clusters.PowerConfigurationServerAttributes
---
--- @field public MainsVoltage st.zigbee.zcl.clusters.PowerConfiguration.MainsVoltage
--- @field public MainsFrequency st.zigbee.zcl.clusters.PowerConfiguration.MainsFrequency
--- @field public MainsAlarmMask st.zigbee.zcl.clusters.PowerConfiguration.MainsAlarmMask
--- @field public MainsVoltageMinThreshold st.zigbee.zcl.clusters.PowerConfiguration.MainsVoltageMinThreshold
--- @field public MainsVoltageMaxThreshold st.zigbee.zcl.clusters.PowerConfiguration.MainsVoltageMaxThreshold
--- @field public MainsVoltageDwellTripPoint st.zigbee.zcl.clusters.PowerConfiguration.MainsVoltageDwellTripPoint
--- @field public BatteryVoltage st.zigbee.zcl.clusters.PowerConfiguration.BatteryVoltage
--- @field public BatteryPercentageRemaining st.zigbee.zcl.clusters.PowerConfiguration.BatteryPercentageRemaining
--- @field public BatteryManufacturer st.zigbee.zcl.clusters.PowerConfiguration.BatteryManufacturer
--- @field public BatterySize st.zigbee.zcl.clusters.PowerConfiguration.BatterySize
--- @field public BatteryAHrRating st.zigbee.zcl.clusters.PowerConfiguration.BatteryAHrRating
--- @field public BatteryQuantity st.zigbee.zcl.clusters.PowerConfiguration.BatteryQuantity
--- @field public BatteryRatedVoltage st.zigbee.zcl.clusters.PowerConfiguration.BatteryRatedVoltage
--- @field public BatteryAlarmMask st.zigbee.zcl.clusters.PowerConfiguration.BatteryAlarmMask
--- @field public BatteryVoltageMinThreshold st.zigbee.zcl.clusters.PowerConfiguration.BatteryVoltageMinThreshold
--- @field public BatteryVoltageThreshold1 st.zigbee.zcl.clusters.PowerConfiguration.BatteryVoltageThreshold1
--- @field public BatteryVoltageThreshold2 st.zigbee.zcl.clusters.PowerConfiguration.BatteryVoltageThreshold2
--- @field public BatteryVoltageThreshold3 st.zigbee.zcl.clusters.PowerConfiguration.BatteryVoltageThreshold3
--- @field public BatteryPercentageMinThreshold st.zigbee.zcl.clusters.PowerConfiguration.BatteryPercentageMinThreshold
--- @field public BatteryPercentageThreshold1 st.zigbee.zcl.clusters.PowerConfiguration.BatteryPercentageThreshold1
--- @field public BatteryPercentageThreshold2 st.zigbee.zcl.clusters.PowerConfiguration.BatteryPercentageThreshold2
--- @field public BatteryPercentageThreshold3 st.zigbee.zcl.clusters.PowerConfiguration.BatteryPercentageThreshold3
--- @field public BatteryAlarmState st.zigbee.zcl.clusters.PowerConfiguration.BatteryAlarmState
--- @field public Battery2Voltage st.zigbee.zcl.clusters.PowerConfiguration.Battery2Voltage
--- @field public Battery2PercentageRemaining st.zigbee.zcl.clusters.PowerConfiguration.Battery2PercentageRemaining
--- @field public Battery2Manufacturer st.zigbee.zcl.clusters.PowerConfiguration.Battery2Manufacturer
--- @field public Battery2Size st.zigbee.zcl.clusters.PowerConfiguration.Battery2Size
--- @field public Battery2AHrRating st.zigbee.zcl.clusters.PowerConfiguration.Battery2AHrRating
--- @field public Battery2Quantity st.zigbee.zcl.clusters.PowerConfiguration.Battery2Quantity
--- @field public Battery2RatedVoltage st.zigbee.zcl.clusters.PowerConfiguration.Battery2RatedVoltage
--- @field public Battery2AlarmMask st.zigbee.zcl.clusters.PowerConfiguration.Battery2AlarmMask
--- @field public Battery2VoltageMinThreshold st.zigbee.zcl.clusters.PowerConfiguration.Battery2VoltageMinThreshold
--- @field public Battery2VoltageThreshold1 st.zigbee.zcl.clusters.PowerConfiguration.Battery2VoltageThreshold1
--- @field public Battery2VoltageThreshold2 st.zigbee.zcl.clusters.PowerConfiguration.Battery2VoltageThreshold2
--- @field public Battery2VoltageThreshold3 st.zigbee.zcl.clusters.PowerConfiguration.Battery2VoltageThreshold3
--- @field public Battery2PercentageMinThreshold st.zigbee.zcl.clusters.PowerConfiguration.Battery2PercentageMinThreshold
--- @field public Battery2PercentageThreshold1 st.zigbee.zcl.clusters.PowerConfiguration.Battery2PercentageThreshold1
--- @field public Battery2PercentageThreshold2 st.zigbee.zcl.clusters.PowerConfiguration.Battery2PercentageThreshold2
--- @field public Battery2PercentageThreshold3 st.zigbee.zcl.clusters.PowerConfiguration.Battery2PercentageThreshold3
--- @field public Battery2AlarmState st.zigbee.zcl.clusters.PowerConfiguration.Battery2AlarmState
--- @field public Battery3Voltage st.zigbee.zcl.clusters.PowerConfiguration.Battery3Voltage
--- @field public Battery3PercentageRemaining st.zigbee.zcl.clusters.PowerConfiguration.Battery3PercentageRemaining
--- @field public Battery3Manufacturer st.zigbee.zcl.clusters.PowerConfiguration.Battery3Manufacturer
--- @field public Battery3Size st.zigbee.zcl.clusters.PowerConfiguration.Battery3Size
--- @field public Battery3AHrRating st.zigbee.zcl.clusters.PowerConfiguration.Battery3AHrRating
--- @field public Battery3Quantity st.zigbee.zcl.clusters.PowerConfiguration.Battery3Quantity
--- @field public Battery3RatedVoltage st.zigbee.zcl.clusters.PowerConfiguration.Battery3RatedVoltage
--- @field public Battery3AlarmMask st.zigbee.zcl.clusters.PowerConfiguration.Battery3AlarmMask
--- @field public Battery3VoltageMinThreshold st.zigbee.zcl.clusters.PowerConfiguration.Battery3VoltageMinThreshold
--- @field public Battery3VoltageThreshold1 st.zigbee.zcl.clusters.PowerConfiguration.Battery3VoltageThreshold1
--- @field public Battery3VoltageThreshold2 st.zigbee.zcl.clusters.PowerConfiguration.Battery3VoltageThreshold2
--- @field public Battery3VoltageThreshold3 st.zigbee.zcl.clusters.PowerConfiguration.Battery3VoltageThreshold3
--- @field public Battery3PercentageMinThreshold st.zigbee.zcl.clusters.PowerConfiguration.Battery3PercentageMinThreshold
--- @field public Battery3PercentageThreshold1 st.zigbee.zcl.clusters.PowerConfiguration.Battery3PercentageThreshold1
--- @field public Battery3PercentageThreshold2 st.zigbee.zcl.clusters.PowerConfiguration.Battery3PercentageThreshold2
--- @field public Battery3PercentageThreshold3 st.zigbee.zcl.clusters.PowerConfiguration.Battery3PercentageThreshold3
--- @field public Battery3AlarmState st.zigbee.zcl.clusters.PowerConfiguration.Battery3AlarmState

local PowerConfigurationServerAttributes = {}

function PowerConfigurationServerAttributes:set_parent_cluster(cluster)
  self._cluster = cluster
  return self
end

setmetatable(PowerConfigurationServerAttributes, attr_mt)

return PowerConfigurationServerAttributes
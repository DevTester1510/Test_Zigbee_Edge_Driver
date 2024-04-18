local cluster_base = require "st.zigbee.cluster_base"
local ElectricalMeasurementClientAttributes = require "st.zigbee.generated.zcl_clusters.ElectricalMeasurement.client.attributes"
local ElectricalMeasurementServerAttributes = require "st.zigbee.generated.zcl_clusters.ElectricalMeasurement.server.attributes"
local ElectricalMeasurementClientCommands = require "st.zigbee.generated.zcl_clusters.ElectricalMeasurement.client.commands"
local ElectricalMeasurementServerCommands = require "st.zigbee.generated.zcl_clusters.ElectricalMeasurement.server.commands"
local ElectricalMeasurementTypes = require "st.zigbee.generated.zcl_clusters.ElectricalMeasurement.types"

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

--- @class st.zigbee.zcl.clusters.ElectricalMeasurement
--- @alias ElectricalMeasurement
---
--- @field public ID number 0x0B04 the ID of this cluster
--- @field public NAME string "ElectricalMeasurement" the name of this cluster
--- @field public attributes st.zigbee.zcl.clusters.ElectricalMeasurementServerAttributes | st.zigbee.zcl.clusters.ElectricalMeasurementClientAttributes
--- @field public commands st.zigbee.zcl.clusters.ElectricalMeasurementServerCommands | st.zigbee.zcl.clusters.ElectricalMeasurementClientCommands
--- @field public types st.zigbee.zcl.clusters.ElectricalMeasurementTypes
local ElectricalMeasurement = {}

ElectricalMeasurement.ID = 0x0B04
ElectricalMeasurement.NAME = "ElectricalMeasurement"
ElectricalMeasurement.server = {}
ElectricalMeasurement.client = {}
ElectricalMeasurement.server.attributes = ElectricalMeasurementServerAttributes:set_parent_cluster(ElectricalMeasurement)
ElectricalMeasurement.client.attributes = ElectricalMeasurementClientAttributes:set_parent_cluster(ElectricalMeasurement)
ElectricalMeasurement.server.commands = ElectricalMeasurementServerCommands:set_parent_cluster(ElectricalMeasurement)
ElectricalMeasurement.client.commands = ElectricalMeasurementClientCommands:set_parent_cluster(ElectricalMeasurement)
ElectricalMeasurement.types = ElectricalMeasurementTypes

function ElectricalMeasurement.attr_id_map()
    return {
    [0x0000] = "MeasurementType",
    [0x0100] = "DCVoltage",
    [0x0101] = "DCVoltageMin",
    [0x0102] = "DCVoltageMax",
    [0x0103] = "DCCurrent",
    [0x0104] = "DCCurrentMin",
    [0x0105] = "DCCurrentMax",
    [0x0106] = "DCPower",
    [0x0107] = "DCPowerMin",
    [0x0108] = "DCPowerMax",
    [0x0200] = "DCVoltageMultiplier",
    [0x0201] = "DCVoltageDivisor",
    [0x0202] = "DCCurrentMultiplier",
    [0x0203] = "DCCurrentDivisor",
    [0x0204] = "DCPowerMultiplier",
    [0x0205] = "DCPowerDivisor",
    [0x0300] = "ACFrequency",
    [0x0301] = "ACFrequencyMin",
    [0x0302] = "ACFrequencyMax",
    [0x0303] = "NeutralCurrent",
    [0x0304] = "TotalActivePower",
    [0x0305] = "TotalReactivePower",
    [0x0306] = "TotalApparentPower",
    [0x0307] = "Measured1stHarmonicCurrent",
    [0x0308] = "Measured3rdHarmonicCurrent",
    [0x0309] = "Measured5thHarmonicCurrent",
    [0x030a] = "Measured7thHarmonicCurrent",
    [0x030b] = "Measured9thHarmonicCurrent",
    [0x030c] = "Measured11thHarmonicCurrent",
    [0x030d] = "MeasuredPhase1stHarmonicCurrent",
    [0x030e] = "MeasuredPhase3rdHarmonicCurrent",
    [0x030f] = "MeasuredPhase5thHarmonicCurrent",
    [0x0310] = "MeasuredPhase7thHarmonicCurrent",
    [0x0311] = "MeasuredPhase9thHarmonicCurrent",
    [0x0312] = "MeasuredPhase11thHarmonicCurrent",
    [0x0400] = "ACFrequencyMultiplier",
    [0x0401] = "ACFrequencyDivisor",
    [0x0402] = "PowerMultiplier",
    [0x0403] = "PowerDivisor",
    [0x0404] = "HarmonicCurrentMultiplier",
    [0x0405] = "PhaseHarmonicCurrentMultiplier",
    [0x0501] = "LineCurrent",
    [0x0502] = "ActiveCurrent",
    [0x0503] = "ReactiveCurrent",
    [0x0505] = "RMSVoltage",
    [0x0506] = "RMSVoltageMin",
    [0x0507] = "RMSVoltageMax",
    [0x0508] = "RMSCurrent",
    [0x0509] = "RMSCurrentMin",
    [0x050a] = "RMSCurrentMax",
    [0x050b] = "ActivePower",
    [0x050c] = "ActivePowerMin",
    [0x050d] = "ActivePowerMax",
    [0x050e] = "ReactivePower",
    [0x050f] = "ApparentPower",
    [0x0510] = "PowerFactor",
    [0x0511] = "AverageRMSVoltageMeasurementPeriod",
    [0x0512] = "AverageRMSOverVoltageCounter",
    [0x0513] = "AverageRMSUnderVoltageCounter",
    [0x0514] = "RMSExtremeOverVoltagePeriod",
    [0x0515] = "RMSExtremeUnderVoltagePeriod",
    [0x0516] = "RMSVoltageSagPeriod",
    [0x0517] = "RMSVoltageSwellPeriod",
    [0x0600] = "ACVoltageMultiplier",
    [0x0601] = "ACVoltageDivisor",
    [0x0602] = "ACCurrentMultiplier",
    [0x0603] = "ACCurrentDivisor",
    [0x0604] = "ACPowerMultiplier",
    [0x0605] = "ACPowerDivisor",
    [0x0700] = "DCOverloadAlarmsMask",
    [0x0701] = "DCVoltageOverload",
    [0x0702] = "DCCurrentOverload",
    [0x0800] = "ACAlarmsMask",
    [0x0801] = "ACVoltageOverload",
    [0x0802] = "ACCurrentOverload",
    [0x0803] = "ACActivePowerOverload",
    [0x0804] = "ACReactivePowerOverload",
    [0x0805] = "AverageRMSOverVoltage",
    [0x0806] = "AverageRMSUnderVoltage",
    [0x0807] = "RMSExtremeOverVoltage",
    [0x0808] = "RMSExtremeUnderVoltage",
    [0x0809] = "RMSVoltageSag",
    [0x080a] = "RMSVoltageSwell",
    [0x0901] = "LineCurrentPhB",
    [0x0902] = "ActiveCurrentPhB",
    [0x0903] = "ReactiveCurrentPhB",
    [0x0905] = "RMSVoltagePhB",
    [0x0906] = "RMSVoltageMinPhB",
    [0x0907] = "RMSVoltageMaxPhB",
    [0x0908] = "RMSCurrentPhB",
    [0x0909] = "RMSCurrentMinPhB",
    [0x090a] = "RMSCurrentMaxPhB",
    [0x090b] = "ActivePowerPhB",
    [0x090c] = "ActivePowerMinPhB",
    [0x090d] = "ActivePowerMaxPhB",
    [0x090e] = "ReactivePowerPhB",
    [0x090f] = "ApparentPowerPhB",
    [0x0910] = "PowerFactorPhB",
    [0x0911] = "AverageRMSVoltageMeasurementPeriodPhB",
    [0x0912] = "AverageRMSOverVoltageCounterPhB",
    [0x0913] = "AverageRMSUnderVoltageCounterPhB",
    [0x0914] = "RMSExtremeOverVoltagePeriodPhB",
    [0x0915] = "RMSExtremeUnderVoltagePeriodPhB",
    [0x0916] = "RMSVoltageSagPeriodPhB",
    [0x0917] = "RMSVoltageSwellPeriodPhB",
    [0x0a01] = "LineCurrentPhC",
    [0x0a02] = "ActiveCurrentPhC",
    [0x0a03] = "ReactiveCurrentPhC",
    [0x0a05] = "RMSVoltagePhC",
    [0x0a06] = "RMSVoltageMinPhC",
    [0x0a07] = "RMSVoltageMaxPhC",
    [0x0a08] = "RMSCurrentPhC",
    [0x0a09] = "RMSCurrentMinPhC",
    [0x0a0a] = "RMSCurrentMaxPhC",
    [0x0a0b] = "ActivePowerPhC",
    [0x0a0c] = "ActivePowerMinPhC",
    [0x0a0d] = "ActivePowerMaxPhC",
    [0x0a0e] = "ReactivePowerPhC",
    [0x0a0f] = "ApparentPowerPhC",
    [0x0a10] = "PowerFactorPhC",
    [0x0a11] = "AverageRMSVoltageMeasurementPeriodPhC",
    [0x0a12] = "AverageRMSOverVoltageCounterPhC",
    [0x0a13] = "AverageRMSUnderVoltageCounterPhC",
    [0x0a14] = "RMSExtremeOverVoltagePeriodPhC",
    [0x0a15] = "RMSExtremeUnderVoltagePeriodPhC",
    [0x0a16] = "RMSVoltageSagPeriodPhC",
    [0x0a17] = "RMSVoltageSwellPeriodPhC",
  }
end

function ElectricalMeasurement.server_id_map()
    return {
    [0x00] = "GetProfileInfo",
    [0x01] = "GetMeasurementProfile",
  }
end

function ElectricalMeasurement.client_id_map()
    return {
    [0x00] = "GetProfileInfoResponse",
    [0x01] = "GetMeasurementProfileResponse",
  }
end

ElectricalMeasurement.attribute_direction_map = {
  ["MeasurementType"] = "server",
  ["DCVoltage"] = "server",
  ["DCVoltageMin"] = "server",
  ["DCVoltageMax"] = "server",
  ["DCCurrent"] = "server",
  ["DCCurrentMin"] = "server",
  ["DCCurrentMax"] = "server",
  ["DCPower"] = "server",
  ["DCPowerMin"] = "server",
  ["DCPowerMax"] = "server",
  ["DCVoltageMultiplier"] = "server",
  ["DCVoltageDivisor"] = "server",
  ["DCCurrentMultiplier"] = "server",
  ["DCCurrentDivisor"] = "server",
  ["DCPowerMultiplier"] = "server",
  ["DCPowerDivisor"] = "server",
  ["ACFrequency"] = "server",
  ["ACFrequencyMin"] = "server",
  ["ACFrequencyMax"] = "server",
  ["NeutralCurrent"] = "server",
  ["TotalActivePower"] = "server",
  ["TotalReactivePower"] = "server",
  ["TotalApparentPower"] = "server",
  ["Measured1stHarmonicCurrent"] = "server",
  ["Measured3rdHarmonicCurrent"] = "server",
  ["Measured5thHarmonicCurrent"] = "server",
  ["Measured7thHarmonicCurrent"] = "server",
  ["Measured9thHarmonicCurrent"] = "server",
  ["Measured11thHarmonicCurrent"] = "server",
  ["MeasuredPhase1stHarmonicCurrent"] = "server",
  ["MeasuredPhase3rdHarmonicCurrent"] = "server",
  ["MeasuredPhase5thHarmonicCurrent"] = "server",
  ["MeasuredPhase7thHarmonicCurrent"] = "server",
  ["MeasuredPhase9thHarmonicCurrent"] = "server",
  ["MeasuredPhase11thHarmonicCurrent"] = "server",
  ["ACFrequencyMultiplier"] = "server",
  ["ACFrequencyDivisor"] = "server",
  ["PowerMultiplier"] = "server",
  ["PowerDivisor"] = "server",
  ["HarmonicCurrentMultiplier"] = "server",
  ["PhaseHarmonicCurrentMultiplier"] = "server",
  ["LineCurrent"] = "server",
  ["ActiveCurrent"] = "server",
  ["ReactiveCurrent"] = "server",
  ["RMSVoltage"] = "server",
  ["RMSVoltageMin"] = "server",
  ["RMSVoltageMax"] = "server",
  ["RMSCurrent"] = "server",
  ["RMSCurrentMin"] = "server",
  ["RMSCurrentMax"] = "server",
  ["ActivePower"] = "server",
  ["ActivePowerMin"] = "server",
  ["ActivePowerMax"] = "server",
  ["ReactivePower"] = "server",
  ["ApparentPower"] = "server",
  ["PowerFactor"] = "server",
  ["AverageRMSVoltageMeasurementPeriod"] = "server",
  ["AverageRMSOverVoltageCounter"] = "server",
  ["AverageRMSUnderVoltageCounter"] = "server",
  ["RMSExtremeOverVoltagePeriod"] = "server",
  ["RMSExtremeUnderVoltagePeriod"] = "server",
  ["RMSVoltageSagPeriod"] = "server",
  ["RMSVoltageSwellPeriod"] = "server",
  ["ACVoltageMultiplier"] = "server",
  ["ACVoltageDivisor"] = "server",
  ["ACCurrentMultiplier"] = "server",
  ["ACCurrentDivisor"] = "server",
  ["ACPowerMultiplier"] = "server",
  ["ACPowerDivisor"] = "server",
  ["DCOverloadAlarmsMask"] = "server",
  ["DCVoltageOverload"] = "server",
  ["DCCurrentOverload"] = "server",
  ["ACAlarmsMask"] = "server",
  ["ACVoltageOverload"] = "server",
  ["ACCurrentOverload"] = "server",
  ["ACActivePowerOverload"] = "server",
  ["ACReactivePowerOverload"] = "server",
  ["AverageRMSOverVoltage"] = "server",
  ["AverageRMSUnderVoltage"] = "server",
  ["RMSExtremeOverVoltage"] = "server",
  ["RMSExtremeUnderVoltage"] = "server",
  ["RMSVoltageSag"] = "server",
  ["RMSVoltageSwell"] = "server",
  ["LineCurrentPhB"] = "server",
  ["ActiveCurrentPhB"] = "server",
  ["ReactiveCurrentPhB"] = "server",
  ["RMSVoltagePhB"] = "server",
  ["RMSVoltageMinPhB"] = "server",
  ["RMSVoltageMaxPhB"] = "server",
  ["RMSCurrentPhB"] = "server",
  ["RMSCurrentMinPhB"] = "server",
  ["RMSCurrentMaxPhB"] = "server",
  ["ActivePowerPhB"] = "server",
  ["ActivePowerMinPhB"] = "server",
  ["ActivePowerMaxPhB"] = "server",
  ["ReactivePowerPhB"] = "server",
  ["ApparentPowerPhB"] = "server",
  ["PowerFactorPhB"] = "server",
  ["AverageRMSVoltageMeasurementPeriodPhB"] = "server",
  ["AverageRMSOverVoltageCounterPhB"] = "server",
  ["AverageRMSUnderVoltageCounterPhB"] = "server",
  ["RMSExtremeOverVoltagePeriodPhB"] = "server",
  ["RMSExtremeUnderVoltagePeriodPhB"] = "server",
  ["RMSVoltageSagPeriodPhB"] = "server",
  ["RMSVoltageSwellPeriodPhB"] = "server",
  ["LineCurrentPhC"] = "server",
  ["ActiveCurrentPhC"] = "server",
  ["ReactiveCurrentPhC"] = "server",
  ["RMSVoltagePhC"] = "server",
  ["RMSVoltageMinPhC"] = "server",
  ["RMSVoltageMaxPhC"] = "server",
  ["RMSCurrentPhC"] = "server",
  ["RMSCurrentMinPhC"] = "server",
  ["RMSCurrentMaxPhC"] = "server",
  ["ActivePowerPhC"] = "server",
  ["ActivePowerMinPhC"] = "server",
  ["ActivePowerMaxPhC"] = "server",
  ["ReactivePowerPhC"] = "server",
  ["ApparentPowerPhC"] = "server",
  ["PowerFactorPhC"] = "server",
  ["AverageRMSVoltageMeasurementPeriodPhC"] = "server",
  ["AverageRMSOverVoltageCounterPhC"] = "server",
  ["AverageRMSUnderVoltageCounterPhC"] = "server",
  ["RMSExtremeOverVoltagePeriodPhC"] = "server",
  ["RMSExtremeUnderVoltagePeriodPhC"] = "server",
  ["RMSVoltageSagPeriodPhC"] = "server",
  ["RMSVoltageSwellPeriodPhC"] = "server",
}
ElectricalMeasurement.command_direction_map = {
  ["GetProfileInfoResponse"] = "client",
  ["GetMeasurementProfileResponse"] = "client",
  ["GetProfileInfo"] = "server",
  ["GetMeasurementProfile"] = "server",
}

setmetatable(ElectricalMeasurement, {__index = cluster_base})

ElectricalMeasurement:init_attributes_table()
ElectricalMeasurement:init_commands_table()

return ElectricalMeasurement

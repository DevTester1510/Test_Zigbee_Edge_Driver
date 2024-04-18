local cluster_base = require "st.zigbee.cluster_base"
local ThermostatClientAttributes = require "st.zigbee.generated.zcl_clusters.Thermostat.client.attributes"
local ThermostatServerAttributes = require "st.zigbee.generated.zcl_clusters.Thermostat.server.attributes"
local ThermostatClientCommands = require "st.zigbee.generated.zcl_clusters.Thermostat.client.commands"
local ThermostatServerCommands = require "st.zigbee.generated.zcl_clusters.Thermostat.server.commands"
local ThermostatTypes = require "st.zigbee.generated.zcl_clusters.Thermostat.types"

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

--- @class st.zigbee.zcl.clusters.Thermostat
--- @alias Thermostat
---
--- @field public ID number 0x0201 the ID of this cluster
--- @field public NAME string "Thermostat" the name of this cluster
--- @field public attributes st.zigbee.zcl.clusters.ThermostatServerAttributes | st.zigbee.zcl.clusters.ThermostatClientAttributes
--- @field public commands st.zigbee.zcl.clusters.ThermostatServerCommands | st.zigbee.zcl.clusters.ThermostatClientCommands
--- @field public types st.zigbee.zcl.clusters.ThermostatTypes
local Thermostat = {}

Thermostat.ID = 0x0201
Thermostat.NAME = "Thermostat"
Thermostat.server = {}
Thermostat.client = {}
Thermostat.server.attributes = ThermostatServerAttributes:set_parent_cluster(Thermostat)
Thermostat.client.attributes = ThermostatClientAttributes:set_parent_cluster(Thermostat)
Thermostat.server.commands = ThermostatServerCommands:set_parent_cluster(Thermostat)
Thermostat.client.commands = ThermostatClientCommands:set_parent_cluster(Thermostat)
Thermostat.types = ThermostatTypes

function Thermostat.attr_id_map()
    return {
    [0x0000] = "LocalTemperature",
    [0x0001] = "OutdoorTemperature",
    [0x0002] = "Occupancy",
    [0x0003] = "AbsMinHeatSetpointLimit",
    [0x0004] = "AbsMaxHeatSetpointLimit",
    [0x0005] = "AbsMinCoolSetpointLimit",
    [0x0006] = "AbsMaxCoolSetpointLimit",
    [0x0007] = "PICoolingDemand",
    [0x0008] = "PIHeatingDemand",
    [0x0009] = "HVACSystemTypeConfiguration",
    [0x0010] = "LocalTemperatureCalibration",
    [0x0011] = "OccupiedCoolingSetpoint",
    [0x0012] = "OccupiedHeatingSetpoint",
    [0x0013] = "UnoccupiedCoolingSetpoint",
    [0x0014] = "UnoccupiedHeatingSetpoint",
    [0x0015] = "MinHeatSetpointLimit",
    [0x0016] = "MaxHeatSetpointLimit",
    [0x0017] = "MinCoolSetpointLimit",
    [0x0018] = "MaxCoolSetpointLimit",
    [0x0019] = "MinSetpointDeadBand",
    [0x001A] = "RemoteSensing",
    [0x001B] = "ControlSequenceOfOperation",
    [0x001C] = "SystemMode",
    [0x001D] = "AlarmMask",
    [0x001E] = "ThermostatRunningMode",
    [0x0020] = "StartOfWeek",
    [0x0021] = "NumberOfWeeklyTransitions",
    [0x0022] = "NumberOfDailyTransitions",
    [0x0023] = "TemperatureSetpointHold",
    [0x0024] = "TemperatureSetpointHoldDuration",
    [0x0025] = "ThermostatProgrammingOperationMode",
    [0x0029] = "ThermostatRunningState",
    [0x0030] = "SetpointChangeSource",
    [0x0031] = "SetpointChangeAmount",
    [0x0032] = "SetpointChangeSourceTimestamp",
    [0x0034] = "OccupiedSetback",
    [0x0035] = "OccupiedSetbackMin",
    [0x0036] = "OccupiedSetbackMax",
    [0x0037] = "UnoccupiedSetback",
    [0x0038] = "UnoccupiedSetbackMin",
    [0x0039] = "UnoccupiedSetbackMax",
    [0x003A] = "EmergencyHeatDelta",
    [0x0040] = "ACType",
    [0x0041] = "ACCapacity",
    [0x0042] = "ACRefrigerantType",
    [0x0043] = "ACCompressorType",
    [0x0044] = "ACErrorCode",
    [0x0045] = "ACLouverPosition",
    [0x0046] = "ACCoilTemperature",
    [0x0047] = "ACCapacityFormat",
  }
end

function Thermostat.server_id_map()
    return {
    [0x00] = "SetpointRaiseOrLower",
    [0x01] = "SetWeeklySchedule",
    [0x02] = "GetWeeklySchedule",
    [0x03] = "ClearWeeklySchedule",
    [0x04] = "GetRelayStatusLog",
  }
end

function Thermostat.client_id_map()
    return {
    [0x00] = "GetWeeklyScheduleResponse",
    [0x01] = "GetRelayStatusLogResponse",
  }
end

Thermostat.attribute_direction_map = {
  ["LocalTemperature"] = "server",
  ["OutdoorTemperature"] = "server",
  ["Occupancy"] = "server",
  ["AbsMinHeatSetpointLimit"] = "server",
  ["AbsMaxHeatSetpointLimit"] = "server",
  ["AbsMinCoolSetpointLimit"] = "server",
  ["AbsMaxCoolSetpointLimit"] = "server",
  ["PICoolingDemand"] = "server",
  ["PIHeatingDemand"] = "server",
  ["HVACSystemTypeConfiguration"] = "server",
  ["LocalTemperatureCalibration"] = "server",
  ["OccupiedCoolingSetpoint"] = "server",
  ["OccupiedHeatingSetpoint"] = "server",
  ["UnoccupiedCoolingSetpoint"] = "server",
  ["UnoccupiedHeatingSetpoint"] = "server",
  ["MinHeatSetpointLimit"] = "server",
  ["MaxHeatSetpointLimit"] = "server",
  ["MinCoolSetpointLimit"] = "server",
  ["MaxCoolSetpointLimit"] = "server",
  ["MinSetpointDeadBand"] = "server",
  ["RemoteSensing"] = "server",
  ["ControlSequenceOfOperation"] = "server",
  ["SystemMode"] = "server",
  ["AlarmMask"] = "server",
  ["ThermostatRunningMode"] = "server",
  ["StartOfWeek"] = "server",
  ["NumberOfWeeklyTransitions"] = "server",
  ["NumberOfDailyTransitions"] = "server",
  ["TemperatureSetpointHold"] = "server",
  ["TemperatureSetpointHoldDuration"] = "server",
  ["ThermostatProgrammingOperationMode"] = "server",
  ["ThermostatRunningState"] = "server",
  ["SetpointChangeSource"] = "server",
  ["SetpointChangeAmount"] = "server",
  ["SetpointChangeSourceTimestamp"] = "server",
  ["OccupiedSetback"] = "server",
  ["OccupiedSetbackMin"] = "server",
  ["OccupiedSetbackMax"] = "server",
  ["UnoccupiedSetback"] = "server",
  ["UnoccupiedSetbackMin"] = "server",
  ["UnoccupiedSetbackMax"] = "server",
  ["EmergencyHeatDelta"] = "server",
  ["ACType"] = "server",
  ["ACCapacity"] = "server",
  ["ACRefrigerantType"] = "server",
  ["ACCompressorType"] = "server",
  ["ACErrorCode"] = "server",
  ["ACLouverPosition"] = "server",
  ["ACCoilTemperature"] = "server",
  ["ACCapacityFormat"] = "server",
}
Thermostat.command_direction_map = {
  ["GetWeeklyScheduleResponse"] = "client",
  ["GetRelayStatusLogResponse"] = "client",
  ["SetpointRaiseOrLower"] = "server",
  ["SetWeeklySchedule"] = "server",
  ["GetWeeklySchedule"] = "server",
  ["ClearWeeklySchedule"] = "server",
  ["GetRelayStatusLog"] = "server",
}

setmetatable(Thermostat, {__index = cluster_base})

Thermostat:init_attributes_table()
Thermostat:init_commands_table()

return Thermostat

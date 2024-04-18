local cluster_base = require "st.zigbee.cluster_base"
local DoorLockClientAttributes = require "st.zigbee.generated.zcl_clusters.DoorLock.client.attributes"
local DoorLockServerAttributes = require "st.zigbee.generated.zcl_clusters.DoorLock.server.attributes"
local DoorLockClientCommands = require "st.zigbee.generated.zcl_clusters.DoorLock.client.commands"
local DoorLockServerCommands = require "st.zigbee.generated.zcl_clusters.DoorLock.server.commands"
local DoorLockTypes = require "st.zigbee.generated.zcl_clusters.DoorLock.types"

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

--- @class st.zigbee.zcl.clusters.DoorLock
--- @alias DoorLock
---
--- @field public ID number 0x0101 the ID of this cluster
--- @field public NAME string "DoorLock" the name of this cluster
--- @field public attributes st.zigbee.zcl.clusters.DoorLockServerAttributes | st.zigbee.zcl.clusters.DoorLockClientAttributes
--- @field public commands st.zigbee.zcl.clusters.DoorLockServerCommands | st.zigbee.zcl.clusters.DoorLockClientCommands
--- @field public types st.zigbee.zcl.clusters.DoorLockTypes
local DoorLock = {}

DoorLock.ID = 0x0101
DoorLock.NAME = "DoorLock"
DoorLock.server = {}
DoorLock.client = {}
DoorLock.server.attributes = DoorLockServerAttributes:set_parent_cluster(DoorLock)
DoorLock.client.attributes = DoorLockClientAttributes:set_parent_cluster(DoorLock)
DoorLock.server.commands = DoorLockServerCommands:set_parent_cluster(DoorLock)
DoorLock.client.commands = DoorLockClientCommands:set_parent_cluster(DoorLock)
DoorLock.types = DoorLockTypes

function DoorLock.attr_id_map()
    return {
    [0x0000] = "LockState",
    [0x0001] = "LockType",
    [0x0002] = "ActuatorEnabled",
    [0x0003] = "DoorState",
    [0x0004] = "DoorOpenEvents",
    [0x0005] = "DoorClosedEvents",
    [0x0006] = "OpenPeriod",
    [0x0010] = "NumberOfLogRecordsSupported",
    [0x0011] = "NumberOfTotalUsersSupported",
    [0x0012] = "NumberOfPINUsersSupported",
    [0x0013] = "NumberOfRFIDUsersSupported",
    [0x0014] = "NumberOfWeekDaySchedulesSupportedPerUser",
    [0x0015] = "NumberOfYearDaySchedulesSupportedPerUser",
    [0x0016] = "NumberOfHolidaySchedulesSupported",
    [0x0017] = "MaxPINCodeLength",
    [0x0018] = "MinPINCodeLength",
    [0x0019] = "MaxRFIDCodeLength",
    [0x001A] = "MinRFIDCodeLength",
    [0x0020] = "EnableLogging",
    [0x0021] = "Language",
    [0x0022] = "LEDSettings",
    [0x0023] = "AutoRelockTime",
    [0x0024] = "SoundVolume",
    [0x0025] = "OperatingMode",
    [0x0026] = "SupportedOperatingModes",
    [0x0027] = "DefaultConfigurationRegister",
    [0x0028] = "EnableLocalProgramming",
    [0x0029] = "EnableOneTouchLocking",
    [0x002A] = "EnableInsideStatusLED",
    [0x002B] = "EnablePrivacyModeButton",
    [0x0030] = "WrongCodeEntryLimit",
    [0x0031] = "UserCodeTemporaryDisableTime",
    [0x0032] = "SendPINOverTheAir",
    [0x0033] = "RequirePINforRFOperation",
    [0x0034] = "SecurityLevel",
    [0x0040] = "AlarmMask",
    [0x0041] = "KeypadOperationEventMask",
    [0x0042] = "RFOperationEventMask",
    [0x0043] = "ManualOperationEventMask",
    [0x0044] = "RFIDOperationEventMask",
    [0x0045] = "KeypadProgrammingEventMask",
    [0x0046] = "RFProgrammingEventMask",
    [0x0047] = "RFIDProgrammingEventMask",
  }
end

function DoorLock.server_id_map()
    return {
    [0x00] = "LockDoor",
    [0x01] = "UnlockDoor",
    [0x02] = "Toggle",
    [0x03] = "UnlockWithTimeout",
    [0x04] = "GetLogRecord",
    [0x05] = "SetPINCode",
    [0x06] = "GetPINCode",
    [0x07] = "ClearPINCode",
    [0x08] = "ClearAllPINCodes",
    [0x09] = "SetUserStatus",
    [0x0A] = "GetUserStatus",
    [0x0B] = "SetWeekdaySchedule",
    [0x0C] = "GetWeekdaySchedule",
    [0x0D] = "ClearWeekdaySchedule",
    [0x0E] = "SetYearDaySchedule",
    [0x0F] = "GetYearDaySchedule",
    [0x10] = "ClearYearDaySchedule",
    [0x11] = "SetHolidaySchedule",
    [0x12] = "GetHolidaySchedule",
    [0x13] = "ClearHolidaySchedule",
    [0x14] = "SetUserType",
    [0x15] = "GetUserType",
    [0x16] = "SetRFIDCode",
    [0x17] = "GetRFIDCode",
    [0x18] = "ClearRFIDCode",
    [0x19] = "ClearAllRFIDCodes",
  }
end

function DoorLock.client_id_map()
    return {
    [0x00] = "LockDoorResponse",
    [0x01] = "UnlockDoorResponse",
    [0x02] = "ToggleResponse",
    [0x03] = "UnlockWithTimeoutResponse",
    [0x04] = "GetLogRecordResponse",
    [0x05] = "SetPINCodeResponse",
    [0x06] = "GetPINCodeResponse",
    [0x07] = "ClearPINCodeResponse",
    [0x08] = "ClearAllPINCodesResponse",
    [0x09] = "SetUserStatusResponse",
    [0x0A] = "GetUserStatusResponse",
    [0x0B] = "SetWeekdayScheduleResponse",
    [0x0C] = "GetWeekdayScheduleResponse",
    [0x0D] = "ClearWeekdayScheduleResponse",
    [0x0E] = "SetYearDayScheduleResponse",
    [0x0F] = "GetYearDayScheduleResponse",
    [0x10] = "ClearYearDayScheduleResponse",
    [0x11] = "SetHolidayScheduleResponse",
    [0x12] = "GetHolidayScheduleResponse",
    [0x13] = "ClearHolidayScheduleResponse",
    [0x14] = "SetUserTypeResponse",
    [0x15] = "GetUserTypeResponse",
    [0x16] = "SetRFIDCodeResponse",
    [0x17] = "GetRFIDCodeResponse",
    [0x18] = "ClearRFIDCodeResponse",
    [0x19] = "ClearAllRFIDCodesResponse",
    [0x20] = "OperatingEventNotification",
    [0x21] = "ProgrammingEventNotification",
  }
end

DoorLock.attribute_direction_map = {
  ["LockState"] = "server",
  ["LockType"] = "server",
  ["ActuatorEnabled"] = "server",
  ["DoorState"] = "server",
  ["DoorOpenEvents"] = "server",
  ["DoorClosedEvents"] = "server",
  ["OpenPeriod"] = "server",
  ["NumberOfLogRecordsSupported"] = "server",
  ["NumberOfTotalUsersSupported"] = "server",
  ["NumberOfPINUsersSupported"] = "server",
  ["NumberOfRFIDUsersSupported"] = "server",
  ["NumberOfWeekDaySchedulesSupportedPerUser"] = "server",
  ["NumberOfYearDaySchedulesSupportedPerUser"] = "server",
  ["NumberOfHolidaySchedulesSupported"] = "server",
  ["MaxPINCodeLength"] = "server",
  ["MinPINCodeLength"] = "server",
  ["MaxRFIDCodeLength"] = "server",
  ["MinRFIDCodeLength"] = "server",
  ["EnableLogging"] = "server",
  ["Language"] = "server",
  ["LEDSettings"] = "server",
  ["AutoRelockTime"] = "server",
  ["SoundVolume"] = "server",
  ["OperatingMode"] = "server",
  ["SupportedOperatingModes"] = "server",
  ["DefaultConfigurationRegister"] = "server",
  ["EnableLocalProgramming"] = "server",
  ["EnableOneTouchLocking"] = "server",
  ["EnableInsideStatusLED"] = "server",
  ["EnablePrivacyModeButton"] = "server",
  ["WrongCodeEntryLimit"] = "server",
  ["UserCodeTemporaryDisableTime"] = "server",
  ["SendPINOverTheAir"] = "server",
  ["RequirePINforRFOperation"] = "server",
  ["SecurityLevel"] = "server",
  ["AlarmMask"] = "server",
  ["KeypadOperationEventMask"] = "server",
  ["RFOperationEventMask"] = "server",
  ["ManualOperationEventMask"] = "server",
  ["RFIDOperationEventMask"] = "server",
  ["KeypadProgrammingEventMask"] = "server",
  ["RFProgrammingEventMask"] = "server",
  ["RFIDProgrammingEventMask"] = "server",
}
DoorLock.command_direction_map = {
  ["LockDoorResponse"] = "client",
  ["UnlockDoorResponse"] = "client",
  ["ToggleResponse"] = "client",
  ["UnlockWithTimeoutResponse"] = "client",
  ["GetLogRecordResponse"] = "client",
  ["SetPINCodeResponse"] = "client",
  ["GetPINCodeResponse"] = "client",
  ["ClearPINCodeResponse"] = "client",
  ["ClearAllPINCodesResponse"] = "client",
  ["SetUserStatusResponse"] = "client",
  ["GetUserStatusResponse"] = "client",
  ["SetWeekdayScheduleResponse"] = "client",
  ["GetWeekdayScheduleResponse"] = "client",
  ["ClearWeekdayScheduleResponse"] = "client",
  ["SetYearDayScheduleResponse"] = "client",
  ["GetYearDayScheduleResponse"] = "client",
  ["ClearYearDayScheduleResponse"] = "client",
  ["SetHolidayScheduleResponse"] = "client",
  ["GetHolidayScheduleResponse"] = "client",
  ["ClearHolidayScheduleResponse"] = "client",
  ["SetUserTypeResponse"] = "client",
  ["GetUserTypeResponse"] = "client",
  ["SetRFIDCodeResponse"] = "client",
  ["GetRFIDCodeResponse"] = "client",
  ["ClearRFIDCodeResponse"] = "client",
  ["ClearAllRFIDCodesResponse"] = "client",
  ["OperatingEventNotification"] = "client",
  ["ProgrammingEventNotification"] = "client",
  ["LockDoor"] = "server",
  ["UnlockDoor"] = "server",
  ["Toggle"] = "server",
  ["UnlockWithTimeout"] = "server",
  ["GetLogRecord"] = "server",
  ["SetPINCode"] = "server",
  ["GetPINCode"] = "server",
  ["ClearPINCode"] = "server",
  ["ClearAllPINCodes"] = "server",
  ["SetUserStatus"] = "server",
  ["GetUserStatus"] = "server",
  ["SetWeekdaySchedule"] = "server",
  ["GetWeekdaySchedule"] = "server",
  ["ClearWeekdaySchedule"] = "server",
  ["SetYearDaySchedule"] = "server",
  ["GetYearDaySchedule"] = "server",
  ["ClearYearDaySchedule"] = "server",
  ["SetHolidaySchedule"] = "server",
  ["GetHolidaySchedule"] = "server",
  ["ClearHolidaySchedule"] = "server",
  ["SetUserType"] = "server",
  ["GetUserType"] = "server",
  ["SetRFIDCode"] = "server",
  ["GetRFIDCode"] = "server",
  ["ClearRFIDCode"] = "server",
  ["ClearAllRFIDCodes"] = "server",
}

setmetatable(DoorLock, {__index = cluster_base})

DoorLock:init_attributes_table()
DoorLock:init_commands_table()

return DoorLock
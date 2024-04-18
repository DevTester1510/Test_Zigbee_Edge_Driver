local data_types = require "st.zigbee.data_types"
local EnumABC = require "st.zigbee.data_types.base_defs.EnumABC"

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

--- @class st.zigbee.zcl.types.ZclStatus: st.zigbee.data_types.Enum8
--- @alias ZclStatus
---
--- @field public byte_length number 1
--- @field public SUCCESS number 0
--- @field public FAILURE number 1
--- @field public NOT_AUTHORIZED number 126
--- @field public MALFORMED_COMMAND number 128
--- @field public UNSUP_CLUSTER_COMMAND number 129
--- @field public UNSUP_GENERAL_COMMAND number 130
--- @field public UNSUP_MANUF_CLUSTER_COMMAND number 131
--- @field public UNSUP_MANUF_GENERAL_COMMAND number 132
--- @field public INVALID_FIELD number 133
--- @field public UNSUPPORTED_ATTRIBUTE number 134
--- @field public INVALID_VALUE number 135
--- @field public READ_ONLY number 136
--- @field public INSUFFICIENT_SPACE number 137
--- @field public DUPLICATE_EXISTS number 138
--- @field public NOT_FOUND number 139
--- @field public UNREPORTABLE_ATTRIBUTE number 140
--- @field public INVALID_DATA_TYPE number 141
--- @field public INVALID_SELECTOR number 142
--- @field public WRITE_ONLY number 143
--- @field public INCONSISTENT_STARTUP_STATE number 144
--- @field public DEFINED_OUT_OF_BAND number 145
--- @field public INCONSISTENT number 146
--- @field public ACTION_DENIED number 147
--- @field public TIMEOUT number 148
--- @field public ABORT number 149
--- @field public INVALID_IMAGE number 150
--- @field public WAIT_FOR_DATA number 151
--- @field public NO_IMAGE_AVAILABLE number 152
--- @field public REQUIRE_MORE_IMAGE number 153
--- @field public NOTIFICATION_PENDING number 154
--- @field public HARDWARE_FAILURE number 192
--- @field public SOFTWARE_FAILURE number 193
--- @field public CALIBRATION_ERROR number 194
--- @field public UNSUPPORTED_CLUSTER number 195
--- @field public LIMIT_REACHED number 196
local ZclStatus = {}
local new_mt = EnumABC.new_mt({NAME = "ZclStatus", ID = data_types.name_to_id_map["Enum8"]}, 1)
new_mt.__index.pretty_print = function(self)
  local name_lookup = {
    [self.SUCCESS]                     = "SUCCESS",
    [self.FAILURE]                     = "FAILURE",
    [self.NOT_AUTHORIZED]              = "NOT_AUTHORIZED",
    [self.MALFORMED_COMMAND]           = "MALFORMED_COMMAND",
    [self.UNSUP_CLUSTER_COMMAND]       = "UNSUP_CLUSTER_COMMAND",
    [self.UNSUP_GENERAL_COMMAND]       = "UNSUP_GENERAL_COMMAND",
    [self.UNSUP_MANUF_CLUSTER_COMMAND] = "UNSUP_MANUF_CLUSTER_COMMAND",
    [self.UNSUP_MANUF_GENERAL_COMMAND] = "UNSUP_MANUF_GENERAL_COMMAND",
    [self.INVALID_FIELD]               = "INVALID_FIELD",
    [self.UNSUPPORTED_ATTRIBUTE]       = "UNSUPPORTED_ATTRIBUTE",
    [self.INVALID_VALUE]               = "INVALID_VALUE",
    [self.READ_ONLY]                   = "READ_ONLY",
    [self.INSUFFICIENT_SPACE]          = "INSUFFICIENT_SPACE",
    [self.DUPLICATE_EXISTS]            = "DUPLICATE_EXISTS",
    [self.NOT_FOUND]                   = "NOT_FOUND",
    [self.UNREPORTABLE_ATTRIBUTE]      = "UNREPORTABLE_ATTRIBUTE",
    [self.INVALID_DATA_TYPE]           = "INVALID_DATA_TYPE",
    [self.INVALID_SELECTOR]            = "INVALID_SELECTOR",
    [self.WRITE_ONLY]                  = "WRITE_ONLY",
    [self.INCONSISTENT_STARTUP_STATE]  = "INCONSISTENT_STARTUP_STATE",
    [self.DEFINED_OUT_OF_BAND]         = "DEFINED_OUT_OF_BAND",
    [self.INCONSISTENT]                = "INCONSISTENT",
    [self.ACTION_DENIED]               = "ACTION_DENIED",
    [self.TIMEOUT]                     = "TIMEOUT",
    [self.ABORT]                       = "ABORT",
    [self.INVALID_IMAGE]               = "INVALID_IMAGE",
    [self.WAIT_FOR_DATA]               = "WAIT_FOR_DATA",
    [self.NO_IMAGE_AVAILABLE]          = "NO_IMAGE_AVAILABLE",
    [self.REQUIRE_MORE_IMAGE]          = "REQUIRE_MORE_IMAGE",
    [self.NOTIFICATION_PENDING]        = "NOTIFICATION_PENDING",
    [self.HARDWARE_FAILURE]            = "HARDWARE_FAILURE",
    [self.SOFTWARE_FAILURE]            = "SOFTWARE_FAILURE",
    [self.CALIBRATION_ERROR]           = "CALIBRATION_ERROR",
    [self.UNSUPPORTED_CLUSTER]         = "UNSUPPORTED_CLUSTER",
    [self.LIMIT_REACHED]               = "LIMIT_REACHED",
  }
  return string.format("%s: %s", self.NAME or self.field_name, name_lookup[self.value] or string.format("%d", self.value))
end
new_mt.__tostring = new_mt.__index.pretty_print
new_mt.__index.SUCCESS                     = 0x00
new_mt.__index.FAILURE                     = 0x01
new_mt.__index.NOT_AUTHORIZED              = 0x7E
new_mt.__index.MALFORMED_COMMAND           = 0x80
new_mt.__index.UNSUP_CLUSTER_COMMAND       = 0x81
new_mt.__index.UNSUP_GENERAL_COMMAND       = 0x82
new_mt.__index.UNSUP_MANUF_CLUSTER_COMMAND = 0x83
new_mt.__index.UNSUP_MANUF_GENERAL_COMMAND = 0x84
new_mt.__index.INVALID_FIELD               = 0x85
new_mt.__index.UNSUPPORTED_ATTRIBUTE       = 0x86
new_mt.__index.INVALID_VALUE               = 0x87
new_mt.__index.READ_ONLY                   = 0x88
new_mt.__index.INSUFFICIENT_SPACE          = 0x89
new_mt.__index.DUPLICATE_EXISTS            = 0x8A
new_mt.__index.NOT_FOUND                   = 0x8B
new_mt.__index.UNREPORTABLE_ATTRIBUTE      = 0x8C
new_mt.__index.INVALID_DATA_TYPE           = 0x8D
new_mt.__index.INVALID_SELECTOR            = 0x8E
new_mt.__index.WRITE_ONLY                  = 0x8F
new_mt.__index.INCONSISTENT_STARTUP_STATE  = 0x90
new_mt.__index.DEFINED_OUT_OF_BAND         = 0x91
new_mt.__index.INCONSISTENT                = 0x92
new_mt.__index.ACTION_DENIED               = 0x93
new_mt.__index.TIMEOUT                     = 0x94
new_mt.__index.ABORT                       = 0x95
new_mt.__index.INVALID_IMAGE               = 0x96
new_mt.__index.WAIT_FOR_DATA               = 0x97
new_mt.__index.NO_IMAGE_AVAILABLE          = 0x98
new_mt.__index.REQUIRE_MORE_IMAGE          = 0x99
new_mt.__index.NOTIFICATION_PENDING        = 0x9A
new_mt.__index.HARDWARE_FAILURE            = 0xC0
new_mt.__index.SOFTWARE_FAILURE            = 0xC1
new_mt.__index.CALIBRATION_ERROR           = 0xC2
new_mt.__index.UNSUPPORTED_CLUSTER         = 0xC3
new_mt.__index.LIMIT_REACHED               = 0xC4

setmetatable(ZclStatus, new_mt)

return ZclStatus

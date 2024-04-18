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

-- THIS CODE IS AUTOMATICALLY GENERATED BY zwave_lib_generator/gen.py.  DO NOT HAND EDIT.
--
-- Generator script revision: b'd02f5cbe533e00c31e517a9bbb6edbc6cecc0e69'
-- Protocol definition XML version: 2.7.4

local zw = require "st.zwave"
local buf = require "st.zwave.utils.buf"
local utils = require "st.utils"

--- @class st.zwave.CommandClass.SensorBinary
--- @alias SensorBinary st.zwave.CommandClass.SensorBinary
---
--- Supported versions: 1,2
---
--- @field public SUPPORTED_GET_SENSOR number 0x01 - SENSOR_BINARY_SUPPORTED_GET_SENSOR command id
--- @field public GET number 0x02 - SENSOR_BINARY_GET command id
--- @field public REPORT number 0x03 - SENSOR_BINARY_REPORT command id
--- @field public SUPPORTED_SENSOR_REPORT number 0x04 - SENSOR_BINARY_SUPPORTED_SENSOR_REPORT command id
local SensorBinary = {}
SensorBinary.SUPPORTED_GET_SENSOR = 0x01
SensorBinary.GET = 0x02
SensorBinary.REPORT = 0x03
SensorBinary.SUPPORTED_SENSOR_REPORT = 0x04

SensorBinary._commands = {
  [SensorBinary.SUPPORTED_GET_SENSOR] = "SUPPORTED_GET_SENSOR",
  [SensorBinary.GET] = "GET",
  [SensorBinary.REPORT] = "REPORT",
  [SensorBinary.SUPPORTED_SENSOR_REPORT] = "SUPPORTED_SENSOR_REPORT"
}

--- Instantiate a versioned instance of the SensorBinary Command Class module, optionally setting strict to require explicit passing of all parameters to constructors.
---
--- @param params st.zwave.CommandClass.Params command class instance parameters
--- @return st.zwave.CommandClass.SensorBinary versioned command class instance
function SensorBinary:init(params)
  local version = params and params.version or nil
  if (params or {}).strict ~= nil then
  local strict = params.strict
  else
  local strict = true -- default
  end
  local strict = params and params.strict or nil
  assert(version == nil or zw._versions[zw.SENSOR_BINARY][version] ~= nil, "unsupported version")
  assert(strict == nil or type(strict) == "boolean", "strict must be a boolean")
  local mt = {
    __index = self
  }
  local instance = setmetatable({}, mt)
  instance._serialization_version = version
  instance._strict = strict
  return instance
end

setmetatable(SensorBinary, {
  __call = SensorBinary.init
})

SensorBinary._serialization_version = nil
SensorBinary._strict = false
zw._deserialization_versions = zw.deserialization_versions or {}
zw._versions = zw._versions or {}
setmetatable(zw._deserialization_versions, { __index = zw._versions })
zw._versions[zw.SENSOR_BINARY] = {
  [1] = true,
  [2] = true
}

--- @class st.zwave.CommandClass.SensorBinary.GetV1Args
--- @alias GetV1Args st.zwave.CommandClass.SensorBinary.GetV1Args
local GetV1Args = {}

--- @class st.zwave.CommandClass.SensorBinary.GetV1:st.zwave.Command
--- @alias GetV1 st.zwave.CommandClass.SensorBinary.GetV1
---
--- v1 SENSOR_BINARY_GET
---
--- @field public cmd_class number 0x30
--- @field public cmd_id number 0x02
--- @field public version number 1
--- @field public args st.zwave.CommandClass.SensorBinary.GetV1Args command-specific arguments
local GetV1 = {}
setmetatable(GetV1, {
  __index = zw.Command,
  __call = function(cls, self, ...)
    local mt = {
      __index = function(tbl, key)
        if key == "payload" then
          return tbl:serialize()
        else
          return cls[key]
        end
      end,
      __tostring = zw.Command.pretty_print,
      __eq = zw.Command.equals
    }
    local instance = setmetatable({}, mt)
    instance:init(self, ...)
    return instance
  end,
})

--- Initialize a v1 SENSOR_BINARY_GET object.
---
--- @param module st.zwave.CommandClass.SensorBinary command class module instance
--- @param args st.zwave.CommandClass.SensorBinary.GetV1Args command-specific arguments
function GetV1:init(module, args, ...)
  zw.Command._parse(self, module, zw.SENSOR_BINARY, SensorBinary.GET, 1, args, ...)
end

--- Serialize v1 SENSOR_BINARY_GET arguments.
---
--- @return string serialized payload
function GetV1:serialize()
  local writer = buf.Writer()
  return writer.buf
end

--- Deserialize a v1 SENSOR_BINARY_GET payload.
---
--- @return st.zwave.CommandClass.SensorBinary.GetV1Args deserialized arguments
function GetV1:deserialize()
  local reader = buf.Reader(self.payload)
  return reader.parsed
end

--- Return a deep copy of self.args, merging defaults for unset, but required parameters.
---
--- @param self st.zwave.CommandClass.SensorBinary.GetV1
--- @return st.zwave.CommandClass.SensorBinary.GetV1Args
function GetV1._defaults(self)
  return {}
end

--- Return a deep copy of self.args, merging defaults for all unset parameters.
---
--- @param self st.zwave.CommandClass.SensorBinary.GetV1
--- @return st.zwave.CommandClass.SensorBinary.GetV1Args
function GetV1._template(self)
  return {}
end

--- Set defaults for any required, but unset arguments.
---
--- @param self st.zwave.CommandClass.SensorBinary.GetV1
function GetV1._set_defaults(self)
  local defaults = self:_defaults()
  utils.merge(self.args, defaults)
end

--- Set const reflectors to allow enum stringification.
---
--- @param self st.zwave.CommandClass.SensorBinary.GetV1
function GetV1._set_reflectors(self)
end

--- @class st.zwave.CommandClass.SensorBinary.ReportV1Args
--- @alias ReportV1Args st.zwave.CommandClass.SensorBinary.ReportV1Args
--- @field public sensor_value integer see :lua:class:`SensorBinary.sensor_value <st.zwave.CommandClass.SensorBinary.sensor_value>`
local ReportV1Args = {}

--- @class st.zwave.CommandClass.SensorBinary.ReportV1:st.zwave.Command
--- @alias ReportV1 st.zwave.CommandClass.SensorBinary.ReportV1
---
--- v1 SENSOR_BINARY_REPORT
---
--- @field public cmd_class number 0x30
--- @field public cmd_id number 0x03
--- @field public version number 1
--- @field public args st.zwave.CommandClass.SensorBinary.ReportV1Args command-specific arguments
local ReportV1 = {}
setmetatable(ReportV1, {
  __index = zw.Command,
  __call = function(cls, self, ...)
    local mt = {
      __index = function(tbl, key)
        if key == "payload" then
          return tbl:serialize()
        else
          return cls[key]
        end
      end,
      __tostring = zw.Command.pretty_print,
      __eq = zw.Command.equals
    }
    local instance = setmetatable({}, mt)
    instance:init(self, ...)
    return instance
  end,
})

--- Initialize a v1 SENSOR_BINARY_REPORT object.
---
--- @param module st.zwave.CommandClass.SensorBinary command class module instance
--- @param args st.zwave.CommandClass.SensorBinary.ReportV1Args command-specific arguments
function ReportV1:init(module, args, ...)
  zw.Command._parse(self, module, zw.SENSOR_BINARY, SensorBinary.REPORT, 1, args, ...)
end

--- Serialize v1 SENSOR_BINARY_REPORT arguments.
---
--- @return string serialized payload
function ReportV1:serialize()
  local writer = buf.Writer()
  local args = self.args
  writer:write_u8(args.sensor_value)
  return writer.buf
end

--- Deserialize a v1 SENSOR_BINARY_REPORT payload.
---
--- @return st.zwave.CommandClass.SensorBinary.ReportV1Args deserialized arguments
function ReportV1:deserialize()
  local reader = buf.Reader(self.payload)
  reader:read_u8("sensor_value")
  return reader.parsed
end

--- Return a deep copy of self.args, merging defaults for unset, but required parameters.
---
--- @param self st.zwave.CommandClass.SensorBinary.ReportV1
--- @return st.zwave.CommandClass.SensorBinary.ReportV1Args
function ReportV1._defaults(self)
  local args = {}
  args.sensor_value = self.args.sensor_value or 0
  return args
end

--- Return a deep copy of self.args, merging defaults for all unset parameters.
---
--- @param self st.zwave.CommandClass.SensorBinary.ReportV1
--- @return st.zwave.CommandClass.SensorBinary.ReportV1Args
function ReportV1._template(self)
  local args = self:_defaults()
  return args
end

--- Set defaults for any required, but unset arguments.
---
--- @param self st.zwave.CommandClass.SensorBinary.ReportV1
function ReportV1._set_defaults(self)
  local defaults = self:_defaults()
  utils.merge(self.args, defaults)
end

--- Set const reflectors to allow enum stringification.
---
--- @param self st.zwave.CommandClass.SensorBinary.ReportV1
function ReportV1._set_reflectors(self)
  local args = self.args
  args._reflect = args._reflect or {}
  args._reflect.sensor_value = function()
    return zw._reflect(
      SensorBinary._reflect_sensor_value,
      args.sensor_value
    )
  end
end

--- @class st.zwave.CommandClass.SensorBinary.SupportedGetSensorV2Args
--- @alias SupportedGetSensorV2Args st.zwave.CommandClass.SensorBinary.SupportedGetSensorV2Args
local SupportedGetSensorV2Args = {}

--- @class st.zwave.CommandClass.SensorBinary.SupportedGetSensorV2:st.zwave.Command
--- @alias SupportedGetSensorV2 st.zwave.CommandClass.SensorBinary.SupportedGetSensorV2
---
--- v2 SENSOR_BINARY_SUPPORTED_GET_SENSOR
---
--- @field public cmd_class number 0x30
--- @field public cmd_id number 0x01
--- @field public version number 2
--- @field public args st.zwave.CommandClass.SensorBinary.SupportedGetSensorV2Args command-specific arguments
local SupportedGetSensorV2 = {}
setmetatable(SupportedGetSensorV2, {
  __index = zw.Command,
  __call = function(cls, self, ...)
    local mt = {
      __index = function(tbl, key)
        if key == "payload" then
          return tbl:serialize()
        else
          return cls[key]
        end
      end,
      __tostring = zw.Command.pretty_print,
      __eq = zw.Command.equals
    }
    local instance = setmetatable({}, mt)
    instance:init(self, ...)
    return instance
  end,
})

--- Initialize a v2 SENSOR_BINARY_SUPPORTED_GET_SENSOR object.
---
--- @param module st.zwave.CommandClass.SensorBinary command class module instance
--- @param args st.zwave.CommandClass.SensorBinary.SupportedGetSensorV2Args command-specific arguments
function SupportedGetSensorV2:init(module, args, ...)
  zw.Command._parse(self, module, zw.SENSOR_BINARY, SensorBinary.SUPPORTED_GET_SENSOR, 2, args, ...)
end

--- Serialize v2 SENSOR_BINARY_SUPPORTED_GET_SENSOR arguments.
---
--- @return string serialized payload
function SupportedGetSensorV2:serialize()
  local writer = buf.Writer()
  return writer.buf
end

--- Deserialize a v2 SENSOR_BINARY_SUPPORTED_GET_SENSOR payload.
---
--- @return st.zwave.CommandClass.SensorBinary.SupportedGetSensorV2Args deserialized arguments
function SupportedGetSensorV2:deserialize()
  local reader = buf.Reader(self.payload)
  return reader.parsed
end

--- Return a deep copy of self.args, merging defaults for unset, but required parameters.
---
--- @param self st.zwave.CommandClass.SensorBinary.SupportedGetSensorV2
--- @return st.zwave.CommandClass.SensorBinary.SupportedGetSensorV2Args
function SupportedGetSensorV2._defaults(self)
  return {}
end

--- Return a deep copy of self.args, merging defaults for all unset parameters.
---
--- @param self st.zwave.CommandClass.SensorBinary.SupportedGetSensorV2
--- @return st.zwave.CommandClass.SensorBinary.SupportedGetSensorV2Args
function SupportedGetSensorV2._template(self)
  return {}
end

--- Set defaults for any required, but unset arguments.
---
--- @param self st.zwave.CommandClass.SensorBinary.SupportedGetSensorV2
function SupportedGetSensorV2._set_defaults(self)
  local defaults = self:_defaults()
  utils.merge(self.args, defaults)
end

--- Set const reflectors to allow enum stringification.
---
--- @param self st.zwave.CommandClass.SensorBinary.SupportedGetSensorV2
function SupportedGetSensorV2._set_reflectors(self)
end

--- @class st.zwave.CommandClass.SensorBinary.GetV2Args
--- @alias GetV2Args st.zwave.CommandClass.SensorBinary.GetV2Args
--- @field public sensor_type integer see :lua:class:`SensorBinary.sensor_type <st.zwave.CommandClass.SensorBinary.sensor_type>`
local GetV2Args = {}

--- @class st.zwave.CommandClass.SensorBinary.GetV2:st.zwave.Command
--- @alias GetV2 st.zwave.CommandClass.SensorBinary.GetV2
---
--- v2 SENSOR_BINARY_GET
---
--- @field public cmd_class number 0x30
--- @field public cmd_id number 0x02
--- @field public version number 2
--- @field public args st.zwave.CommandClass.SensorBinary.GetV2Args command-specific arguments
local GetV2 = {}
setmetatable(GetV2, {
  __index = zw.Command,
  __call = function(cls, self, ...)
    local mt = {
      __index = function(tbl, key)
        if key == "payload" then
          return tbl:serialize()
        else
          return cls[key]
        end
      end,
      __tostring = zw.Command.pretty_print,
      __eq = zw.Command.equals
    }
    local instance = setmetatable({}, mt)
    instance:init(self, ...)
    return instance
  end,
})

--- Initialize a v2 SENSOR_BINARY_GET object.
---
--- @param module st.zwave.CommandClass.SensorBinary command class module instance
--- @param args st.zwave.CommandClass.SensorBinary.GetV2Args command-specific arguments
function GetV2:init(module, args, ...)
  zw.Command._parse(self, module, zw.SENSOR_BINARY, SensorBinary.GET, 2, args, ...)
end

--- Serialize v2 SENSOR_BINARY_GET arguments.
---
--- @return string serialized payload
function GetV2:serialize()
  local writer = buf.Writer()
  local args = self.args
  writer:write_u8(args.sensor_type)
  return writer.buf
end

--- Deserialize a v2 SENSOR_BINARY_GET payload.
---
--- @return st.zwave.CommandClass.SensorBinary.GetV2Args deserialized arguments
function GetV2:deserialize()
  local reader = buf.Reader(self.payload)
  reader:read_u8("sensor_type")
  return reader.parsed
end

--- Return a deep copy of self.args, merging defaults for unset, but required parameters.
---
--- @param self st.zwave.CommandClass.SensorBinary.GetV2
--- @return st.zwave.CommandClass.SensorBinary.GetV2Args
function GetV2._defaults(self)
  local args = {}
  args.sensor_type = self.args.sensor_type or 0
  return args
end

--- Return a deep copy of self.args, merging defaults for all unset parameters.
---
--- @param self st.zwave.CommandClass.SensorBinary.GetV2
--- @return st.zwave.CommandClass.SensorBinary.GetV2Args
function GetV2._template(self)
  local args = self:_defaults()
  return args
end

--- Set defaults for any required, but unset arguments.
---
--- @param self st.zwave.CommandClass.SensorBinary.GetV2
function GetV2._set_defaults(self)
  local defaults = self:_defaults()
  utils.merge(self.args, defaults)
end

--- Set const reflectors to allow enum stringification.
---
--- @param self st.zwave.CommandClass.SensorBinary.GetV2
function GetV2._set_reflectors(self)
  local args = self.args
  args._reflect = args._reflect or {}
  args._reflect.sensor_type = function()
    return zw._reflect(
      SensorBinary._reflect_sensor_type,
      args.sensor_type
    )
  end
end

--- @class st.zwave.CommandClass.SensorBinary.ReportV2Args
--- @alias ReportV2Args st.zwave.CommandClass.SensorBinary.ReportV2Args
--- @field public sensor_value integer see :lua:class:`SensorBinary.sensor_value <st.zwave.CommandClass.SensorBinary.sensor_value>`
--- @field public sensor_type integer see :lua:class:`SensorBinary.sensor_type <st.zwave.CommandClass.SensorBinary.sensor_type>`
local ReportV2Args = {}

--- @class st.zwave.CommandClass.SensorBinary.ReportV2:st.zwave.Command
--- @alias ReportV2 st.zwave.CommandClass.SensorBinary.ReportV2
---
--- v2 SENSOR_BINARY_REPORT
---
--- @field public cmd_class number 0x30
--- @field public cmd_id number 0x03
--- @field public version number 2
--- @field public args st.zwave.CommandClass.SensorBinary.ReportV2Args command-specific arguments
local ReportV2 = {}
setmetatable(ReportV2, {
  __index = zw.Command,
  __call = function(cls, self, ...)
    local mt = {
      __index = function(tbl, key)
        if key == "payload" then
          return tbl:serialize()
        else
          return cls[key]
        end
      end,
      __tostring = zw.Command.pretty_print,
      __eq = zw.Command.equals
    }
    local instance = setmetatable({}, mt)
    instance:init(self, ...)
    return instance
  end,
})

--- Initialize a v2 SENSOR_BINARY_REPORT object.
---
--- @param module st.zwave.CommandClass.SensorBinary command class module instance
--- @param args st.zwave.CommandClass.SensorBinary.ReportV2Args command-specific arguments
function ReportV2:init(module, args, ...)
  zw.Command._parse(self, module, zw.SENSOR_BINARY, SensorBinary.REPORT, 2, args, ...)
end

--- Serialize v2 SENSOR_BINARY_REPORT arguments.
---
--- @return string serialized payload
function ReportV2:serialize()
  local writer = buf.Writer()
  local args = self.args
  writer:write_u8(args.sensor_value)
  writer:write_u8(args.sensor_type)
  return writer.buf
end

--- Deserialize a v2 SENSOR_BINARY_REPORT payload.
---
--- @return st.zwave.CommandClass.SensorBinary.ReportV2Args deserialized arguments
function ReportV2:deserialize()
  local reader = buf.Reader(self.payload)
  reader:read_u8("sensor_value")
  reader:read_u8("sensor_type")
  return reader.parsed
end

--- Return a deep copy of self.args, merging defaults for unset, but required parameters.
---
--- @param self st.zwave.CommandClass.SensorBinary.ReportV2
--- @return st.zwave.CommandClass.SensorBinary.ReportV2Args
function ReportV2._defaults(self)
  local args = {}
  args.sensor_value = self.args.sensor_value or 0
  args.sensor_type = self.args.sensor_type or 0
  return args
end

--- Return a deep copy of self.args, merging defaults for all unset parameters.
---
--- @param self st.zwave.CommandClass.SensorBinary.ReportV2
--- @return st.zwave.CommandClass.SensorBinary.ReportV2Args
function ReportV2._template(self)
  local args = self:_defaults()
  return args
end

--- Set defaults for any required, but unset arguments.
---
--- @param self st.zwave.CommandClass.SensorBinary.ReportV2
function ReportV2._set_defaults(self)
  local defaults = self:_defaults()
  utils.merge(self.args, defaults)
end

--- Set const reflectors to allow enum stringification.
---
--- @param self st.zwave.CommandClass.SensorBinary.ReportV2
function ReportV2._set_reflectors(self)
  local args = self.args
  args._reflect = args._reflect or {}
  args._reflect.sensor_value = function()
    return zw._reflect(
      SensorBinary._reflect_sensor_value,
      args.sensor_value
    )
  end
  args._reflect = args._reflect or {}
  args._reflect.sensor_type = function()
    return zw._reflect(
      SensorBinary._reflect_sensor_type,
      args.sensor_type
    )
  end
end

--- @class st.zwave.CommandClass.SensorBinary.SupportedSensorReportV2Args
--- @alias SupportedSensorReportV2Args st.zwave.CommandClass.SensorBinary.SupportedSensorReportV2Args
--- @field public general boolean
--- @field public smoke boolean
--- @field public co boolean
--- @field public co2 boolean
--- @field public heat boolean
--- @field public water boolean
--- @field public freeze boolean
--- @field public tamper boolean
--- @field public aux boolean
--- @field public door_window boolean
--- @field public tilt boolean
--- @field public motion boolean
--- @field public glass_break boolean
local SupportedSensorReportV2Args = {}

--- @class st.zwave.CommandClass.SensorBinary.SupportedSensorReportV2:st.zwave.Command
--- @alias SupportedSensorReportV2 st.zwave.CommandClass.SensorBinary.SupportedSensorReportV2
---
--- v2 SENSOR_BINARY_SUPPORTED_SENSOR_REPORT
---
--- @field public cmd_class number 0x30
--- @field public cmd_id number 0x04
--- @field public version number 2
--- @field public args st.zwave.CommandClass.SensorBinary.SupportedSensorReportV2Args command-specific arguments
local SupportedSensorReportV2 = {}
setmetatable(SupportedSensorReportV2, {
  __index = zw.Command,
  __call = function(cls, self, ...)
    local mt = {
      __index = function(tbl, key)
        if key == "payload" then
          return tbl:serialize()
        else
          return cls[key]
        end
      end,
      __tostring = zw.Command.pretty_print,
      __eq = zw.Command.equals
    }
    local instance = setmetatable({}, mt)
    instance:init(self, ...)
    return instance
  end,
})

--- Initialize a v2 SENSOR_BINARY_SUPPORTED_SENSOR_REPORT object.
---
--- @param module st.zwave.CommandClass.SensorBinary command class module instance
--- @param args st.zwave.CommandClass.SensorBinary.SupportedSensorReportV2Args command-specific arguments
function SupportedSensorReportV2:init(module, args, ...)
  zw.Command._parse(self, module, zw.SENSOR_BINARY, SensorBinary.SUPPORTED_SENSOR_REPORT, 2, args, ...)
end

--- Serialize v2 SENSOR_BINARY_SUPPORTED_SENSOR_REPORT arguments.
---
--- @return string serialized payload
function SupportedSensorReportV2:serialize()
  local writer = buf.Writer()
  local args = self.args
  writer:write_bool(false) -- reserved
  writer:write_bool(args.general)
  writer:write_bool(args.smoke)
  writer:write_bool(args.co)
  writer:write_bool(args.co2)
  writer:write_bool(args.heat)
  writer:write_bool(args.water)
  writer:write_bool(args.freeze)
  writer:write_bool(args.tamper)
  writer:write_bool(args.aux)
  writer:write_bool(args.door_window)
  writer:write_bool(args.tilt)
  writer:write_bool(args.motion)
  writer:write_bool(args.glass_break)
  return writer.buf
end

--- Deserialize a v2 SENSOR_BINARY_SUPPORTED_SENSOR_REPORT payload.
---
--- @return st.zwave.CommandClass.SensorBinary.SupportedSensorReportV2Args deserialized arguments
function SupportedSensorReportV2:deserialize()
  local reader = buf.Reader(self.payload)
  reader:read_bool() -- reserved
  reader:read_bool("general")
  reader:read_bool("smoke")
  reader:read_bool("co")
  reader:read_bool("co2")
  reader:read_bool("heat")
  reader:read_bool("water")
  reader:read_bool("freeze")
  reader:read_bool("tamper")
  reader:read_bool("aux")
  reader:read_bool("door_window")
  reader:read_bool("tilt")
  reader:read_bool("motion")
  reader:read_bool("glass_break")
  return reader.parsed
end

--- Return a deep copy of self.args, merging defaults for unset, but required parameters.
---
--- @param self st.zwave.CommandClass.SensorBinary.SupportedSensorReportV2
--- @return st.zwave.CommandClass.SensorBinary.SupportedSensorReportV2Args
function SupportedSensorReportV2._defaults(self)
  local args = {}
  args.general = self.args.general or false
  args.smoke = self.args.smoke or false
  args.co = self.args.co or false
  args.co2 = self.args.co2 or false
  args.heat = self.args.heat or false
  args.water = self.args.water or false
  args.freeze = self.args.freeze or false
  args.tamper = self.args.tamper or false
  args.aux = self.args.aux or false
  args.door_window = self.args.door_window or false
  args.tilt = self.args.tilt or false
  args.motion = self.args.motion or false
  args.glass_break = self.args.glass_break or false
  return args
end

--- Return a deep copy of self.args, merging defaults for all unset parameters.
---
--- @param self st.zwave.CommandClass.SensorBinary.SupportedSensorReportV2
--- @return st.zwave.CommandClass.SensorBinary.SupportedSensorReportV2Args
function SupportedSensorReportV2._template(self)
  local args = self:_defaults()
  return args
end

--- Set defaults for any required, but unset arguments.
---
--- @param self st.zwave.CommandClass.SensorBinary.SupportedSensorReportV2
function SupportedSensorReportV2._set_defaults(self)
  local defaults = self:_defaults()
  utils.merge(self.args, defaults)
end

--- Set const reflectors to allow enum stringification.
---
--- @param self st.zwave.CommandClass.SensorBinary.SupportedSensorReportV2
function SupportedSensorReportV2._set_reflectors(self)
end

--- @class st.zwave.CommandClass.SensorBinary.Get
--- @alias _Get st.zwave.CommandClass.SensorBinary.Get
---
--- Dynamically versioned SENSOR_BINARY_GET
---
--- Supported versions: 1,2; unique base versions: 1,2
---
--- @field public cmd_class number 0x30
--- @field public cmd_id number 0x02
--- @field public version number 1,2
--- @field public args st.zwave.CommandClass.SensorBinary.GetV1Args|st.zwave.CommandClass.SensorBinary.GetV2Args
local _Get = {}
setmetatable(_Get, {
  __call = function(cls, self, ...)
    return cls:construct(self, ...)
  end,
})

--- Construct a SENSOR_BINARY_GET object at the module instance serialization version.
---
--- @param module st.zwave.CommandClass.SensorBinary command class module instance
--- @param args st.zwave.CommandClass.SensorBinary.GetV1Args|st.zwave.CommandClass.SensorBinary.GetV2Args command-specific arguments
--- @return st.zwave.CommandClass.SensorBinary.Get
function _Get:construct(module, args, ...)
  return zw.Command._construct(module, SensorBinary.GET, module._serialization_version, args, ...)
end

--- @class st.zwave.CommandClass.SensorBinary.Report
--- @alias _Report st.zwave.CommandClass.SensorBinary.Report
---
--- Dynamically versioned SENSOR_BINARY_REPORT
---
--- Supported versions: 1,2; unique base versions: 1,2
---
--- @field public cmd_class number 0x30
--- @field public cmd_id number 0x03
--- @field public version number 1,2
--- @field public args st.zwave.CommandClass.SensorBinary.ReportV1Args|st.zwave.CommandClass.SensorBinary.ReportV2Args
local _Report = {}
setmetatable(_Report, {
  __call = function(cls, self, ...)
    return cls:construct(self, ...)
  end,
})

--- Construct a SENSOR_BINARY_REPORT object at the module instance serialization version.
---
--- @param module st.zwave.CommandClass.SensorBinary command class module instance
--- @param args st.zwave.CommandClass.SensorBinary.ReportV1Args|st.zwave.CommandClass.SensorBinary.ReportV2Args command-specific arguments
--- @return st.zwave.CommandClass.SensorBinary.Report
function _Report:construct(module, args, ...)
  return zw.Command._construct(module, SensorBinary.REPORT, module._serialization_version, args, ...)
end

--- @class st.zwave.CommandClass.SensorBinary.SupportedGetSensor
--- @alias _SupportedGetSensor st.zwave.CommandClass.SensorBinary.SupportedGetSensor
---
--- Dynamically versioned SENSOR_BINARY_SUPPORTED_GET_SENSOR
---
--- Supported versions: 2; unique base versions: 2
---
--- @field public cmd_class number 0x30
--- @field public cmd_id number 0x01
--- @field public version number 2
--- @field public args st.zwave.CommandClass.SensorBinary.SupportedGetSensorV2Args
local _SupportedGetSensor = {}
setmetatable(_SupportedGetSensor, {
  __call = function(cls, self, ...)
    return cls:construct(self, ...)
  end,
})

--- Construct a SENSOR_BINARY_SUPPORTED_GET_SENSOR object at the module instance serialization version.
---
--- @param module st.zwave.CommandClass.SensorBinary command class module instance
--- @param args st.zwave.CommandClass.SensorBinary.SupportedGetSensorV2Args command-specific arguments
--- @return st.zwave.CommandClass.SensorBinary.SupportedGetSensor
function _SupportedGetSensor:construct(module, args, ...)
  return zw.Command._construct(module, SensorBinary.SUPPORTED_GET_SENSOR, module._serialization_version, args, ...)
end

--- @class st.zwave.CommandClass.SensorBinary.SupportedSensorReport
--- @alias _SupportedSensorReport st.zwave.CommandClass.SensorBinary.SupportedSensorReport
---
--- Dynamically versioned SENSOR_BINARY_SUPPORTED_SENSOR_REPORT
---
--- Supported versions: 2; unique base versions: 2
---
--- @field public cmd_class number 0x30
--- @field public cmd_id number 0x04
--- @field public version number 2
--- @field public args st.zwave.CommandClass.SensorBinary.SupportedSensorReportV2Args
local _SupportedSensorReport = {}
setmetatable(_SupportedSensorReport, {
  __call = function(cls, self, ...)
    return cls:construct(self, ...)
  end,
})

--- Construct a SENSOR_BINARY_SUPPORTED_SENSOR_REPORT object at the module instance serialization version.
---
--- @param module st.zwave.CommandClass.SensorBinary command class module instance
--- @param args st.zwave.CommandClass.SensorBinary.SupportedSensorReportV2Args command-specific arguments
--- @return st.zwave.CommandClass.SensorBinary.SupportedSensorReport
function _SupportedSensorReport:construct(module, args, ...)
  return zw.Command._construct(module, SensorBinary.SUPPORTED_SENSOR_REPORT, module._serialization_version, args, ...)
end

SensorBinary.GetV1 = GetV1
SensorBinary.ReportV1 = ReportV1
SensorBinary.SupportedGetSensorV2 = SupportedGetSensorV2
SensorBinary.GetV2 = GetV2
SensorBinary.ReportV2 = ReportV2
SensorBinary.SupportedSensorReportV2 = SupportedSensorReportV2
SensorBinary.Get = _Get
SensorBinary.Report = _Report
SensorBinary.SupportedGetSensor = _SupportedGetSensor
SensorBinary.SupportedSensorReport = _SupportedSensorReport

SensorBinary._lut = {
  [0] = { -- dynamically versioned constructors
    [SensorBinary.SUPPORTED_GET_SENSOR] = SensorBinary.SupportedGetSensor,
    [SensorBinary.GET] = SensorBinary.Get,
    [SensorBinary.REPORT] = SensorBinary.Report,
    [SensorBinary.SUPPORTED_SENSOR_REPORT] = SensorBinary.SupportedSensorReport
  },
  [1] = { -- version 1
    [SensorBinary.GET] = SensorBinary.GetV1,
    [SensorBinary.REPORT] = SensorBinary.ReportV1
  },
  [2] = { -- version 2
    [SensorBinary.SUPPORTED_GET_SENSOR] = SensorBinary.SupportedGetSensorV2,
    [SensorBinary.GET] = SensorBinary.GetV2,
    [SensorBinary.REPORT] = SensorBinary.ReportV2,
    [SensorBinary.SUPPORTED_SENSOR_REPORT] = SensorBinary.SupportedSensorReportV2
  }
}
--- @class st.zwave.CommandClass.SensorBinary.sensor_type
--- @alias sensor_type st.zwave.CommandClass.SensorBinary.sensor_type
--- @field public GENERAL number 0x01
--- @field public SMOKE number 0x02
--- @field public CO number 0x03
--- @field public CO2 number 0x04
--- @field public HEAT number 0x05
--- @field public WATER number 0x06
--- @field public FREEZE number 0x07
--- @field public TAMPER number 0x08
--- @field public AUX number 0x09
--- @field public DOOR_WINDOW number 0x0A
--- @field public TILT number 0x0B
--- @field public MOTION number 0x0C
--- @field public GLASS_BREAK number 0x0D
--- @field public FIRST number 0xFF
local sensor_type = {
  GENERAL = 0x01,
  SMOKE = 0x02,
  CO = 0x03,
  CO2 = 0x04,
  HEAT = 0x05,
  WATER = 0x06,
  FREEZE = 0x07,
  TAMPER = 0x08,
  AUX = 0x09,
  DOOR_WINDOW = 0x0A,
  TILT = 0x0B,
  MOTION = 0x0C,
  GLASS_BREAK = 0x0D,
  FIRST = 0xFF
}
SensorBinary.sensor_type = sensor_type
SensorBinary._reflect_sensor_type = zw._reflection_builder(SensorBinary.sensor_type)

--- @class st.zwave.CommandClass.SensorBinary.sensor_value
--- @alias sensor_value st.zwave.CommandClass.SensorBinary.sensor_value
--- @field public IDLE number 0x00
--- @field public DETECTED_AN_EVENT number 0xFF
local sensor_value = {
  IDLE = 0x00,
  DETECTED_AN_EVENT = 0xFF
}
SensorBinary.sensor_value = sensor_value
SensorBinary._reflect_sensor_value = zw._reflection_builder(SensorBinary.sensor_value)


return SensorBinary
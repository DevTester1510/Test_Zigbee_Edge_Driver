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

--- @class st.zwave.CommandClass.SwitchAll
--- @alias SwitchAll st.zwave.CommandClass.SwitchAll
---
--- Supported versions: 1
---
--- @field public SET number 0x01 - SWITCH_ALL_SET command id
--- @field public GET number 0x02 - SWITCH_ALL_GET command id
--- @field public REPORT number 0x03 - SWITCH_ALL_REPORT command id
--- @field public ON number 0x04 - SWITCH_ALL_ON command id
--- @field public OFF number 0x05 - SWITCH_ALL_OFF command id
local SwitchAll = {}
SwitchAll.SET = 0x01
SwitchAll.GET = 0x02
SwitchAll.REPORT = 0x03
SwitchAll.ON = 0x04
SwitchAll.OFF = 0x05

SwitchAll._commands = {
  [SwitchAll.SET] = "SET",
  [SwitchAll.GET] = "GET",
  [SwitchAll.REPORT] = "REPORT",
  [SwitchAll.ON] = "ON",
  [SwitchAll.OFF] = "OFF"
}

--- Instantiate a versioned instance of the SwitchAll Command Class module, optionally setting strict to require explicit passing of all parameters to constructors.
---
--- @param params st.zwave.CommandClass.Params command class instance parameters
--- @return st.zwave.CommandClass.SwitchAll versioned command class instance
function SwitchAll:init(params)
  local version = params and params.version or nil
  if (params or {}).strict ~= nil then
  local strict = params.strict
  else
  local strict = true -- default
  end
  local strict = params and params.strict or nil
  assert(version == nil or zw._versions[zw.SWITCH_ALL][version] ~= nil, "unsupported version")
  assert(strict == nil or type(strict) == "boolean", "strict must be a boolean")
  local mt = {
    __index = self
  }
  local instance = setmetatable({}, mt)
  instance._serialization_version = version
  instance._strict = strict
  return instance
end

setmetatable(SwitchAll, {
  __call = SwitchAll.init
})

SwitchAll._serialization_version = nil
SwitchAll._strict = false
zw._deserialization_versions = zw.deserialization_versions or {}
zw._versions = zw._versions or {}
setmetatable(zw._deserialization_versions, { __index = zw._versions })
zw._versions[zw.SWITCH_ALL] = {
  [1] = true
}

--- @class st.zwave.CommandClass.SwitchAll.SetV1Args
--- @alias SetV1Args st.zwave.CommandClass.SwitchAll.SetV1Args
--- @field public mode integer see :lua:class:`SwitchAll.mode <st.zwave.CommandClass.SwitchAll.mode>`
local SetV1Args = {}

--- @class st.zwave.CommandClass.SwitchAll.SetV1:st.zwave.Command
--- @alias SetV1 st.zwave.CommandClass.SwitchAll.SetV1
---
--- v1 SWITCH_ALL_SET
---
--- @field public cmd_class number 0x27
--- @field public cmd_id number 0x01
--- @field public version number 1
--- @field public args st.zwave.CommandClass.SwitchAll.SetV1Args command-specific arguments
local SetV1 = {}
setmetatable(SetV1, {
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

--- Initialize a v1 SWITCH_ALL_SET object.
---
--- @param module st.zwave.CommandClass.SwitchAll command class module instance
--- @param args st.zwave.CommandClass.SwitchAll.SetV1Args command-specific arguments
function SetV1:init(module, args, ...)
  zw.Command._parse(self, module, zw.SWITCH_ALL, SwitchAll.SET, 1, args, ...)
end

--- Serialize v1 SWITCH_ALL_SET arguments.
---
--- @return string serialized payload
function SetV1:serialize()
  local writer = buf.Writer()
  local args = self.args
  writer:write_u8(args.mode)
  return writer.buf
end

--- Deserialize a v1 SWITCH_ALL_SET payload.
---
--- @return st.zwave.CommandClass.SwitchAll.SetV1Args deserialized arguments
function SetV1:deserialize()
  local reader = buf.Reader(self.payload)
  reader:read_u8("mode")
  return reader.parsed
end

--- Return a deep copy of self.args, merging defaults for unset, but required parameters.
---
--- @param self st.zwave.CommandClass.SwitchAll.SetV1
--- @return st.zwave.CommandClass.SwitchAll.SetV1Args
function SetV1._defaults(self)
  local args = {}
  args.mode = self.args.mode or 0
  return args
end

--- Return a deep copy of self.args, merging defaults for all unset parameters.
---
--- @param self st.zwave.CommandClass.SwitchAll.SetV1
--- @return st.zwave.CommandClass.SwitchAll.SetV1Args
function SetV1._template(self)
  local args = self:_defaults()
  return args
end

--- Set defaults for any required, but unset arguments.
---
--- @param self st.zwave.CommandClass.SwitchAll.SetV1
function SetV1._set_defaults(self)
  local defaults = self:_defaults()
  utils.merge(self.args, defaults)
end

--- Set const reflectors to allow enum stringification.
---
--- @param self st.zwave.CommandClass.SwitchAll.SetV1
function SetV1._set_reflectors(self)
  local args = self.args
  args._reflect = args._reflect or {}
  args._reflect.mode = function()
    return zw._reflect(
      SwitchAll._reflect_mode,
      args.mode
    )
  end
end

--- @class st.zwave.CommandClass.SwitchAll.GetV1Args
--- @alias GetV1Args st.zwave.CommandClass.SwitchAll.GetV1Args
local GetV1Args = {}

--- @class st.zwave.CommandClass.SwitchAll.GetV1:st.zwave.Command
--- @alias GetV1 st.zwave.CommandClass.SwitchAll.GetV1
---
--- v1 SWITCH_ALL_GET
---
--- @field public cmd_class number 0x27
--- @field public cmd_id number 0x02
--- @field public version number 1
--- @field public args st.zwave.CommandClass.SwitchAll.GetV1Args command-specific arguments
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

--- Initialize a v1 SWITCH_ALL_GET object.
---
--- @param module st.zwave.CommandClass.SwitchAll command class module instance
--- @param args st.zwave.CommandClass.SwitchAll.GetV1Args command-specific arguments
function GetV1:init(module, args, ...)
  zw.Command._parse(self, module, zw.SWITCH_ALL, SwitchAll.GET, 1, args, ...)
end

--- Serialize v1 SWITCH_ALL_GET arguments.
---
--- @return string serialized payload
function GetV1:serialize()
  local writer = buf.Writer()
  return writer.buf
end

--- Deserialize a v1 SWITCH_ALL_GET payload.
---
--- @return st.zwave.CommandClass.SwitchAll.GetV1Args deserialized arguments
function GetV1:deserialize()
  local reader = buf.Reader(self.payload)
  return reader.parsed
end

--- Return a deep copy of self.args, merging defaults for unset, but required parameters.
---
--- @param self st.zwave.CommandClass.SwitchAll.GetV1
--- @return st.zwave.CommandClass.SwitchAll.GetV1Args
function GetV1._defaults(self)
  return {}
end

--- Return a deep copy of self.args, merging defaults for all unset parameters.
---
--- @param self st.zwave.CommandClass.SwitchAll.GetV1
--- @return st.zwave.CommandClass.SwitchAll.GetV1Args
function GetV1._template(self)
  return {}
end

--- Set defaults for any required, but unset arguments.
---
--- @param self st.zwave.CommandClass.SwitchAll.GetV1
function GetV1._set_defaults(self)
  local defaults = self:_defaults()
  utils.merge(self.args, defaults)
end

--- Set const reflectors to allow enum stringification.
---
--- @param self st.zwave.CommandClass.SwitchAll.GetV1
function GetV1._set_reflectors(self)
end

--- @class st.zwave.CommandClass.SwitchAll.ReportV1Args
--- @alias ReportV1Args st.zwave.CommandClass.SwitchAll.ReportV1Args
--- @field public mode integer see :lua:class:`SwitchAll.mode <st.zwave.CommandClass.SwitchAll.mode>`
local ReportV1Args = {}

--- @class st.zwave.CommandClass.SwitchAll.ReportV1:st.zwave.Command
--- @alias ReportV1 st.zwave.CommandClass.SwitchAll.ReportV1
---
--- v1 SWITCH_ALL_REPORT
---
--- @field public cmd_class number 0x27
--- @field public cmd_id number 0x03
--- @field public version number 1
--- @field public args st.zwave.CommandClass.SwitchAll.ReportV1Args command-specific arguments
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

--- Initialize a v1 SWITCH_ALL_REPORT object.
---
--- @param module st.zwave.CommandClass.SwitchAll command class module instance
--- @param args st.zwave.CommandClass.SwitchAll.ReportV1Args command-specific arguments
function ReportV1:init(module, args, ...)
  zw.Command._parse(self, module, zw.SWITCH_ALL, SwitchAll.REPORT, 1, args, ...)
end

--- Serialize v1 SWITCH_ALL_REPORT arguments.
---
--- @return string serialized payload
function ReportV1:serialize()
  local writer = buf.Writer()
  local args = self.args
  writer:write_u8(args.mode)
  return writer.buf
end

--- Deserialize a v1 SWITCH_ALL_REPORT payload.
---
--- @return st.zwave.CommandClass.SwitchAll.ReportV1Args deserialized arguments
function ReportV1:deserialize()
  local reader = buf.Reader(self.payload)
  reader:read_u8("mode")
  return reader.parsed
end

--- Return a deep copy of self.args, merging defaults for unset, but required parameters.
---
--- @param self st.zwave.CommandClass.SwitchAll.ReportV1
--- @return st.zwave.CommandClass.SwitchAll.ReportV1Args
function ReportV1._defaults(self)
  local args = {}
  args.mode = self.args.mode or 0
  return args
end

--- Return a deep copy of self.args, merging defaults for all unset parameters.
---
--- @param self st.zwave.CommandClass.SwitchAll.ReportV1
--- @return st.zwave.CommandClass.SwitchAll.ReportV1Args
function ReportV1._template(self)
  local args = self:_defaults()
  return args
end

--- Set defaults for any required, but unset arguments.
---
--- @param self st.zwave.CommandClass.SwitchAll.ReportV1
function ReportV1._set_defaults(self)
  local defaults = self:_defaults()
  utils.merge(self.args, defaults)
end

--- Set const reflectors to allow enum stringification.
---
--- @param self st.zwave.CommandClass.SwitchAll.ReportV1
function ReportV1._set_reflectors(self)
  local args = self.args
  args._reflect = args._reflect or {}
  args._reflect.mode = function()
    return zw._reflect(
      SwitchAll._reflect_mode,
      args.mode
    )
  end
end

--- @class st.zwave.CommandClass.SwitchAll.OnV1Args
--- @alias OnV1Args st.zwave.CommandClass.SwitchAll.OnV1Args
local OnV1Args = {}

--- @class st.zwave.CommandClass.SwitchAll.OnV1:st.zwave.Command
--- @alias OnV1 st.zwave.CommandClass.SwitchAll.OnV1
---
--- v1 SWITCH_ALL_ON
---
--- @field public cmd_class number 0x27
--- @field public cmd_id number 0x04
--- @field public version number 1
--- @field public args st.zwave.CommandClass.SwitchAll.OnV1Args command-specific arguments
local OnV1 = {}
setmetatable(OnV1, {
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

--- Initialize a v1 SWITCH_ALL_ON object.
---
--- @param module st.zwave.CommandClass.SwitchAll command class module instance
--- @param args st.zwave.CommandClass.SwitchAll.OnV1Args command-specific arguments
function OnV1:init(module, args, ...)
  zw.Command._parse(self, module, zw.SWITCH_ALL, SwitchAll.ON, 1, args, ...)
end

--- Serialize v1 SWITCH_ALL_ON arguments.
---
--- @return string serialized payload
function OnV1:serialize()
  local writer = buf.Writer()
  return writer.buf
end

--- Deserialize a v1 SWITCH_ALL_ON payload.
---
--- @return st.zwave.CommandClass.SwitchAll.OnV1Args deserialized arguments
function OnV1:deserialize()
  local reader = buf.Reader(self.payload)
  return reader.parsed
end

--- Return a deep copy of self.args, merging defaults for unset, but required parameters.
---
--- @param self st.zwave.CommandClass.SwitchAll.OnV1
--- @return st.zwave.CommandClass.SwitchAll.OnV1Args
function OnV1._defaults(self)
  return {}
end

--- Return a deep copy of self.args, merging defaults for all unset parameters.
---
--- @param self st.zwave.CommandClass.SwitchAll.OnV1
--- @return st.zwave.CommandClass.SwitchAll.OnV1Args
function OnV1._template(self)
  return {}
end

--- Set defaults for any required, but unset arguments.
---
--- @param self st.zwave.CommandClass.SwitchAll.OnV1
function OnV1._set_defaults(self)
  local defaults = self:_defaults()
  utils.merge(self.args, defaults)
end

--- Set const reflectors to allow enum stringification.
---
--- @param self st.zwave.CommandClass.SwitchAll.OnV1
function OnV1._set_reflectors(self)
end

--- @class st.zwave.CommandClass.SwitchAll.OffV1Args
--- @alias OffV1Args st.zwave.CommandClass.SwitchAll.OffV1Args
local OffV1Args = {}

--- @class st.zwave.CommandClass.SwitchAll.OffV1:st.zwave.Command
--- @alias OffV1 st.zwave.CommandClass.SwitchAll.OffV1
---
--- v1 SWITCH_ALL_OFF
---
--- @field public cmd_class number 0x27
--- @field public cmd_id number 0x05
--- @field public version number 1
--- @field public args st.zwave.CommandClass.SwitchAll.OffV1Args command-specific arguments
local OffV1 = {}
setmetatable(OffV1, {
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

--- Initialize a v1 SWITCH_ALL_OFF object.
---
--- @param module st.zwave.CommandClass.SwitchAll command class module instance
--- @param args st.zwave.CommandClass.SwitchAll.OffV1Args command-specific arguments
function OffV1:init(module, args, ...)
  zw.Command._parse(self, module, zw.SWITCH_ALL, SwitchAll.OFF, 1, args, ...)
end

--- Serialize v1 SWITCH_ALL_OFF arguments.
---
--- @return string serialized payload
function OffV1:serialize()
  local writer = buf.Writer()
  return writer.buf
end

--- Deserialize a v1 SWITCH_ALL_OFF payload.
---
--- @return st.zwave.CommandClass.SwitchAll.OffV1Args deserialized arguments
function OffV1:deserialize()
  local reader = buf.Reader(self.payload)
  return reader.parsed
end

--- Return a deep copy of self.args, merging defaults for unset, but required parameters.
---
--- @param self st.zwave.CommandClass.SwitchAll.OffV1
--- @return st.zwave.CommandClass.SwitchAll.OffV1Args
function OffV1._defaults(self)
  return {}
end

--- Return a deep copy of self.args, merging defaults for all unset parameters.
---
--- @param self st.zwave.CommandClass.SwitchAll.OffV1
--- @return st.zwave.CommandClass.SwitchAll.OffV1Args
function OffV1._template(self)
  return {}
end

--- Set defaults for any required, but unset arguments.
---
--- @param self st.zwave.CommandClass.SwitchAll.OffV1
function OffV1._set_defaults(self)
  local defaults = self:_defaults()
  utils.merge(self.args, defaults)
end

--- Set const reflectors to allow enum stringification.
---
--- @param self st.zwave.CommandClass.SwitchAll.OffV1
function OffV1._set_reflectors(self)
end

--- @class st.zwave.CommandClass.SwitchAll.Set
--- @alias _Set st.zwave.CommandClass.SwitchAll.Set
---
--- Dynamically versioned SWITCH_ALL_SET
---
--- Supported versions: 1; unique base versions: 1
---
--- @field public cmd_class number 0x27
--- @field public cmd_id number 0x01
--- @field public version number 1
--- @field public args st.zwave.CommandClass.SwitchAll.SetV1Args
local _Set = {}
setmetatable(_Set, {
  __call = function(cls, self, ...)
    return cls:construct(self, ...)
  end,
})

--- Construct a SWITCH_ALL_SET object at the module instance serialization version.
---
--- @param module st.zwave.CommandClass.SwitchAll command class module instance
--- @param args st.zwave.CommandClass.SwitchAll.SetV1Args command-specific arguments
--- @return st.zwave.CommandClass.SwitchAll.Set
function _Set:construct(module, args, ...)
  return zw.Command._construct(module, SwitchAll.SET, module._serialization_version, args, ...)
end

--- @class st.zwave.CommandClass.SwitchAll.Get
--- @alias _Get st.zwave.CommandClass.SwitchAll.Get
---
--- Dynamically versioned SWITCH_ALL_GET
---
--- Supported versions: 1; unique base versions: 1
---
--- @field public cmd_class number 0x27
--- @field public cmd_id number 0x02
--- @field public version number 1
--- @field public args st.zwave.CommandClass.SwitchAll.GetV1Args
local _Get = {}
setmetatable(_Get, {
  __call = function(cls, self, ...)
    return cls:construct(self, ...)
  end,
})

--- Construct a SWITCH_ALL_GET object at the module instance serialization version.
---
--- @param module st.zwave.CommandClass.SwitchAll command class module instance
--- @param args st.zwave.CommandClass.SwitchAll.GetV1Args command-specific arguments
--- @return st.zwave.CommandClass.SwitchAll.Get
function _Get:construct(module, args, ...)
  return zw.Command._construct(module, SwitchAll.GET, module._serialization_version, args, ...)
end

--- @class st.zwave.CommandClass.SwitchAll.Report
--- @alias _Report st.zwave.CommandClass.SwitchAll.Report
---
--- Dynamically versioned SWITCH_ALL_REPORT
---
--- Supported versions: 1; unique base versions: 1
---
--- @field public cmd_class number 0x27
--- @field public cmd_id number 0x03
--- @field public version number 1
--- @field public args st.zwave.CommandClass.SwitchAll.ReportV1Args
local _Report = {}
setmetatable(_Report, {
  __call = function(cls, self, ...)
    return cls:construct(self, ...)
  end,
})

--- Construct a SWITCH_ALL_REPORT object at the module instance serialization version.
---
--- @param module st.zwave.CommandClass.SwitchAll command class module instance
--- @param args st.zwave.CommandClass.SwitchAll.ReportV1Args command-specific arguments
--- @return st.zwave.CommandClass.SwitchAll.Report
function _Report:construct(module, args, ...)
  return zw.Command._construct(module, SwitchAll.REPORT, module._serialization_version, args, ...)
end

--- @class st.zwave.CommandClass.SwitchAll.On
--- @alias _On st.zwave.CommandClass.SwitchAll.On
---
--- Dynamically versioned SWITCH_ALL_ON
---
--- Supported versions: 1; unique base versions: 1
---
--- @field public cmd_class number 0x27
--- @field public cmd_id number 0x04
--- @field public version number 1
--- @field public args st.zwave.CommandClass.SwitchAll.OnV1Args
local _On = {}
setmetatable(_On, {
  __call = function(cls, self, ...)
    return cls:construct(self, ...)
  end,
})

--- Construct a SWITCH_ALL_ON object at the module instance serialization version.
---
--- @param module st.zwave.CommandClass.SwitchAll command class module instance
--- @param args st.zwave.CommandClass.SwitchAll.OnV1Args command-specific arguments
--- @return st.zwave.CommandClass.SwitchAll.On
function _On:construct(module, args, ...)
  return zw.Command._construct(module, SwitchAll.ON, module._serialization_version, args, ...)
end

--- @class st.zwave.CommandClass.SwitchAll.Off
--- @alias _Off st.zwave.CommandClass.SwitchAll.Off
---
--- Dynamically versioned SWITCH_ALL_OFF
---
--- Supported versions: 1; unique base versions: 1
---
--- @field public cmd_class number 0x27
--- @field public cmd_id number 0x05
--- @field public version number 1
--- @field public args st.zwave.CommandClass.SwitchAll.OffV1Args
local _Off = {}
setmetatable(_Off, {
  __call = function(cls, self, ...)
    return cls:construct(self, ...)
  end,
})

--- Construct a SWITCH_ALL_OFF object at the module instance serialization version.
---
--- @param module st.zwave.CommandClass.SwitchAll command class module instance
--- @param args st.zwave.CommandClass.SwitchAll.OffV1Args command-specific arguments
--- @return st.zwave.CommandClass.SwitchAll.Off
function _Off:construct(module, args, ...)
  return zw.Command._construct(module, SwitchAll.OFF, module._serialization_version, args, ...)
end

SwitchAll.SetV1 = SetV1
SwitchAll.GetV1 = GetV1
SwitchAll.ReportV1 = ReportV1
SwitchAll.OnV1 = OnV1
SwitchAll.OffV1 = OffV1
SwitchAll.Set = _Set
SwitchAll.Get = _Get
SwitchAll.Report = _Report
SwitchAll.On = _On
SwitchAll.Off = _Off

SwitchAll._lut = {
  [0] = { -- dynamically versioned constructors
    [SwitchAll.SET] = SwitchAll.Set,
    [SwitchAll.GET] = SwitchAll.Get,
    [SwitchAll.REPORT] = SwitchAll.Report,
    [SwitchAll.ON] = SwitchAll.On,
    [SwitchAll.OFF] = SwitchAll.Off
  },
  [1] = { -- version 1
    [SwitchAll.SET] = SwitchAll.SetV1,
    [SwitchAll.GET] = SwitchAll.GetV1,
    [SwitchAll.REPORT] = SwitchAll.ReportV1,
    [SwitchAll.ON] = SwitchAll.OnV1,
    [SwitchAll.OFF] = SwitchAll.OffV1
  }
}
--- @class st.zwave.CommandClass.SwitchAll.mode
--- @alias mode st.zwave.CommandClass.SwitchAll.mode
--- @field public EXCLUDED_FROM_THE_ALL_ON_ALL_OFF_FUNCTIONALITY number 0x00
--- @field public EXCLUDED_FROM_THE_ALL_ON_FUNCTIONALITY_BUT_NOT_ALL_OFF number 0x01
--- @field public EXCLUDED_FROM_THE_ALL_OFF_FUNCTIONALITY_BUT_NOT_ALL_ON number 0x02
--- @field public INCLUDED_IN_THE_ALL_ON_ALL_OFF_FUNCTIONALITY number 0xFF
local mode = {
  EXCLUDED_FROM_THE_ALL_ON_ALL_OFF_FUNCTIONALITY = 0x00,
  EXCLUDED_FROM_THE_ALL_ON_FUNCTIONALITY_BUT_NOT_ALL_OFF = 0x01,
  EXCLUDED_FROM_THE_ALL_OFF_FUNCTIONALITY_BUT_NOT_ALL_ON = 0x02,
  INCLUDED_IN_THE_ALL_ON_ALL_OFF_FUNCTIONALITY = 0xFF
}
SwitchAll.mode = mode
SwitchAll._reflect_mode = zw._reflection_builder(SwitchAll.mode)


return SwitchAll
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

--- @class st.zwave.CommandClass.ZwaveplusInfo
--- @alias ZwaveplusInfo st.zwave.CommandClass.ZwaveplusInfo
---
--- Supported versions: 1,2
---
--- @field public GET number 0x01 - ZWAVEPLUS_INFO_GET command id
--- @field public REPORT number 0x02 - ZWAVEPLUS_INFO_REPORT command id
local ZwaveplusInfo = {}
ZwaveplusInfo.GET = 0x01
ZwaveplusInfo.REPORT = 0x02

ZwaveplusInfo._commands = {
  [ZwaveplusInfo.GET] = "GET",
  [ZwaveplusInfo.REPORT] = "REPORT"
}

--- Instantiate a versioned instance of the ZwaveplusInfo Command Class module, optionally setting strict to require explicit passing of all parameters to constructors.
---
--- @param params st.zwave.CommandClass.Params command class instance parameters
--- @return st.zwave.CommandClass.ZwaveplusInfo versioned command class instance
function ZwaveplusInfo:init(params)
  local version = params and params.version or nil
  if (params or {}).strict ~= nil then
  local strict = params.strict
  else
  local strict = true -- default
  end
  local strict = params and params.strict or nil
  assert(version == nil or zw._versions[zw.ZWAVEPLUS_INFO][version] ~= nil, "unsupported version")
  assert(strict == nil or type(strict) == "boolean", "strict must be a boolean")
  local mt = {
    __index = self
  }
  local instance = setmetatable({}, mt)
  instance._serialization_version = version
  instance._strict = strict
  return instance
end

setmetatable(ZwaveplusInfo, {
  __call = ZwaveplusInfo.init
})

ZwaveplusInfo._serialization_version = nil
ZwaveplusInfo._strict = false
zw._deserialization_versions = zw.deserialization_versions or {}
zw._versions = zw._versions or {}
setmetatable(zw._deserialization_versions, { __index = zw._versions })
zw._versions[zw.ZWAVEPLUS_INFO] = {
  [1] = true,
  [2] = true
}

--- @class st.zwave.CommandClass.ZwaveplusInfo.GetV1Args
--- @alias GetV1Args st.zwave.CommandClass.ZwaveplusInfo.GetV1Args
local GetV1Args = {}

--- @class st.zwave.CommandClass.ZwaveplusInfo.GetV1:st.zwave.Command
--- @alias GetV1 st.zwave.CommandClass.ZwaveplusInfo.GetV1
---
--- v1 and forward-compatible v2 ZWAVEPLUS_INFO_GET
---
--- @field public cmd_class number 0x5E
--- @field public cmd_id number 0x01
--- @field public version number 1
--- @field public args st.zwave.CommandClass.ZwaveplusInfo.GetV1Args command-specific arguments
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

--- Initialize a v1 and forward-compatible v2 ZWAVEPLUS_INFO_GET object.
---
--- @param module st.zwave.CommandClass.ZwaveplusInfo command class module instance
--- @param args st.zwave.CommandClass.ZwaveplusInfo.GetV1Args command-specific arguments
function GetV1:init(module, args, ...)
  zw.Command._parse(self, module, zw.ZWAVEPLUS_INFO, ZwaveplusInfo.GET, 1, args, ...)
end

--- Serialize v1 or forward-compatible v2 ZWAVEPLUS_INFO_GET arguments.
---
--- @return string serialized payload
function GetV1:serialize()
  local writer = buf.Writer()
  return writer.buf
end

--- Deserialize a v1 or forward-compatible v2 ZWAVEPLUS_INFO_GET payload.
---
--- @return st.zwave.CommandClass.ZwaveplusInfo.GetV1Args deserialized arguments
function GetV1:deserialize()
  local reader = buf.Reader(self.payload)
  return reader.parsed
end

--- Return a deep copy of self.args, merging defaults for unset, but required parameters.
---
--- @param self st.zwave.CommandClass.ZwaveplusInfo.GetV1
--- @return st.zwave.CommandClass.ZwaveplusInfo.GetV1Args
function GetV1._defaults(self)
  return {}
end

--- Return a deep copy of self.args, merging defaults for all unset parameters.
---
--- @param self st.zwave.CommandClass.ZwaveplusInfo.GetV1
--- @return st.zwave.CommandClass.ZwaveplusInfo.GetV1Args
function GetV1._template(self)
  return {}
end

--- Set defaults for any required, but unset arguments.
---
--- @param self st.zwave.CommandClass.ZwaveplusInfo.GetV1
function GetV1._set_defaults(self)
  local defaults = self:_defaults()
  utils.merge(self.args, defaults)
end

--- Set const reflectors to allow enum stringification.
---
--- @param self st.zwave.CommandClass.ZwaveplusInfo.GetV1
function GetV1._set_reflectors(self)
end

--- @class st.zwave.CommandClass.ZwaveplusInfo.ReportV1Args
--- @alias ReportV1Args st.zwave.CommandClass.ZwaveplusInfo.ReportV1Args
--- @field public z_wave_version integer [0,255]
--- @field public role_type integer see :lua:class:`ZwaveplusInfo.role_type <st.zwave.CommandClass.ZwaveplusInfo.role_type>`
--- @field public node_type integer see :lua:class:`ZwaveplusInfo.node_type <st.zwave.CommandClass.ZwaveplusInfo.node_type>`
local ReportV1Args = {}

--- @class st.zwave.CommandClass.ZwaveplusInfo.ReportV1:st.zwave.Command
--- @alias ReportV1 st.zwave.CommandClass.ZwaveplusInfo.ReportV1
---
--- v1 ZWAVEPLUS_INFO_REPORT
---
--- @field public cmd_class number 0x5E
--- @field public cmd_id number 0x02
--- @field public version number 1
--- @field public args st.zwave.CommandClass.ZwaveplusInfo.ReportV1Args command-specific arguments
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

--- Initialize a v1 ZWAVEPLUS_INFO_REPORT object.
---
--- @param module st.zwave.CommandClass.ZwaveplusInfo command class module instance
--- @param args st.zwave.CommandClass.ZwaveplusInfo.ReportV1Args command-specific arguments
function ReportV1:init(module, args, ...)
  zw.Command._parse(self, module, zw.ZWAVEPLUS_INFO, ZwaveplusInfo.REPORT, 1, args, ...)
end

--- Serialize v1 ZWAVEPLUS_INFO_REPORT arguments.
---
--- @return string serialized payload
function ReportV1:serialize()
  local writer = buf.Writer()
  local args = self.args
  writer:write_u8(args.z_wave_version)
  writer:write_u8(args.role_type)
  writer:write_u8(args.node_type)
  return writer.buf
end

--- Deserialize a v1 ZWAVEPLUS_INFO_REPORT payload.
---
--- @return st.zwave.CommandClass.ZwaveplusInfo.ReportV1Args deserialized arguments
function ReportV1:deserialize()
  local reader = buf.Reader(self.payload)
  reader:read_u8("z_wave_version")
  reader:read_u8("role_type")
  reader:read_u8("node_type")
  return reader.parsed
end

--- Return a deep copy of self.args, merging defaults for unset, but required parameters.
---
--- @param self st.zwave.CommandClass.ZwaveplusInfo.ReportV1
--- @return st.zwave.CommandClass.ZwaveplusInfo.ReportV1Args
function ReportV1._defaults(self)
  local args = {}
  args.z_wave_version = self.args.z_wave_version or 0
  args.role_type = self.args.role_type or 0
  args.node_type = self.args.node_type or 0
  return args
end

--- Return a deep copy of self.args, merging defaults for all unset parameters.
---
--- @param self st.zwave.CommandClass.ZwaveplusInfo.ReportV1
--- @return st.zwave.CommandClass.ZwaveplusInfo.ReportV1Args
function ReportV1._template(self)
  local args = self:_defaults()
  return args
end

--- Set defaults for any required, but unset arguments.
---
--- @param self st.zwave.CommandClass.ZwaveplusInfo.ReportV1
function ReportV1._set_defaults(self)
  local defaults = self:_defaults()
  utils.merge(self.args, defaults)
end

--- Set const reflectors to allow enum stringification.
---
--- @param self st.zwave.CommandClass.ZwaveplusInfo.ReportV1
function ReportV1._set_reflectors(self)
  local args = self.args
  args._reflect = args._reflect or {}
  args._reflect.role_type = function()
    return zw._reflect(
      ZwaveplusInfo._reflect_role_type,
      args.role_type
    )
  end
  args._reflect = args._reflect or {}
  args._reflect.node_type = function()
    return zw._reflect(
      ZwaveplusInfo._reflect_node_type,
      args.node_type
    )
  end
end

--- @class st.zwave.CommandClass.ZwaveplusInfo.ReportV2Args
--- @alias ReportV2Args st.zwave.CommandClass.ZwaveplusInfo.ReportV2Args
--- @field public z_wave_version integer [0,255]
--- @field public role_type integer see :lua:class:`ZwaveplusInfo.role_type <st.zwave.CommandClass.ZwaveplusInfo.role_type>`
--- @field public node_type integer see :lua:class:`ZwaveplusInfo.node_type <st.zwave.CommandClass.ZwaveplusInfo.node_type>`
--- @field public installer_icon_type integer [0,65535]
--- @field public user_icon_type integer [0,65535]
local ReportV2Args = {}

--- @class st.zwave.CommandClass.ZwaveplusInfo.ReportV2:st.zwave.Command
--- @alias ReportV2 st.zwave.CommandClass.ZwaveplusInfo.ReportV2
---
--- v2 ZWAVEPLUS_INFO_REPORT
---
--- @field public cmd_class number 0x5E
--- @field public cmd_id number 0x02
--- @field public version number 2
--- @field public args st.zwave.CommandClass.ZwaveplusInfo.ReportV2Args command-specific arguments
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

--- Initialize a v2 ZWAVEPLUS_INFO_REPORT object.
---
--- @param module st.zwave.CommandClass.ZwaveplusInfo command class module instance
--- @param args st.zwave.CommandClass.ZwaveplusInfo.ReportV2Args command-specific arguments
function ReportV2:init(module, args, ...)
  zw.Command._parse(self, module, zw.ZWAVEPLUS_INFO, ZwaveplusInfo.REPORT, 2, args, ...)
end

--- Serialize v2 ZWAVEPLUS_INFO_REPORT arguments.
---
--- @return string serialized payload
function ReportV2:serialize()
  local writer = buf.Writer()
  local args = self.args
  writer:write_u8(args.z_wave_version)
  writer:write_u8(args.role_type)
  writer:write_u8(args.node_type)
  writer:write_be_u16(args.installer_icon_type)
  writer:write_be_u16(args.user_icon_type)
  return writer.buf
end

--- Deserialize a v2 ZWAVEPLUS_INFO_REPORT payload.
---
--- @return st.zwave.CommandClass.ZwaveplusInfo.ReportV2Args deserialized arguments
function ReportV2:deserialize()
  local reader = buf.Reader(self.payload)
  reader:read_u8("z_wave_version")
  reader:read_u8("role_type")
  reader:read_u8("node_type")
  reader:read_be_u16("installer_icon_type")
  reader:read_be_u16("user_icon_type")
  return reader.parsed
end

--- Return a deep copy of self.args, merging defaults for unset, but required parameters.
---
--- @param self st.zwave.CommandClass.ZwaveplusInfo.ReportV2
--- @return st.zwave.CommandClass.ZwaveplusInfo.ReportV2Args
function ReportV2._defaults(self)
  local args = {}
  args.z_wave_version = self.args.z_wave_version or 0
  args.role_type = self.args.role_type or 0
  args.node_type = self.args.node_type or 0
  args.installer_icon_type = self.args.installer_icon_type or 0
  args.user_icon_type = self.args.user_icon_type or 0
  return args
end

--- Return a deep copy of self.args, merging defaults for all unset parameters.
---
--- @param self st.zwave.CommandClass.ZwaveplusInfo.ReportV2
--- @return st.zwave.CommandClass.ZwaveplusInfo.ReportV2Args
function ReportV2._template(self)
  local args = self:_defaults()
  return args
end

--- Set defaults for any required, but unset arguments.
---
--- @param self st.zwave.CommandClass.ZwaveplusInfo.ReportV2
function ReportV2._set_defaults(self)
  local defaults = self:_defaults()
  utils.merge(self.args, defaults)
end

--- Set const reflectors to allow enum stringification.
---
--- @param self st.zwave.CommandClass.ZwaveplusInfo.ReportV2
function ReportV2._set_reflectors(self)
  local args = self.args
  args._reflect = args._reflect or {}
  args._reflect.role_type = function()
    return zw._reflect(
      ZwaveplusInfo._reflect_role_type,
      args.role_type
    )
  end
  args._reflect = args._reflect or {}
  args._reflect.node_type = function()
    return zw._reflect(
      ZwaveplusInfo._reflect_node_type,
      args.node_type
    )
  end
end

--- @class st.zwave.CommandClass.ZwaveplusInfo.Get
--- @alias _Get st.zwave.CommandClass.ZwaveplusInfo.Get
---
--- Dynamically versioned ZWAVEPLUS_INFO_GET
---
--- Supported versions: 1,2; unique base versions: 1
---
--- @field public cmd_class number 0x5E
--- @field public cmd_id number 0x01
--- @field public version number 1
--- @field public args st.zwave.CommandClass.ZwaveplusInfo.GetV1Args
local _Get = {}
setmetatable(_Get, {
  __call = function(cls, self, ...)
    return cls:construct(self, ...)
  end,
})

--- Construct a ZWAVEPLUS_INFO_GET object at the module instance serialization version.
---
--- @param module st.zwave.CommandClass.ZwaveplusInfo command class module instance
--- @param args st.zwave.CommandClass.ZwaveplusInfo.GetV1Args command-specific arguments
--- @return st.zwave.CommandClass.ZwaveplusInfo.Get
function _Get:construct(module, args, ...)
  return zw.Command._construct(module, ZwaveplusInfo.GET, module._serialization_version, args, ...)
end

--- @class st.zwave.CommandClass.ZwaveplusInfo.Report
--- @alias _Report st.zwave.CommandClass.ZwaveplusInfo.Report
---
--- Dynamically versioned ZWAVEPLUS_INFO_REPORT
---
--- Supported versions: 1,2; unique base versions: 1,2
---
--- @field public cmd_class number 0x5E
--- @field public cmd_id number 0x02
--- @field public version number 1,2
--- @field public args st.zwave.CommandClass.ZwaveplusInfo.ReportV1Args|st.zwave.CommandClass.ZwaveplusInfo.ReportV2Args
local _Report = {}
setmetatable(_Report, {
  __call = function(cls, self, ...)
    return cls:construct(self, ...)
  end,
})

--- Construct a ZWAVEPLUS_INFO_REPORT object at the module instance serialization version.
---
--- @param module st.zwave.CommandClass.ZwaveplusInfo command class module instance
--- @param args st.zwave.CommandClass.ZwaveplusInfo.ReportV1Args|st.zwave.CommandClass.ZwaveplusInfo.ReportV2Args command-specific arguments
--- @return st.zwave.CommandClass.ZwaveplusInfo.Report
function _Report:construct(module, args, ...)
  return zw.Command._construct(module, ZwaveplusInfo.REPORT, module._serialization_version, args, ...)
end

ZwaveplusInfo.GetV1 = GetV1
ZwaveplusInfo.ReportV1 = ReportV1
ZwaveplusInfo.ReportV2 = ReportV2
ZwaveplusInfo.Get = _Get
ZwaveplusInfo.Report = _Report

ZwaveplusInfo._lut = {
  [0] = { -- dynamically versioned constructors
    [ZwaveplusInfo.GET] = ZwaveplusInfo.Get,
    [ZwaveplusInfo.REPORT] = ZwaveplusInfo.Report
  },
  [1] = { -- version 1
    [ZwaveplusInfo.GET] = ZwaveplusInfo.GetV1,
    [ZwaveplusInfo.REPORT] = ZwaveplusInfo.ReportV1
  },
  [2] = { -- version 2
    [ZwaveplusInfo.GET] = ZwaveplusInfo.GetV1,
    [ZwaveplusInfo.REPORT] = ZwaveplusInfo.ReportV2
  }
}
--- @class st.zwave.CommandClass.ZwaveplusInfo.node_type
--- @alias node_type st.zwave.CommandClass.ZwaveplusInfo.node_type
--- @field public NODE_TYPE_ZWAVEPLUS_NODE number 0x00
--- @field public NODE_TYPE_ZWAVEPLUS_FOR_IP_ROUTER number 0x01
--- @field public NODE_TYPE_ZWAVEPLUS_FOR_IP_GATEWAY number 0x02
--- @field public NODE_TYPE_ZWAVEPLUS_FOR_IP_CLIENT_IP_NODE number 0x03
--- @field public NODE_TYPE_ZWAVEPLUS_FOR_IP_CLIENT_ZWAVE_NODE number 0x04
local node_type = {
  NODE_TYPE_ZWAVEPLUS_NODE = 0x00,
  NODE_TYPE_ZWAVEPLUS_FOR_IP_ROUTER = 0x01,
  NODE_TYPE_ZWAVEPLUS_FOR_IP_GATEWAY = 0x02,
  NODE_TYPE_ZWAVEPLUS_FOR_IP_CLIENT_IP_NODE = 0x03,
  NODE_TYPE_ZWAVEPLUS_FOR_IP_CLIENT_ZWAVE_NODE = 0x04
}
ZwaveplusInfo.node_type = node_type
ZwaveplusInfo._reflect_node_type = zw._reflection_builder(ZwaveplusInfo.node_type)

--- @class st.zwave.CommandClass.ZwaveplusInfo.role_type
--- @alias role_type st.zwave.CommandClass.ZwaveplusInfo.role_type
--- @field public ROLE_TYPE_CONTROLLER_CENTRAL_STATIC number 0x00
--- @field public ROLE_TYPE_CONTROLLER_SUB_STATIC number 0x01
--- @field public ROLE_TYPE_CONTROLLER_PORTABLE number 0x02
--- @field public ROLE_TYPE_CONTROLLER_PORTABLE_REPORTING number 0x03
--- @field public ROLE_TYPE_SLAVE_PORTABLE number 0x04
--- @field public ROLE_TYPE_SLAVE_ALWAYS_ON number 0x05
--- @field public ROLE_TYPE_SLAVE_SLEEPING_REPORTING number 0x06
--- @field public ROLE_TYPE_SLAVE_SLEEPING_LISTENING number 0x07
local role_type = {
  ROLE_TYPE_CONTROLLER_CENTRAL_STATIC = 0x00,
  ROLE_TYPE_CONTROLLER_SUB_STATIC = 0x01,
  ROLE_TYPE_CONTROLLER_PORTABLE = 0x02,
  ROLE_TYPE_CONTROLLER_PORTABLE_REPORTING = 0x03,
  ROLE_TYPE_SLAVE_PORTABLE = 0x04,
  ROLE_TYPE_SLAVE_ALWAYS_ON = 0x05,
  ROLE_TYPE_SLAVE_SLEEPING_REPORTING = 0x06,
  ROLE_TYPE_SLAVE_SLEEPING_LISTENING = 0x07
}
ZwaveplusInfo.role_type = role_type
ZwaveplusInfo._reflect_role_type = zw._reflection_builder(ZwaveplusInfo.role_type)


return ZwaveplusInfo

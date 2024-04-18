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

--- @class st.zwave.CommandClass.AssociationCommandConfiguration
--- @alias AssociationCommandConfiguration st.zwave.CommandClass.AssociationCommandConfiguration
---
--- Supported versions: 1
---
--- @field public COMMAND_RECORDS_SUPPORTED_GET number 0x01 - COMMAND_RECORDS_SUPPORTED_GET command id
--- @field public COMMAND_RECORDS_SUPPORTED_REPORT number 0x02 - COMMAND_RECORDS_SUPPORTED_REPORT command id
--- @field public COMMAND_CONFIGURATION_SET number 0x03 - COMMAND_CONFIGURATION_SET command id
--- @field public COMMAND_CONFIGURATION_GET number 0x04 - COMMAND_CONFIGURATION_GET command id
--- @field public COMMAND_CONFIGURATION_REPORT number 0x05 - COMMAND_CONFIGURATION_REPORT command id
local AssociationCommandConfiguration = {}
AssociationCommandConfiguration.COMMAND_RECORDS_SUPPORTED_GET = 0x01
AssociationCommandConfiguration.COMMAND_RECORDS_SUPPORTED_REPORT = 0x02
AssociationCommandConfiguration.COMMAND_CONFIGURATION_SET = 0x03
AssociationCommandConfiguration.COMMAND_CONFIGURATION_GET = 0x04
AssociationCommandConfiguration.COMMAND_CONFIGURATION_REPORT = 0x05

AssociationCommandConfiguration._commands = {
  [AssociationCommandConfiguration.COMMAND_RECORDS_SUPPORTED_GET] = "COMMAND_RECORDS_SUPPORTED_GET",
  [AssociationCommandConfiguration.COMMAND_RECORDS_SUPPORTED_REPORT] = "COMMAND_RECORDS_SUPPORTED_REPORT",
  [AssociationCommandConfiguration.COMMAND_CONFIGURATION_SET] = "COMMAND_CONFIGURATION_SET",
  [AssociationCommandConfiguration.COMMAND_CONFIGURATION_GET] = "COMMAND_CONFIGURATION_GET",
  [AssociationCommandConfiguration.COMMAND_CONFIGURATION_REPORT] = "COMMAND_CONFIGURATION_REPORT"
}

--- Instantiate a versioned instance of the AssociationCommandConfiguration Command Class module, optionally setting strict to require explicit passing of all parameters to constructors.
---
--- @param params st.zwave.CommandClass.Params command class instance parameters
--- @return st.zwave.CommandClass.AssociationCommandConfiguration versioned command class instance
function AssociationCommandConfiguration:init(params)
  local version = params and params.version or nil
  if (params or {}).strict ~= nil then
  local strict = params.strict
  else
  local strict = true -- default
  end
  local strict = params and params.strict or nil
  assert(version == nil or zw._versions[zw.ASSOCIATION_COMMAND_CONFIGURATION][version] ~= nil, "unsupported version")
  assert(strict == nil or type(strict) == "boolean", "strict must be a boolean")
  local mt = {
    __index = self
  }
  local instance = setmetatable({}, mt)
  instance._serialization_version = version
  instance._strict = strict
  return instance
end

setmetatable(AssociationCommandConfiguration, {
  __call = AssociationCommandConfiguration.init
})

AssociationCommandConfiguration._serialization_version = nil
AssociationCommandConfiguration._strict = false
zw._deserialization_versions = zw.deserialization_versions or {}
zw._versions = zw._versions or {}
setmetatable(zw._deserialization_versions, { __index = zw._versions })
zw._versions[zw.ASSOCIATION_COMMAND_CONFIGURATION] = {
  [1] = true
}

--- @class st.zwave.CommandClass.AssociationCommandConfiguration.CommandRecordsSupportedGetV1Args
--- @alias CommandRecordsSupportedGetV1Args st.zwave.CommandClass.AssociationCommandConfiguration.CommandRecordsSupportedGetV1Args
local CommandRecordsSupportedGetV1Args = {}

--- @class st.zwave.CommandClass.AssociationCommandConfiguration.CommandRecordsSupportedGetV1:st.zwave.Command
--- @alias CommandRecordsSupportedGetV1 st.zwave.CommandClass.AssociationCommandConfiguration.CommandRecordsSupportedGetV1
---
--- v1 COMMAND_RECORDS_SUPPORTED_GET
---
--- @field public cmd_class number 0x9B
--- @field public cmd_id number 0x01
--- @field public version number 1
--- @field public args st.zwave.CommandClass.AssociationCommandConfiguration.CommandRecordsSupportedGetV1Args command-specific arguments
local CommandRecordsSupportedGetV1 = {}
setmetatable(CommandRecordsSupportedGetV1, {
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

--- Initialize a v1 COMMAND_RECORDS_SUPPORTED_GET object.
---
--- @param module st.zwave.CommandClass.AssociationCommandConfiguration command class module instance
--- @param args st.zwave.CommandClass.AssociationCommandConfiguration.CommandRecordsSupportedGetV1Args command-specific arguments
function CommandRecordsSupportedGetV1:init(module, args, ...)
  zw.Command._parse(self, module, zw.ASSOCIATION_COMMAND_CONFIGURATION, AssociationCommandConfiguration.COMMAND_RECORDS_SUPPORTED_GET, 1, args, ...)
end

--- Serialize v1 COMMAND_RECORDS_SUPPORTED_GET arguments.
---
--- @return string serialized payload
function CommandRecordsSupportedGetV1:serialize()
  local writer = buf.Writer()
  return writer.buf
end

--- Deserialize a v1 COMMAND_RECORDS_SUPPORTED_GET payload.
---
--- @return st.zwave.CommandClass.AssociationCommandConfiguration.CommandRecordsSupportedGetV1Args deserialized arguments
function CommandRecordsSupportedGetV1:deserialize()
  local reader = buf.Reader(self.payload)
  return reader.parsed
end

--- Return a deep copy of self.args, merging defaults for unset, but required parameters.
---
--- @param self st.zwave.CommandClass.AssociationCommandConfiguration.CommandRecordsSupportedGetV1
--- @return st.zwave.CommandClass.AssociationCommandConfiguration.CommandRecordsSupportedGetV1Args
function CommandRecordsSupportedGetV1._defaults(self)
  return {}
end

--- Return a deep copy of self.args, merging defaults for all unset parameters.
---
--- @param self st.zwave.CommandClass.AssociationCommandConfiguration.CommandRecordsSupportedGetV1
--- @return st.zwave.CommandClass.AssociationCommandConfiguration.CommandRecordsSupportedGetV1Args
function CommandRecordsSupportedGetV1._template(self)
  return {}
end

--- Set defaults for any required, but unset arguments.
---
--- @param self st.zwave.CommandClass.AssociationCommandConfiguration.CommandRecordsSupportedGetV1
function CommandRecordsSupportedGetV1._set_defaults(self)
  local defaults = self:_defaults()
  utils.merge(self.args, defaults)
end

--- Set const reflectors to allow enum stringification.
---
--- @param self st.zwave.CommandClass.AssociationCommandConfiguration.CommandRecordsSupportedGetV1
function CommandRecordsSupportedGetV1._set_reflectors(self)
end

--- @class st.zwave.CommandClass.AssociationCommandConfiguration.CommandRecordsSupportedReportV1Args
--- @alias CommandRecordsSupportedReportV1Args st.zwave.CommandClass.AssociationCommandConfiguration.CommandRecordsSupportedReportV1Args
--- @field public conf_cmd boolean
--- @field public v_c boolean
--- @field public max_command_length integer [0,63]
--- @field public free_command_records integer [0,65535]
--- @field public max_command_records integer [0,65535]
local CommandRecordsSupportedReportV1Args = {}

--- @class st.zwave.CommandClass.AssociationCommandConfiguration.CommandRecordsSupportedReportV1:st.zwave.Command
--- @alias CommandRecordsSupportedReportV1 st.zwave.CommandClass.AssociationCommandConfiguration.CommandRecordsSupportedReportV1
---
--- v1 COMMAND_RECORDS_SUPPORTED_REPORT
---
--- @field public cmd_class number 0x9B
--- @field public cmd_id number 0x02
--- @field public version number 1
--- @field public args st.zwave.CommandClass.AssociationCommandConfiguration.CommandRecordsSupportedReportV1Args command-specific arguments
local CommandRecordsSupportedReportV1 = {}
setmetatable(CommandRecordsSupportedReportV1, {
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

--- Initialize a v1 COMMAND_RECORDS_SUPPORTED_REPORT object.
---
--- @param module st.zwave.CommandClass.AssociationCommandConfiguration command class module instance
--- @param args st.zwave.CommandClass.AssociationCommandConfiguration.CommandRecordsSupportedReportV1Args command-specific arguments
function CommandRecordsSupportedReportV1:init(module, args, ...)
  zw.Command._parse(self, module, zw.ASSOCIATION_COMMAND_CONFIGURATION, AssociationCommandConfiguration.COMMAND_RECORDS_SUPPORTED_REPORT, 1, args, ...)
end

--- Serialize v1 COMMAND_RECORDS_SUPPORTED_REPORT arguments.
---
--- @return string serialized payload
function CommandRecordsSupportedReportV1:serialize()
  local writer = buf.Writer()
  local args = self.args
  writer:write_bool(args.conf_cmd)
  writer:write_bool(args.v_c)
  writer:write_bits(6, args.max_command_length)
  writer:write_be_u16(args.free_command_records)
  writer:write_be_u16(args.max_command_records)
  return writer.buf
end

--- Deserialize a v1 COMMAND_RECORDS_SUPPORTED_REPORT payload.
---
--- @return st.zwave.CommandClass.AssociationCommandConfiguration.CommandRecordsSupportedReportV1Args deserialized arguments
function CommandRecordsSupportedReportV1:deserialize()
  local reader = buf.Reader(self.payload)
  reader:read_bool("conf_cmd")
  reader:read_bool("v_c")
  reader:read_bits(6, "max_command_length")
  reader:read_be_u16("free_command_records")
  reader:read_be_u16("max_command_records")
  return reader.parsed
end

--- Return a deep copy of self.args, merging defaults for unset, but required parameters.
---
--- @param self st.zwave.CommandClass.AssociationCommandConfiguration.CommandRecordsSupportedReportV1
--- @return st.zwave.CommandClass.AssociationCommandConfiguration.CommandRecordsSupportedReportV1Args
function CommandRecordsSupportedReportV1._defaults(self)
  local args = {}
  args.conf_cmd = self.args.conf_cmd or false
  args.v_c = self.args.v_c or false
  args.max_command_length = self.args.max_command_length or 0
  args.free_command_records = self.args.free_command_records or 0
  args.max_command_records = self.args.max_command_records or 0
  return args
end

--- Return a deep copy of self.args, merging defaults for all unset parameters.
---
--- @param self st.zwave.CommandClass.AssociationCommandConfiguration.CommandRecordsSupportedReportV1
--- @return st.zwave.CommandClass.AssociationCommandConfiguration.CommandRecordsSupportedReportV1Args
function CommandRecordsSupportedReportV1._template(self)
  local args = self:_defaults()
  return args
end

--- Set defaults for any required, but unset arguments.
---
--- @param self st.zwave.CommandClass.AssociationCommandConfiguration.CommandRecordsSupportedReportV1
function CommandRecordsSupportedReportV1._set_defaults(self)
  local defaults = self:_defaults()
  utils.merge(self.args, defaults)
end

--- Set const reflectors to allow enum stringification.
---
--- @param self st.zwave.CommandClass.AssociationCommandConfiguration.CommandRecordsSupportedReportV1
function CommandRecordsSupportedReportV1._set_reflectors(self)
end

--- @class st.zwave.CommandClass.AssociationCommandConfiguration.CommandConfigurationSetV1Args
--- @alias CommandConfigurationSetV1Args st.zwave.CommandClass.AssociationCommandConfiguration.CommandConfigurationSetV1Args
--- @field public grouping_identifier integer [0,255]
--- @field public node_id integer [0,255]
--- @field public command_length integer [0,255]
--- @field public command_class_identifier integer
--- @field public command_identifier integer [0,255]
--- @field public command_byte string
local CommandConfigurationSetV1Args = {}

--- @class st.zwave.CommandClass.AssociationCommandConfiguration.CommandConfigurationSetV1:st.zwave.Command
--- @alias CommandConfigurationSetV1 st.zwave.CommandClass.AssociationCommandConfiguration.CommandConfigurationSetV1
---
--- v1 COMMAND_CONFIGURATION_SET
---
--- @field public cmd_class number 0x9B
--- @field public cmd_id number 0x03
--- @field public version number 1
--- @field public args st.zwave.CommandClass.AssociationCommandConfiguration.CommandConfigurationSetV1Args command-specific arguments
local CommandConfigurationSetV1 = {}
setmetatable(CommandConfigurationSetV1, {
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

--- Initialize a v1 COMMAND_CONFIGURATION_SET object.
---
--- @param module st.zwave.CommandClass.AssociationCommandConfiguration command class module instance
--- @param args st.zwave.CommandClass.AssociationCommandConfiguration.CommandConfigurationSetV1Args command-specific arguments
function CommandConfigurationSetV1:init(module, args, ...)
  zw.Command._parse(self, module, zw.ASSOCIATION_COMMAND_CONFIGURATION, AssociationCommandConfiguration.COMMAND_CONFIGURATION_SET, 1, args, ...)
end

--- Serialize v1 COMMAND_CONFIGURATION_SET arguments.
---
--- @return string serialized payload
function CommandConfigurationSetV1:serialize()
  local writer = buf.Writer()
  local args = self.args
  writer:write_u8(args.grouping_identifier)
  writer:write_u8(args.node_id)
  writer:write_u8(args.command_length)
  writer:write_cmd_class(args.command_class_identifier)
  writer:write_u8(args.command_identifier)
  writer:write_bytes(args.command_byte)
  return writer.buf
end

--- Deserialize a v1 COMMAND_CONFIGURATION_SET payload.
---
--- @return st.zwave.CommandClass.AssociationCommandConfiguration.CommandConfigurationSetV1Args deserialized arguments
function CommandConfigurationSetV1:deserialize()
  local reader = buf.Reader(self.payload)
  reader:read_u8("grouping_identifier")
  reader:read_u8("node_id")
  reader:read_u8("command_length")
  reader:read_cmd_class("command_class_identifier")
  reader:read_u8("command_identifier")
  reader:read_bytes(reader:remain(), "command_byte")
  return reader.parsed
end

--- Return a deep copy of self.args, merging defaults for unset, but required parameters.
---
--- @param self st.zwave.CommandClass.AssociationCommandConfiguration.CommandConfigurationSetV1
--- @return st.zwave.CommandClass.AssociationCommandConfiguration.CommandConfigurationSetV1Args
function CommandConfigurationSetV1._defaults(self)
  local args = {}
  args.grouping_identifier = self.args.grouping_identifier or 0
  args.node_id = self.args.node_id or 0
  args.command_length = self.args.command_length or 0
  args.command_class_identifier = self.args.command_class_identifier or 0
  args.command_identifier = self.args.command_identifier or 0
  args.command_byte = self.args.command_byte or ""
  return args
end

--- Return a deep copy of self.args, merging defaults for all unset parameters.
---
--- @param self st.zwave.CommandClass.AssociationCommandConfiguration.CommandConfigurationSetV1
--- @return st.zwave.CommandClass.AssociationCommandConfiguration.CommandConfigurationSetV1Args
function CommandConfigurationSetV1._template(self)
  local args = self:_defaults()
  return args
end

--- Set defaults for any required, but unset arguments.
---
--- @param self st.zwave.CommandClass.AssociationCommandConfiguration.CommandConfigurationSetV1
function CommandConfigurationSetV1._set_defaults(self)
  local defaults = self:_defaults()
  utils.merge(self.args, defaults)
end

--- Set const reflectors to allow enum stringification.
---
--- @param self st.zwave.CommandClass.AssociationCommandConfiguration.CommandConfigurationSetV1
function CommandConfigurationSetV1._set_reflectors(self)
end

--- @class st.zwave.CommandClass.AssociationCommandConfiguration.CommandConfigurationGetV1Args
--- @alias CommandConfigurationGetV1Args st.zwave.CommandClass.AssociationCommandConfiguration.CommandConfigurationGetV1Args
--- @field public grouping_identifier integer [0,255]
--- @field public node_id integer [0,255]
local CommandConfigurationGetV1Args = {}

--- @class st.zwave.CommandClass.AssociationCommandConfiguration.CommandConfigurationGetV1:st.zwave.Command
--- @alias CommandConfigurationGetV1 st.zwave.CommandClass.AssociationCommandConfiguration.CommandConfigurationGetV1
---
--- v1 COMMAND_CONFIGURATION_GET
---
--- @field public cmd_class number 0x9B
--- @field public cmd_id number 0x04
--- @field public version number 1
--- @field public args st.zwave.CommandClass.AssociationCommandConfiguration.CommandConfigurationGetV1Args command-specific arguments
local CommandConfigurationGetV1 = {}
setmetatable(CommandConfigurationGetV1, {
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

--- Initialize a v1 COMMAND_CONFIGURATION_GET object.
---
--- @param module st.zwave.CommandClass.AssociationCommandConfiguration command class module instance
--- @param args st.zwave.CommandClass.AssociationCommandConfiguration.CommandConfigurationGetV1Args command-specific arguments
function CommandConfigurationGetV1:init(module, args, ...)
  zw.Command._parse(self, module, zw.ASSOCIATION_COMMAND_CONFIGURATION, AssociationCommandConfiguration.COMMAND_CONFIGURATION_GET, 1, args, ...)
end

--- Serialize v1 COMMAND_CONFIGURATION_GET arguments.
---
--- @return string serialized payload
function CommandConfigurationGetV1:serialize()
  local writer = buf.Writer()
  local args = self.args
  writer:write_u8(args.grouping_identifier)
  writer:write_u8(args.node_id)
  return writer.buf
end

--- Deserialize a v1 COMMAND_CONFIGURATION_GET payload.
---
--- @return st.zwave.CommandClass.AssociationCommandConfiguration.CommandConfigurationGetV1Args deserialized arguments
function CommandConfigurationGetV1:deserialize()
  local reader = buf.Reader(self.payload)
  reader:read_u8("grouping_identifier")
  reader:read_u8("node_id")
  return reader.parsed
end

--- Return a deep copy of self.args, merging defaults for unset, but required parameters.
---
--- @param self st.zwave.CommandClass.AssociationCommandConfiguration.CommandConfigurationGetV1
--- @return st.zwave.CommandClass.AssociationCommandConfiguration.CommandConfigurationGetV1Args
function CommandConfigurationGetV1._defaults(self)
  local args = {}
  args.grouping_identifier = self.args.grouping_identifier or 0
  args.node_id = self.args.node_id or 0
  return args
end

--- Return a deep copy of self.args, merging defaults for all unset parameters.
---
--- @param self st.zwave.CommandClass.AssociationCommandConfiguration.CommandConfigurationGetV1
--- @return st.zwave.CommandClass.AssociationCommandConfiguration.CommandConfigurationGetV1Args
function CommandConfigurationGetV1._template(self)
  local args = self:_defaults()
  return args
end

--- Set defaults for any required, but unset arguments.
---
--- @param self st.zwave.CommandClass.AssociationCommandConfiguration.CommandConfigurationGetV1
function CommandConfigurationGetV1._set_defaults(self)
  local defaults = self:_defaults()
  utils.merge(self.args, defaults)
end

--- Set const reflectors to allow enum stringification.
---
--- @param self st.zwave.CommandClass.AssociationCommandConfiguration.CommandConfigurationGetV1
function CommandConfigurationGetV1._set_reflectors(self)
end

--- @class st.zwave.CommandClass.AssociationCommandConfiguration.CommandConfigurationReportV1Args
--- @alias CommandConfigurationReportV1Args st.zwave.CommandClass.AssociationCommandConfiguration.CommandConfigurationReportV1Args
--- @field public grouping_identifier integer [0,255]
--- @field public node_id integer [0,255]
--- @field public reports_to_follow integer [0,15]
--- @field public first boolean
--- @field public command_length integer [0,255]
--- @field public command_class_identifier integer
--- @field public command_identifier integer [0,255]
--- @field public command_byte string
local CommandConfigurationReportV1Args = {}

--- @class st.zwave.CommandClass.AssociationCommandConfiguration.CommandConfigurationReportV1:st.zwave.Command
--- @alias CommandConfigurationReportV1 st.zwave.CommandClass.AssociationCommandConfiguration.CommandConfigurationReportV1
---
--- v1 COMMAND_CONFIGURATION_REPORT
---
--- @field public cmd_class number 0x9B
--- @field public cmd_id number 0x05
--- @field public version number 1
--- @field public args st.zwave.CommandClass.AssociationCommandConfiguration.CommandConfigurationReportV1Args command-specific arguments
local CommandConfigurationReportV1 = {}
setmetatable(CommandConfigurationReportV1, {
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

--- Initialize a v1 COMMAND_CONFIGURATION_REPORT object.
---
--- @param module st.zwave.CommandClass.AssociationCommandConfiguration command class module instance
--- @param args st.zwave.CommandClass.AssociationCommandConfiguration.CommandConfigurationReportV1Args command-specific arguments
function CommandConfigurationReportV1:init(module, args, ...)
  zw.Command._parse(self, module, zw.ASSOCIATION_COMMAND_CONFIGURATION, AssociationCommandConfiguration.COMMAND_CONFIGURATION_REPORT, 1, args, ...)
end

--- Serialize v1 COMMAND_CONFIGURATION_REPORT arguments.
---
--- @return string serialized payload
function CommandConfigurationReportV1:serialize()
  local writer = buf.Writer()
  local args = self.args
  writer:write_u8(args.grouping_identifier)
  writer:write_u8(args.node_id)
  writer:write_bits(4, args.reports_to_follow)
  writer:write_bits(3, 0) -- reserved
  writer:write_bool(args.first)
  writer:write_u8(args.command_length)
  writer:write_cmd_class(args.command_class_identifier)
  writer:write_u8(args.command_identifier)
  writer:write_bytes(args.command_byte)
  return writer.buf
end

--- Deserialize a v1 COMMAND_CONFIGURATION_REPORT payload.
---
--- @return st.zwave.CommandClass.AssociationCommandConfiguration.CommandConfigurationReportV1Args deserialized arguments
function CommandConfigurationReportV1:deserialize()
  local reader = buf.Reader(self.payload)
  reader:read_u8("grouping_identifier")
  reader:read_u8("node_id")
  reader:read_bits(4, "reports_to_follow")
  reader:read_bits(3) -- reserved
  reader:read_bool("first")
  reader:read_u8("command_length")
  reader:read_cmd_class("command_class_identifier")
  reader:read_u8("command_identifier")
  reader:read_bytes(reader:remain(), "command_byte")
  return reader.parsed
end

--- Return a deep copy of self.args, merging defaults for unset, but required parameters.
---
--- @param self st.zwave.CommandClass.AssociationCommandConfiguration.CommandConfigurationReportV1
--- @return st.zwave.CommandClass.AssociationCommandConfiguration.CommandConfigurationReportV1Args
function CommandConfigurationReportV1._defaults(self)
  local args = {}
  args.grouping_identifier = self.args.grouping_identifier or 0
  args.node_id = self.args.node_id or 0
  args.reports_to_follow = self.args.reports_to_follow or 0
  args.first = self.args.first or false
  args.command_length = self.args.command_length or 0
  args.command_class_identifier = self.args.command_class_identifier or 0
  args.command_identifier = self.args.command_identifier or 0
  args.command_byte = self.args.command_byte or ""
  return args
end

--- Return a deep copy of self.args, merging defaults for all unset parameters.
---
--- @param self st.zwave.CommandClass.AssociationCommandConfiguration.CommandConfigurationReportV1
--- @return st.zwave.CommandClass.AssociationCommandConfiguration.CommandConfigurationReportV1Args
function CommandConfigurationReportV1._template(self)
  local args = self:_defaults()
  return args
end

--- Set defaults for any required, but unset arguments.
---
--- @param self st.zwave.CommandClass.AssociationCommandConfiguration.CommandConfigurationReportV1
function CommandConfigurationReportV1._set_defaults(self)
  local defaults = self:_defaults()
  utils.merge(self.args, defaults)
end

--- Set const reflectors to allow enum stringification.
---
--- @param self st.zwave.CommandClass.AssociationCommandConfiguration.CommandConfigurationReportV1
function CommandConfigurationReportV1._set_reflectors(self)
end

--- @class st.zwave.CommandClass.AssociationCommandConfiguration.CommandRecordsSupportedGet
--- @alias _CommandRecordsSupportedGet st.zwave.CommandClass.AssociationCommandConfiguration.CommandRecordsSupportedGet
---
--- Dynamically versioned COMMAND_RECORDS_SUPPORTED_GET
---
--- Supported versions: 1; unique base versions: 1
---
--- @field public cmd_class number 0x9B
--- @field public cmd_id number 0x01
--- @field public version number 1
--- @field public args st.zwave.CommandClass.AssociationCommandConfiguration.CommandRecordsSupportedGetV1Args
local _CommandRecordsSupportedGet = {}
setmetatable(_CommandRecordsSupportedGet, {
  __call = function(cls, self, ...)
    return cls:construct(self, ...)
  end,
})

--- Construct a COMMAND_RECORDS_SUPPORTED_GET object at the module instance serialization version.
---
--- @param module st.zwave.CommandClass.AssociationCommandConfiguration command class module instance
--- @param args st.zwave.CommandClass.AssociationCommandConfiguration.CommandRecordsSupportedGetV1Args command-specific arguments
--- @return st.zwave.CommandClass.AssociationCommandConfiguration.CommandRecordsSupportedGet
function _CommandRecordsSupportedGet:construct(module, args, ...)
  return zw.Command._construct(module, AssociationCommandConfiguration.COMMAND_RECORDS_SUPPORTED_GET, module._serialization_version, args, ...)
end

--- @class st.zwave.CommandClass.AssociationCommandConfiguration.CommandRecordsSupportedReport
--- @alias _CommandRecordsSupportedReport st.zwave.CommandClass.AssociationCommandConfiguration.CommandRecordsSupportedReport
---
--- Dynamically versioned COMMAND_RECORDS_SUPPORTED_REPORT
---
--- Supported versions: 1; unique base versions: 1
---
--- @field public cmd_class number 0x9B
--- @field public cmd_id number 0x02
--- @field public version number 1
--- @field public args st.zwave.CommandClass.AssociationCommandConfiguration.CommandRecordsSupportedReportV1Args
local _CommandRecordsSupportedReport = {}
setmetatable(_CommandRecordsSupportedReport, {
  __call = function(cls, self, ...)
    return cls:construct(self, ...)
  end,
})

--- Construct a COMMAND_RECORDS_SUPPORTED_REPORT object at the module instance serialization version.
---
--- @param module st.zwave.CommandClass.AssociationCommandConfiguration command class module instance
--- @param args st.zwave.CommandClass.AssociationCommandConfiguration.CommandRecordsSupportedReportV1Args command-specific arguments
--- @return st.zwave.CommandClass.AssociationCommandConfiguration.CommandRecordsSupportedReport
function _CommandRecordsSupportedReport:construct(module, args, ...)
  return zw.Command._construct(module, AssociationCommandConfiguration.COMMAND_RECORDS_SUPPORTED_REPORT, module._serialization_version, args, ...)
end

--- @class st.zwave.CommandClass.AssociationCommandConfiguration.CommandConfigurationSet
--- @alias _CommandConfigurationSet st.zwave.CommandClass.AssociationCommandConfiguration.CommandConfigurationSet
---
--- Dynamically versioned COMMAND_CONFIGURATION_SET
---
--- Supported versions: 1; unique base versions: 1
---
--- @field public cmd_class number 0x9B
--- @field public cmd_id number 0x03
--- @field public version number 1
--- @field public args st.zwave.CommandClass.AssociationCommandConfiguration.CommandConfigurationSetV1Args
local _CommandConfigurationSet = {}
setmetatable(_CommandConfigurationSet, {
  __call = function(cls, self, ...)
    return cls:construct(self, ...)
  end,
})

--- Construct a COMMAND_CONFIGURATION_SET object at the module instance serialization version.
---
--- @param module st.zwave.CommandClass.AssociationCommandConfiguration command class module instance
--- @param args st.zwave.CommandClass.AssociationCommandConfiguration.CommandConfigurationSetV1Args command-specific arguments
--- @return st.zwave.CommandClass.AssociationCommandConfiguration.CommandConfigurationSet
function _CommandConfigurationSet:construct(module, args, ...)
  return zw.Command._construct(module, AssociationCommandConfiguration.COMMAND_CONFIGURATION_SET, module._serialization_version, args, ...)
end

--- @class st.zwave.CommandClass.AssociationCommandConfiguration.CommandConfigurationGet
--- @alias _CommandConfigurationGet st.zwave.CommandClass.AssociationCommandConfiguration.CommandConfigurationGet
---
--- Dynamically versioned COMMAND_CONFIGURATION_GET
---
--- Supported versions: 1; unique base versions: 1
---
--- @field public cmd_class number 0x9B
--- @field public cmd_id number 0x04
--- @field public version number 1
--- @field public args st.zwave.CommandClass.AssociationCommandConfiguration.CommandConfigurationGetV1Args
local _CommandConfigurationGet = {}
setmetatable(_CommandConfigurationGet, {
  __call = function(cls, self, ...)
    return cls:construct(self, ...)
  end,
})

--- Construct a COMMAND_CONFIGURATION_GET object at the module instance serialization version.
---
--- @param module st.zwave.CommandClass.AssociationCommandConfiguration command class module instance
--- @param args st.zwave.CommandClass.AssociationCommandConfiguration.CommandConfigurationGetV1Args command-specific arguments
--- @return st.zwave.CommandClass.AssociationCommandConfiguration.CommandConfigurationGet
function _CommandConfigurationGet:construct(module, args, ...)
  return zw.Command._construct(module, AssociationCommandConfiguration.COMMAND_CONFIGURATION_GET, module._serialization_version, args, ...)
end

--- @class st.zwave.CommandClass.AssociationCommandConfiguration.CommandConfigurationReport
--- @alias _CommandConfigurationReport st.zwave.CommandClass.AssociationCommandConfiguration.CommandConfigurationReport
---
--- Dynamically versioned COMMAND_CONFIGURATION_REPORT
---
--- Supported versions: 1; unique base versions: 1
---
--- @field public cmd_class number 0x9B
--- @field public cmd_id number 0x05
--- @field public version number 1
--- @field public args st.zwave.CommandClass.AssociationCommandConfiguration.CommandConfigurationReportV1Args
local _CommandConfigurationReport = {}
setmetatable(_CommandConfigurationReport, {
  __call = function(cls, self, ...)
    return cls:construct(self, ...)
  end,
})

--- Construct a COMMAND_CONFIGURATION_REPORT object at the module instance serialization version.
---
--- @param module st.zwave.CommandClass.AssociationCommandConfiguration command class module instance
--- @param args st.zwave.CommandClass.AssociationCommandConfiguration.CommandConfigurationReportV1Args command-specific arguments
--- @return st.zwave.CommandClass.AssociationCommandConfiguration.CommandConfigurationReport
function _CommandConfigurationReport:construct(module, args, ...)
  return zw.Command._construct(module, AssociationCommandConfiguration.COMMAND_CONFIGURATION_REPORT, module._serialization_version, args, ...)
end

AssociationCommandConfiguration.CommandRecordsSupportedGetV1 = CommandRecordsSupportedGetV1
AssociationCommandConfiguration.CommandRecordsSupportedReportV1 = CommandRecordsSupportedReportV1
AssociationCommandConfiguration.CommandConfigurationSetV1 = CommandConfigurationSetV1
AssociationCommandConfiguration.CommandConfigurationGetV1 = CommandConfigurationGetV1
AssociationCommandConfiguration.CommandConfigurationReportV1 = CommandConfigurationReportV1
AssociationCommandConfiguration.CommandRecordsSupportedGet = _CommandRecordsSupportedGet
AssociationCommandConfiguration.CommandRecordsSupportedReport = _CommandRecordsSupportedReport
AssociationCommandConfiguration.CommandConfigurationSet = _CommandConfigurationSet
AssociationCommandConfiguration.CommandConfigurationGet = _CommandConfigurationGet
AssociationCommandConfiguration.CommandConfigurationReport = _CommandConfigurationReport

AssociationCommandConfiguration._lut = {
  [0] = { -- dynamically versioned constructors
    [AssociationCommandConfiguration.COMMAND_RECORDS_SUPPORTED_GET] = AssociationCommandConfiguration.CommandRecordsSupportedGet,
    [AssociationCommandConfiguration.COMMAND_RECORDS_SUPPORTED_REPORT] = AssociationCommandConfiguration.CommandRecordsSupportedReport,
    [AssociationCommandConfiguration.COMMAND_CONFIGURATION_SET] = AssociationCommandConfiguration.CommandConfigurationSet,
    [AssociationCommandConfiguration.COMMAND_CONFIGURATION_GET] = AssociationCommandConfiguration.CommandConfigurationGet,
    [AssociationCommandConfiguration.COMMAND_CONFIGURATION_REPORT] = AssociationCommandConfiguration.CommandConfigurationReport
  },
  [1] = { -- version 1
    [AssociationCommandConfiguration.COMMAND_RECORDS_SUPPORTED_GET] = AssociationCommandConfiguration.CommandRecordsSupportedGetV1,
    [AssociationCommandConfiguration.COMMAND_RECORDS_SUPPORTED_REPORT] = AssociationCommandConfiguration.CommandRecordsSupportedReportV1,
    [AssociationCommandConfiguration.COMMAND_CONFIGURATION_SET] = AssociationCommandConfiguration.CommandConfigurationSetV1,
    [AssociationCommandConfiguration.COMMAND_CONFIGURATION_GET] = AssociationCommandConfiguration.CommandConfigurationGetV1,
    [AssociationCommandConfiguration.COMMAND_CONFIGURATION_REPORT] = AssociationCommandConfiguration.CommandConfigurationReportV1
  }
}

return AssociationCommandConfiguration

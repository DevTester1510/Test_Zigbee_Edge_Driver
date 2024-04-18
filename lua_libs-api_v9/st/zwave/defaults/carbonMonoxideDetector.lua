-- Copyright 2021 SmartThings
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
local capabilities = require "st.capabilities"
local log = require "log"
--- @type st.zwave.CommandClass
local cc = require "st.zwave.CommandClass"
--- @type st.zwave.CommandClass.SensorAlarm
local SensorAlarm = (require "st.zwave.CommandClass.SensorAlarm")({ version = 1 })
--- @type st.zwave.CommandClass.Notification
local Notification = (require "st.zwave.CommandClass.Notification")({ version = 3 })
--- @type st.zwave.CommandClass.SensorBinary
local SensorBinary = (require "st.zwave.CommandClass.SensorBinary")({ version = 2 })

--- Default handler for sensor alarm command class reports
---
--- This converts sensor alarm reports to carbon monoxide detected events
---
--- @param self st.zwave.Driver
--- @param device st.zwave.Device
--- @param cmd st.zwave.CommandClass.SensorAlarm.Report
local function sensor_alarm_report_handler(self, device, cmd)
  if (cmd.args.sensor_type == SensorAlarm.sensor_type.CO_ALARM) then
    local event
    if (cmd.args.sensor_state == SensorAlarm.sensor_state.ALARM) then
      event = capabilities.carbonMonoxideDetector.carbonMonoxide.detected()
    elseif (cmd.args.sensor_state == SensorAlarm.sensor_state.NO_ALARM) then
      event = capabilities.carbonMonoxideDetector.carbonMonoxide.clear()
    end
    if event ~= nil then
      device:emit_event_for_endpoint(cmd.src_channel, event)
    end
  end
end

--- Default handler for binary sensor command class reports
---
--- This converts binary sensor reports to correct carbon monoxide events
---
--- For a device that uses v1 of the binary sensor command class, all reports will be considered
--- carbon monoxide reports.
---
--- @param self st.zwave.Driver
--- @param device st.zwave.Device
--- @param cmd st.zwave.CommandClass.SensorBinary.Report
local function sensor_binary_report_handler(self, device, cmd)
  -- sensor_type will be nil if this is a v1 report
  if ((cmd.args.sensor_type ~= nil and cmd.args.sensor_type == SensorBinary.sensor_type.CO) or
        cmd.args.sensor_type == nil) then
    if (cmd.args.sensor_value == SensorBinary.sensor_value.DETECTED_AN_EVENT) then
      device:emit_event_for_endpoint(cmd.src_channel, capabilities.carbonMonoxideDetector.carbonMonoxide.detected())
    elseif (cmd.args.sensor_value == SensorBinary.sensor_value.IDLE) then
      device:emit_event_for_endpoint(cmd.src_channel, capabilities.carbonMonoxideDetector.carbonMonoxide.clear())
    end
  end
end

--- Default handler for notification command class reports
---
--- This converts notification reports into carbon monoxide events
---
--- @param self st.zwave.Driver
--- @param device st.zwave.Device
--- @param cmd table st.zwave.CommandClass.Notification.Report
local function notification_handler(self, device, cmd)
  if cmd.version < 3 then
    -- cc.ALARM and cc.NOTIFICATION has same command class ID
    -- only version is different
    -- subdriver for cc.ALARM ( V1 and V2) should be used
      log.warn_with({ hub_logs = true }, "Unhandled Alarm V2 CO command received.")
      return
    end

  -- start with handling cc.NOTIFICATION for V3, V4 etc.
  local co_notification_events_map = {
    [Notification.event.co.CARBON_MONOXIDE_DETECTED] =
      capabilities.carbonMonoxideDetector.carbonMonoxide.detected(),
    [Notification.event.co.CARBON_MONOXIDE_DETECTED_LOCATION_PROVIDED] =
      capabilities.carbonMonoxideDetector.carbonMonoxide.detected(),
    [Notification.event.co.CARBON_MONOXIDE_TEST] =
      capabilities.carbonMonoxideDetector.carbonMonoxide.tested(),
    [Notification.event.co.STATE_IDLE] =
      capabilities.carbonMonoxideDetector.carbonMonoxide.clear(),
    [Notification.event.co.UNKNOWN_EVENT_STATE] =
      capabilities.carbonMonoxideDetector.carbonMonoxide.clear(),
    [Notification.event.co.ALARM_SILENCED] =
      capabilities.carbonMonoxideDetector.carbonMonoxide.clear(),
  }

  if (cmd.args.notification_type == Notification.notification_type.CO) then
    local event
    event = co_notification_events_map[cmd.args.event]
    if (event ~= nil) then
      device:emit_event_for_endpoint(cmd.src_channel, event)
    end
    return
  end
end

--- @param self st.zwave.Driver
--- @param device st.zwave.Device
--- @param component string
--- @param endpoint integer
local function get_refresh_commands(driver, device, component, endpoint)
  if device:supports_capability_by_id(capabilities.carbonMonoxideDetector.ID, component) and device:is_cc_supported(cc.SENSOR_BINARY, endpoint) then
    return {SensorBinary:Get({ sensor_type = SensorBinary.sensor_type.CO }, {dst_channels = {endpoint}})}
  end
end

--- @class st.zwave.defaults.carbonMonoxideDetector
--- @alias carbon_monoxide_detector_defaults st.zwave.defaults.carbonMonoxideDetector
--- @field public zwave_handlers table
--- @field public get_refresh_commands function
local co_detector_defaults = {
  zwave_handlers = {
    [cc.SENSOR_BINARY] = {
      [SensorBinary.REPORT] = sensor_binary_report_handler
    },
    [cc.SENSOR_ALARM] = {
      [SensorAlarm.REPORT] = sensor_alarm_report_handler
    },
    [cc.NOTIFICATION] = {
      -- also shall handle cc.ALARM
      [Notification.REPORT] = notification_handler
    }
  },
  get_refresh_commands = get_refresh_commands
}

return co_detector_defaults

local data_types = require "st.zigbee.data_types"
local utils = require "st.zigbee.utils"
local log = require "log"
local cluster_base = require "st.zigbee.cluster_base"
local EventIdType = require "st.zigbee.generated.zcl_clusters.ApplianceEventsAlerts.types.EventId"

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

-----------------------------------------------------------
-- ApplianceEventsAlerts command EventNotification
-----------------------------------------------------------

--- @class st.zigbee.zcl.clusters.ApplianceEventsAlerts.EventNotification
--- @alias EventNotification
---
--- @field public ID number 0x02 the ID of this command
--- @field public NAME string "EventNotification" the name of this command
--- @field public event_header st.zigbee.data_types.Uint8
--- @field public event_id st.zigbee.zcl.clusters.ApplianceEventsAlerts.types.EventId
local EventNotification = {}
EventNotification.NAME = "EventNotification"
EventNotification.ID = 0x02
EventNotification.args_def = {
  {
    name = "event_header",
    optional = false,
    data_type = data_types.Uint8,
    is_complex = false,
    is_array = false,
    default = 0x00,
  },
  {
    name = "event_id",
    optional = false,
    data_type = EventIdType,
    is_complex = false,
    is_array = false,
  },
}

function EventNotification:get_fields()
  return cluster_base.command_get_fields(self)
end

EventNotification.get_length = utils.length_from_fields
EventNotification._serialize = utils.serialize_from_fields
EventNotification.pretty_print = utils.print_from_fields

--- Deserialize this command
---
--- @param buf buf the bytes of the command body
--- @return EventNotification
function EventNotification.deserialize(buf)
  return cluster_base.command_deserialize(EventNotification, buf)
end

function EventNotification:set_field_names()
  cluster_base.command_set_fields(self)
end

--- Build a version of this message as if it came from the device
---
--- @param device st.zigbee.Device the device to build the message from
--- @param event_header st.zigbee.data_types.Uint8
--- @param event_id st.zigbee.zcl.clusters.ApplianceEventsAlerts.types.EventId
--- @return st.zigbee.ZigbeeMessageRx The full Zigbee message containing this command body
function EventNotification.build_test_rx(device, event_header, event_id)
  local args = {event_header, event_id}

  return cluster_base.command_build_test_rx(EventNotification, device, args, "client")
end

--- Initialize the EventNotification command
---
--- @param self EventNotification the template class for this command
--- @param device st.zigbee.Device the device to build this message to
--- @param event_header st.zigbee.data_types.Uint8
--- @param event_id st.zigbee.zcl.clusters.ApplianceEventsAlerts.types.EventId
--- @return st.zigbee.ZigbeeMessageTx the full command addressed to the device
function EventNotification:init(device, event_header, event_id)
  local args = {event_header, event_id}

  return cluster_base.command_init(self, device, args, "client")
end

function EventNotification:set_parent_cluster(cluster)
  self._cluster = cluster
  return self
end

setmetatable(EventNotification, {__call = EventNotification.init})

return EventNotification
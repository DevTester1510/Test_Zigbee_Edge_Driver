local data_types = require "st.zigbee.data_types"
local utils = require "st.zigbee.utils"
local log = require "log"
local cluster_base = require "st.zigbee.cluster_base"

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
-- DoorLock command UnlockDoor
-----------------------------------------------------------

--- @class st.zigbee.zcl.clusters.DoorLock.UnlockDoor
--- @alias UnlockDoor
---
--- @field public ID number 0x01 the ID of this command
--- @field public NAME string "UnlockDoor" the name of this command
--- @field public pin_or_rfid_code st.zigbee.data_types.OctetString
local UnlockDoor = {}
UnlockDoor.NAME = "UnlockDoor"
UnlockDoor.ID = 0x01
UnlockDoor.args_def = {
  {
    name = "pin_or_rfid_code",
    optional = false,
    data_type = data_types.OctetString,
    is_complex = false,
    is_array = false,
    default = "",
  },
}

function UnlockDoor:get_fields()
  return cluster_base.command_get_fields(self)
end

UnlockDoor.get_length = utils.length_from_fields
UnlockDoor._serialize = utils.serialize_from_fields
UnlockDoor.pretty_print = utils.print_from_fields

--- Deserialize this command
---
--- @param buf buf the bytes of the command body
--- @return UnlockDoor
function UnlockDoor.deserialize(buf)
  return cluster_base.command_deserialize(UnlockDoor, buf)
end

function UnlockDoor:set_field_names()
  cluster_base.command_set_fields(self)
end

--- Build a version of this message as if it came from the device
---
--- @param device st.zigbee.Device the device to build the message from
--- @param pin_or_rfid_code st.zigbee.data_types.OctetString
--- @return st.zigbee.ZigbeeMessageRx The full Zigbee message containing this command body
function UnlockDoor.build_test_rx(device, pin_or_rfid_code)
  local args = {pin_or_rfid_code}

  return cluster_base.command_build_test_rx(UnlockDoor, device, args, "server")
end

--- Initialize the UnlockDoor command
---
--- @param self UnlockDoor the template class for this command
--- @param device st.zigbee.Device the device to build this message to
--- @param pin_or_rfid_code st.zigbee.data_types.OctetString
--- @return st.zigbee.ZigbeeMessageTx the full command addressed to the device
function UnlockDoor:init(device, pin_or_rfid_code)
  local args = {pin_or_rfid_code}

  return cluster_base.command_init(self, device, args, "server")
end

function UnlockDoor:set_parent_cluster(cluster)
  self._cluster = cluster
  return self
end

setmetatable(UnlockDoor, {__call = UnlockDoor.init})

return UnlockDoor
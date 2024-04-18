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

local attr_mt = {}
attr_mt.__attr_cache = {}
attr_mt.__index = function(self, key)
  if attr_mt.__attr_cache[key] == nil then
    local req_loc = string.format("st.zigbee.generated.zcl_clusters.Commissioning.server.attributes.%s", key)
    local raw_def = require(req_loc)
    local cluster = rawget(self, "_cluster")
    raw_def:set_parent_cluster(cluster)
    attr_mt.__attr_cache[key] = raw_def
  end
  return attr_mt.__attr_cache[key]
end


--- @class st.zigbee.zcl.clusters.CommissioningServerAttributes
---
--- @field public ShortAddress st.zigbee.zcl.clusters.Commissioning.ShortAddress
--- @field public ExtendedPANId st.zigbee.zcl.clusters.Commissioning.ExtendedPANId
--- @field public PANId st.zigbee.zcl.clusters.Commissioning.PANId
--- @field public ChannelMask st.zigbee.zcl.clusters.Commissioning.ChannelMask
--- @field public ProtocolVersion st.zigbee.zcl.clusters.Commissioning.ProtocolVersion
--- @field public StackProfile st.zigbee.zcl.clusters.Commissioning.StackProfile
--- @field public StartupControl st.zigbee.zcl.clusters.Commissioning.StartupControl
--- @field public TrustCenterAddress st.zigbee.zcl.clusters.Commissioning.TrustCenterAddress
--- @field public TrustCenterMasterKey st.zigbee.zcl.clusters.Commissioning.TrustCenterMasterKey
--- @field public NetworkKey st.zigbee.zcl.clusters.Commissioning.NetworkKey
--- @field public UseInsecureJoin st.zigbee.zcl.clusters.Commissioning.UseInsecureJoin
--- @field public PreconfiguredLinkKey st.zigbee.zcl.clusters.Commissioning.PreconfiguredLinkKey
--- @field public NetworkKeySeqNum st.zigbee.zcl.clusters.Commissioning.NetworkKeySeqNum
--- @field public NetworkKeyType st.zigbee.zcl.clusters.Commissioning.NetworkKeyType
--- @field public NetworkManagerAddress st.zigbee.zcl.clusters.Commissioning.NetworkManagerAddress
--- @field public ScanAttempts st.zigbee.zcl.clusters.Commissioning.ScanAttempts
--- @field public TimeBetweenScans st.zigbee.zcl.clusters.Commissioning.TimeBetweenScans
--- @field public RejoinInterval st.zigbee.zcl.clusters.Commissioning.RejoinInterval
--- @field public MaxRejoinInterval st.zigbee.zcl.clusters.Commissioning.MaxRejoinInterval
--- @field public IndirectPollRate st.zigbee.zcl.clusters.Commissioning.IndirectPollRate
--- @field public ParentRetryThreshold st.zigbee.zcl.clusters.Commissioning.ParentRetryThreshold
--- @field public ConcentratorFlag st.zigbee.zcl.clusters.Commissioning.ConcentratorFlag
--- @field public ConcentratorRadius st.zigbee.zcl.clusters.Commissioning.ConcentratorRadius
--- @field public ConcentratorDiscoveryTime st.zigbee.zcl.clusters.Commissioning.ConcentratorDiscoveryTime

local CommissioningServerAttributes = {}

function CommissioningServerAttributes:set_parent_cluster(cluster)
  self._cluster = cluster
  return self
end

setmetatable(CommissioningServerAttributes, attr_mt)

return CommissioningServerAttributes

-- Copyright 2022 SmartThings
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
local StructureABC = require "st.matter.data_types.base_defs.StructureABC"

--- @class st.matter.data_types.Structure: st.matter.data_types.StructureABC
--- @field public ID number 0x15
--- @field public NAME string "Structure"
--- @field public elements table the list of elements in this structure
local Structure = {}
setmetatable(Structure, StructureABC.new_mt({NAME = "Structure", ID = 0x15}))

return Structure

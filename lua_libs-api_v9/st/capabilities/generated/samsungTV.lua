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

return [[{"name": "Samsung TV", "status": "live", "attributes": {"messageButton": {"schema": {"type": "object", "additionalProperties": false, "properties": {"value": {"$ref": "JsonObject"}}}}, "mute": {"schema": {"type": "object", "additionalProperties": false, "properties": {"value": {"type": "string", "enum": ["muted", "unknown", "unmuted"]}}}, "enumCommands": [{"command": "mute", "value": "muted"}, {"command": "unmute", "value": "unmuted"}]}, "pictureMode": {"schema": {"type": "object", "additionalProperties": false, "properties": {"value": {"type": "string", "enum": ["dynamic", "movie", "standard", "unknown"]}}}, "setter": "setPictureMode"}, "soundMode": {"schema": {"type": "object", "additionalProperties": false, "properties": {"value": {"type": "string", "enum": ["clear voice", "movie", "music", "standard", "unknown"]}}}, "setter": "setSoundMode"}, "switch": {"schema": {"type": "object", "additionalProperties": false, "properties": {"value": {"$ref": "SwitchState"}}}, "enumCommands": [{"command": "on", "value": "on"}, {"command": "off", "value": "off"}]}, "volume": {"schema": {"type": "object", "additionalProperties": false, "properties": {"value": {"$ref": "PositiveInteger"}}}, "setter": "setVolume", "actedOnBy": ["volumeUp", "volumeDown"]}}, "commands": {"mute": {"arguments": [], "name": "mute"}, "off": {"arguments": [], "name": "off"}, "on": {"arguments": [], "name": "on"}, "setPictureMode": {"arguments": [{"name": "pictureMode", "schema": {"type": "string", "enum": ["dynamic", "movie", "standard"]}, "optional": false}], "name": "setPictureMode"}, "setSoundMode": {"arguments": [{"name": "soundMode", "schema": {"type": "string", "enum": ["clear voice", "movie", "music", "standard"]}, "optional": false}], "name": "setSoundMode"}, "setVolume": {"arguments": [{"name": "volume", "schema": {"$ref": "PositiveInteger"}, "optional": false}], "name": "setVolume"}, "showMessage": {"arguments": [{"name": "1", "schema": {"$ref": "String"}, "optional": false}, {"name": "2", "schema": {"$ref": "String"}, "optional": false}, {"name": "3", "schema": {"$ref": "String"}, "optional": false}, {"name": "4", "schema": {"$ref": "String"}, "optional": false}], "name": "showMessage"}, "unmute": {"arguments": [], "name": "unmute"}, "volumeDown": {"arguments": [], "name": "volumeDown"}, "volumeUp": {"arguments": [], "name": "volumeUp"}}, "id": "samsungTV", "version": 1}]]

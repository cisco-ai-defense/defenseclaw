# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
# SPDX-License-Identifier: Apache-2.0

package defenseclaw.guardrail

import rego.v1

# Agent Control distributes validated policy data; these helpers combine it
# with the local DefenseClaw baseline. The supplemental loader always injects
# a disabled object when the file is absent. Explicit data references (rather
# than a dynamic object.get on the data root) keep the package non-recursive
# when Rego unit-test modules are loaded into the same compiler.

_agent_control_enabled := data.agent_control.enabled if {
	data.agent_control.enabled
} else := false

_agent_control_precedence := data.agent_control.precedence if {
	data.agent_control.precedence
} else := "stricter"

_agent_control_guardrail := data.agent_control.guardrail if {
	data.agent_control.guardrail
} else := {}

_effective_block_threshold := data.guardrail.block_threshold if {
	not _agent_control_enabled
} else := min({data.guardrail.block_threshold, _agent_control_guardrail.block_threshold}) if {
	_agent_control_precedence == "stricter"
} else := _agent_control_guardrail.block_threshold

_effective_alert_threshold := data.guardrail.alert_threshold if {
	not _agent_control_enabled
} else := min({data.guardrail.alert_threshold, _agent_control_guardrail.alert_threshold}) if {
	_agent_control_precedence == "stricter"
} else := _agent_control_guardrail.alert_threshold

_trust_rank := {"none": 0, "advisory": 1, "full": 2}

_effective_cisco_trust_level := data.guardrail.cisco_trust_level if {
	not _agent_control_enabled
} else := data.guardrail.cisco_trust_level if {
	_agent_control_precedence == "stricter"
	_trust_rank[data.guardrail.cisco_trust_level] >= _trust_rank[_agent_control_guardrail.cisco_trust_level]
} else := _agent_control_guardrail.cisco_trust_level if {
	_agent_control_precedence == "stricter"
	_trust_rank[data.guardrail.cisco_trust_level] < _trust_rank[_agent_control_guardrail.cisco_trust_level]
} else := _agent_control_guardrail.cisco_trust_level

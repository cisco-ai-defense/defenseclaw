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

# LLM guardrail verdict policy. It reads only input; config.yaml is the
# single source of truth and the gateway resolves every value below.
# Input fields:
#   direction       - "prompt" or "completion"
#   model           - model name
#   mode            - "observe" or "action"
#   scanner_mode    - "local", "remote", or "both"
#   local_result    - {action, severity, findings[]} or null
#   cisco_result    - {action, severity, findings[], is_safe} or null
#   content_length  - int
#   thresholds      - {block, alert, cisco_trust_level}: the severity ranks
#                     (CRITICAL=4, HIGH=3, MEDIUM=2, LOW=1) that block and
#                     alert for the request's connector and profile
#                     (guardrail.block_at / alert_at, else the rule pack's
#                     posture), and guardrail.cisco_trust_level
#                     ("full" | "advisory" | "none"). Absent: 4, 2, full.
#   hilt            - {enabled, min_severity} from guardrail.hilt; absent
#                     means human-in-the-loop confirmation is off.

severity_rank := {"NONE": 0, "LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}

default severity := "NONE"
default reason := ""

_block_threshold := object.get(input, ["thresholds", "block"], 4)

_alert_threshold := object.get(input, ["thresholds", "alert"], 2)

_cisco_trust_level := object.get(input, ["thresholds", "cisco_trust_level"], "full")

# --- Determine effective severity from all scanner sources ---

effective_severity := _highest_severity

_local_sev_rank := severity_rank[input.local_result.severity] if {
	input.local_result
	input.local_result.severity
} else := 0

_cisco_sev_rank := severity_rank[input.cisco_result.severity] if {
	input.cisco_result
	input.cisco_result.severity
	_cisco_trust_level != "none"
} else := 0

_highest_sev_rank := max({_local_sev_rank, _cisco_sev_rank, 0})

_highest_severity := "CRITICAL" if _highest_sev_rank == 4

else := "HIGH" if _highest_sev_rank == 3

else := "MEDIUM" if _highest_sev_rank == 2

else := "LOW" if _highest_sev_rank == 1

else := "NONE"

severity := effective_severity

# --- Determine action ---
# Priority: observe override > advisory downgrade > block > confirm > alert > allow
# Using else-chain to avoid conflict errors.

action := "alert" if {
	input.mode == "observe"
	_highest_sev_rank >= _alert_threshold
} else := "alert" if {
	_cisco_trust_level == "advisory"
	_cisco_sev_rank >= _block_threshold
	_local_sev_rank < _alert_threshold
} else := "block" if {
	_highest_sev_rank >= _block_threshold
} else := "confirm" if {
	input.mode == "action"
	_hilt_enabled
	_highest_sev_rank >= _hilt_min_rank
} else := "alert" if {
	_highest_sev_rank >= _alert_threshold
} else := "allow"

_hilt_enabled := object.get(input, ["hilt", "enabled"], false)

_hilt_min_rank := object.get(severity_rank, object.get(input, ["hilt", "min_severity"], "HIGH"), 3)

# --- Build reason ---

reason := _build_reason

_local_reason := input.local_result.reason if {
	input.local_result
	input.local_result.reason != ""
} else := ""

_cisco_reason := input.cisco_result.reason if {
	input.cisco_result
	input.cisco_result.reason != ""
} else := ""

_build_reason := sprintf("%s; %s", [_local_reason, _cisco_reason]) if {
	_local_reason != ""
	_cisco_reason != ""
} else := _local_reason if {
	_local_reason != ""
} else := _cisco_reason if {
	_cisco_reason != ""
} else := ""

# --- Scanner sources ---

scanner_sources contains "local-pattern" if {
	input.local_result
	input.local_result.severity != "NONE"
}

scanner_sources contains "ai-defense" if {
	input.cisco_result
	input.cisco_result.severity != "NONE"
}

scanner_sources contains "opa-policy" if {
	_highest_sev_rank > 0
}

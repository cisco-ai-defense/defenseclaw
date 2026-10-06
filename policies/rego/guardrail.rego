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

# LLM guardrail verdict policy.
# Input fields:
#   direction       - "prompt" or "completion"
#   model           - model name
#   mode            - "observe" or "action"
#   scanner_mode    - "local", "remote", or "both"
#   local_result    - {action, severity, findings[]} or null
#   cisco_result    - {action, severity, findings[], is_safe} or null
#   content_length  - int
#
#   thresholds      - {block, alert, cisco_trust_level}: the resolved block and
#                     alert ranks (4=CRITICAL, 3=HIGH, 2=MEDIUM, 1=LOW) and the
#                     Cisco AI Defense trust level ("full" | "advisory" | "none"),
#                     from config.yaml (policy.ThresholdsInput)
#   hilt            - {enabled, min_severity}: config.yaml guardrail.hilt
#
# The policy reads only input: config.yaml is the only source.

default severity := "NONE"
default reason := ""

# --- Determine effective severity from all scanner sources ---

effective_severity := _highest_severity

_severity_rank := {"NONE": 0, "LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}

_local_sev_rank := _severity_rank[input.local_result.severity] if {
	input.local_result
	input.local_result.severity
} else := 0

_cisco_sev_rank := _severity_rank[input.cisco_result.severity] if {
	input.cisco_result
	input.cisco_result.severity
	input.thresholds.cisco_trust_level != "none"
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
	_highest_sev_rank >= input.thresholds.alert
} else := "alert" if {
	input.thresholds.cisco_trust_level == "advisory"
	_cisco_sev_rank >= input.thresholds.block
	_local_sev_rank < input.thresholds.alert
} else := "block" if {
	_highest_sev_rank >= input.thresholds.block
} else := "confirm" if {
	input.mode == "action"
	_hilt_enabled
	_highest_sev_rank >= _hilt_min_rank
} else := "alert" if {
	_highest_sev_rank >= input.thresholds.alert
} else := "allow"

_hilt := object.get(input, "hilt", {})

_hilt_enabled := object.get(_hilt, "enabled", false)

_hilt_min_rank := object.get(_severity_rank, object.get(_hilt, "min_severity", "HIGH"), 3)

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

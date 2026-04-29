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
#   policy_tier     - "default" | "strict" | "permissive" (optional; default = "default")
#   taint_context   - object describing session-level taint state from
#                     the Go-side TaintTracker (optional). All decisions
#                     about whether and how to escalate based on this
#                     overlay live in this file — Go produces only data.
#
# Static data (data.guardrail in data.json):
#   severity_rank.<SEV>           - int ranking (CRITICAL=4, HIGH=3, ...)
#   block_threshold               - minimum severity rank to block (default 3 = HIGH)
#   alert_threshold               - minimum severity rank to alert (default 2 = MEDIUM)
#   cisco_trust_level             - "full" | "advisory" | "none"
#   taint.<tier>                  - per-tier taint policy knobs:
#     mode                          "observe" | "action"
#     escalation_steps_strong       int (severity rank bumps when a consumer
#                                   references a tainted/sensitive file)
#     escalation_steps_weak         int (rank bumps for weak path)
#     require_taint_source          bool (weak path gated on session source)
#     min_consumer_confidence       float (weak path confidence floor)

default severity := "NONE"

default reason := ""

# --- Determine effective severity from all scanner sources ---

effective_severity := _highest_severity

_local_sev_rank := data.guardrail.severity_rank[input.local_result.severity] if {
	input.local_result
	input.local_result.severity
} else := 0

_cisco_sev_rank := data.guardrail.severity_rank[input.cisco_result.severity] if {
	input.cisco_result
	input.cisco_result.severity
	data.guardrail.cisco_trust_level != "none"
} else := 0

_base_sev_rank := max({_local_sev_rank, _cisco_sev_rank, 0})

# --- Taint-driven severity escalation ---
#
# The Go-side TaintTracker emits a pure-data overlay (taint_context).
# This block is the SOLE place where escalation steps are computed and
# applied. The result is bounded by CRITICAL (rank 4) and never lowers
# the base severity.

# Resolve the effective tier knobs. If input.policy_tier is missing or
# unknown, fall back to "default".
_tier := input.policy_tier if {
	input.policy_tier
	data.guardrail.taint[input.policy_tier]
} else := "default"

_taint_knobs := data.guardrail.taint[_tier] if {
	data.guardrail.taint[_tier]
} else := {
	"mode": "action",
	"escalation_steps_strong": 0,
	"escalation_steps_weak": 0,
	"require_taint_source": true,
	"min_consumer_confidence": 1.0,
}

# Strong escalation path: a taint-consumer references a tainted or
# baseline-sensitive file. This is the highest-confidence multi-step
# evidence. Active in any non-observe mode, regardless of session flag
# liveness.
_taint_steps_strong := _taint_knobs.escalation_steps_strong if {
	_taint_knobs.mode != "observe"
	input.taint_context
	input.taint_context.has_strong_consumer == true
} else := 0

# Weak escalation path: a taint-consumer fires in a tainted session but
# doesn't reference a known-tainted file. Gated on:
#   - mode != observe
#   - confidence above min_consumer_confidence
#   - require_taint_source ⇒ session has live source flag
#   - network destination not in exclusion list (so internal/loopback
#     traffic doesn't trigger weak escalation alone)
_taint_steps_weak := _taint_knobs.escalation_steps_weak if {
	_taint_knobs.mode != "observe"
	input.taint_context
	input.taint_context.has_weak_consumer == true
	not input.taint_context.network_dest_excluded
	input.taint_context.max_consumer_confidence >= _taint_knobs.min_consumer_confidence
	_weak_source_ok
} else := 0

_weak_source_ok if {
	not _taint_knobs.require_taint_source
}

_weak_source_ok if {
	_taint_knobs.require_taint_source
	input.taint_context.has_taint_source_in_session == true
}

# Strong is preferred when both paths qualify; we never sum them.
_taint_steps := _taint_steps_strong if {
	_taint_steps_strong > 0
} else := _taint_steps_weak

# Final escalated rank, capped at CRITICAL (4).
_escalated_sev_rank := _x if {
	_x := _base_sev_rank + _taint_steps
	_x <= 4
} else := 4

_highest_sev_rank := _escalated_sev_rank

_highest_severity := "CRITICAL" if _highest_sev_rank == 4

else := "HIGH" if _highest_sev_rank == 3

else := "MEDIUM" if _highest_sev_rank == 2

else := "LOW" if _highest_sev_rank == 1

else := "NONE"

severity := effective_severity

# --- Determine action ---
# Priority: observe override > advisory downgrade > block > alert > allow
# Using else-chain to avoid conflict errors.

action := "alert" if {
	input.mode == "observe"
	_highest_sev_rank >= data.guardrail.block_threshold
} else := "alert" if {
	data.guardrail.cisco_trust_level == "advisory"
	_cisco_sev_rank >= data.guardrail.block_threshold
	_local_sev_rank < data.guardrail.alert_threshold
} else := "block" if {
	_highest_sev_rank >= data.guardrail.block_threshold
} else := "alert" if {
	_highest_sev_rank >= data.guardrail.alert_threshold
} else := "allow"

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

_taint_reason := sprintf(
	"taint-escalation:%s tier=%s +%d steps (base=%d → %d)",
	[_taint_path_label, _tier, _taint_steps, _base_sev_rank, _highest_sev_rank],
) if {
	_taint_steps > 0
} else := ""

_taint_path_label := "strong" if {
	_taint_steps_strong > 0
} else := "weak"

_build_reason := _join_reasons([_local_reason, _cisco_reason, _taint_reason])

_join_reasons(parts) := result if {
	non_empty := [p | p := parts[_]; p != ""]
	count(non_empty) > 0
	result := concat("; ", non_empty)
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

scanner_sources contains "taint-tracker" if {
	_taint_steps > 0
}

# --- Taint escalation telemetry payload ---
#
# Emitted only when escalation actually fired. The Go gateway lifts
# this into a structured audit event so operators can see why a
# verdict crossed the block threshold.

taint_escalation := {
	"path": _taint_path_label,
	"tier": _tier,
	"steps": _taint_steps,
	"base_severity_rank": _base_sev_rank,
	"effective_severity_rank": _highest_sev_rank,
	"tainted_files_referenced": _taint_files,
	"source_findings": _taint_sources,
	"events_since_source": _taint_events,
	"network_dest_excluded": _taint_excluded,
} if {
	_taint_steps > 0
}

_taint_files := input.taint_context.tainted_files_referenced if {
	input.taint_context
	input.taint_context.tainted_files_referenced
} else := []

_taint_sources := input.taint_context.source_findings if {
	input.taint_context
	input.taint_context.source_findings
} else := []

_taint_events := input.taint_context.events_since_source if {
	input.taint_context
	input.taint_context.events_since_source
} else := 0

_taint_excluded := input.taint_context.network_dest_excluded if {
	input.taint_context
	input.taint_context.network_dest_excluded
} else := false

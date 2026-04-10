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

package defenseclaw.admission

import rego.v1

# Admission gate: block → allow → scan_on_install bypass → scan → severity-based verdict.
# Input fields:
#   target_type   - "skill", "mcp", or "plugin"
#   target_name   - name of the skill, MCP server, or plugin
#   path          - filesystem path
#   block_list    - array of {target_type, target_name, reason}
#   allow_list    - array of {target_type, target_name, reason}
#   scan_result   - optional {max_severity, total_findings, scanner_name, findings}
#
# Static data (data.json):
#   config.allow_list_bypass_scan  - bool
#   config.scan_on_install         - bool (when false, skip scan if no result present)
#   actions.<SEVERITY>.runtime     - "block" or "allow"
#   actions.<SEVERITY>.file        - "quarantine" or "none"
#   actions.<SEVERITY>.install     - "block", "allow", or "none"
#   scanner_overrides.<TYPE>.<SEVERITY> - per-scanner-type action overrides
#   severity_ranking.<SEVERITY>    - int (CRITICAL=5 … INFO=1)

default verdict := "scan"

default reason := "awaiting scan"

# --- Block list (highest priority) ---

verdict := "blocked" if _is_blocked

reason := sprintf("%s '%s' is on the block list", [input.target_type, input.target_name]) if {
	verdict == "blocked"
}

# --- Signing enforcement (after block list, before allow list) ---

verdict := "rejected" if {
	not _is_blocked
	data.signing.mode == "enforce"
	not _is_signed
}

reason := "unsigned or untrusted — signing policy is 'enforce'" if {
	not _is_blocked
	data.signing.mode == "enforce"
	not _is_signed
}

_is_signed if {
	input.signing_status
	input.signing_status.signed == true
	input.signing_status.trusted == true
}

# --- Allow list (skip scan when configured) ---

verdict := "allowed" if {
	not _is_blocked
	_is_allow_listed
	data.config.allow_list_bypass_scan == true
}

reason := sprintf("%s '%s' is on the allow list — scan skipped", [input.target_type, input.target_name]) if {
	not _is_blocked
	_is_allow_listed
	data.config.allow_list_bypass_scan == true
}

# --- scan_on_install disabled: skip scan when no result present ---

verdict := "allowed" if {
	not _is_blocked
	not _is_allow_bypassed
	not _has_scan
	data.config.scan_on_install == false
}

reason := "scan_on_install disabled — allowed without scan" if {
	not _is_blocked
	not _is_allow_bypassed
	not _has_scan
	data.config.scan_on_install == false
}

# --- Scan: clean (no findings) ---

verdict := "clean" if {
	not _is_blocked
	not _is_allow_bypassed
	_has_scan
	input.scan_result.total_findings == 0
}

reason := "scan clean" if {
	not _is_blocked
	not _is_allow_bypassed
	_has_scan
	input.scan_result.total_findings == 0
}

# --- Scan: rejected (severity triggers block) ---

verdict := "rejected" if {
	not _is_blocked
	not _is_allow_bypassed
	_has_scan
	input.scan_result.total_findings > 0
	_should_reject
}

reason := sprintf("max severity %s triggers block per policy", [input.scan_result.max_severity]) if {
	not _is_blocked
	not _is_allow_bypassed
	_has_scan
	input.scan_result.total_findings > 0
	_should_reject
}

# --- Scan: warning (findings present but below block threshold) ---

verdict := "warning" if {
	not _is_blocked
	not _is_allow_bypassed
	_has_scan
	input.scan_result.total_findings > 0
	not _should_reject
}

reason := sprintf("findings present (max %s) — allowed with warning", [input.scan_result.max_severity]) if {
	not _is_blocked
	not _is_allow_bypassed
	_has_scan
	input.scan_result.total_findings > 0
	not _should_reject
}

# --- Helper rules ---

_is_blocked if {
	some entry in input.block_list
	entry.target_name == input.target_name
	entry.target_type == input.target_type
}

_is_allow_listed if {
	some entry in input.allow_list
	entry.target_name == input.target_name
	entry.target_type == input.target_type
}

_is_allow_bypassed if {
	_is_allow_listed
	data.config.allow_list_bypass_scan == true
}

_has_scan if input.scan_result

# --- Per-scanner action resolution ---
# Check scanner_overrides[target_type][severity] first, fall back to global actions.

_effective_action := action if {
	action := data.scanner_overrides[input.target_type][input.scan_result.max_severity]
} else := action if {
	action := data.actions[input.scan_result.max_severity]
}

_should_reject if {
	_effective_action.runtime == "block"
}

# --- Structured output: file_action ---

file_action := action if {
	_has_scan
	action := _effective_action.file
}

file_action := "none" if {
	not _has_scan
}

# --- Structured output: install_action ---

install_action := action if {
	_has_scan
	action := _effective_action.install
}

install_action := "none" if {
	not _has_scan
}
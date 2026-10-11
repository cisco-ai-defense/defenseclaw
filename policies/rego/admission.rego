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

# Admission gate: block -> allow -> first-party bypass -> scan_on_install ->
# scan -> severity verdict. Every input comes from config.yaml; no data.* is
# read, so there is no second policy source.
#
# Input fields:
#   target_type   - "skill", "mcp", or "plugin"
#   target_name   - name of the skill, MCP server, or plugin
#   path          - filesystem path
#   block_list    - [{target_type, target_name, reason, source_path?, connector?}]
#                   from asset_policy.<type>.denied
#   allow_list    - the same shape, from asset_policy.<type>.allowed
#   scan_result   - optional {max_severity, total_findings, scanner_name,
#                   findings, exit_code, scan_error}
#   admission     - config admission: compiled for target_type
#                   (policy.CompiledAdmission):
#     scan_on_install, allow_list_bypass_scan          - bool
#     actions.<SEVERITY>                               - {install, file, runtime, verdict?}
#     scanner_overrides.<scanner_name>.<SEVERITY>      - the same, per scanner
#     first_party_allow_list                           - [{name, source_path_contains, reason?}]

default verdict := "scan"

default reason := "awaiting scan"

# --- Block list (highest priority) ---

verdict := "blocked" if _is_blocked

reason := sprintf("%s '%s' is on the block list", [input.target_type, input.target_name]) if {
	_is_blocked
}

# --- Explicit allow list (manual override; always skip scan) ---

verdict := "allowed" if {
	not _is_blocked
	_is_explicit_allow_listed
}

reason := sprintf("%s '%s' is on the allow list — scan skipped", [input.target_type, input.target_name]) if {
	not _is_blocked
	_is_explicit_allow_listed
}

# --- First-party allow list (skip scan when configured) ---

verdict := "allowed" if {
	not _is_blocked
	not _is_explicit_allow_listed
	_is_policy_allow_listed
	input.admission.allow_list_bypass_scan == true
}

reason := _first_party_reason if {
	not _is_blocked
	not _is_explicit_allow_listed
	_is_policy_allow_listed
	input.admission.allow_list_bypass_scan == true
}

_first_party_reason := r if {
	r := object.get(_first_party_matches[0], "reason", "")
	r != ""
} else := sprintf("%s '%s' is on the allow list — scan skipped", [input.target_type, input.target_name])

# --- scan_on_install disabled: skip scan when no result present ---

verdict := "allowed" if {
	not _is_blocked
	not _is_allow_bypassed
	not _has_scan
	input.admission.scan_on_install == false
}

reason := "scan_on_install disabled — allowed without scan" if {
	not _is_blocked
	not _is_allow_bypassed
	not _has_scan
	input.admission.scan_on_install == false
}

# --- Scan: the scanner failed (fail closed) ---

verdict := "rejected" if {
	_scan_considered
	_scan_failed
}

reason := sprintf("scanner failed: %s", [object.get(input.scan_result, "scan_error", "")]) if {
	_scan_considered
	_scan_failed
}

# --- Scan: clean (no findings) ---

verdict := "clean" if {
	_scan_considered
	not _scan_failed
	input.scan_result.total_findings == 0
}

reason := "scan clean" if {
	_scan_considered
	not _scan_failed
	input.scan_result.total_findings == 0
}

# --- Scan: rejected (severity triggers block) ---

verdict := "rejected" if {
	_scan_has_findings
	_should_reject
}

reason := sprintf("max severity %s triggers block per policy", [input.scan_result.max_severity]) if {
	_scan_has_findings
	_should_reject
}

# --- Scan: allowed by an explicit allow action ---

verdict := "allowed" if {
	_scan_has_findings
	not _should_reject
	_effective_action.verdict == "allowed"
}

reason := sprintf("findings present (max %s) — allowed by policy", [input.scan_result.max_severity]) if {
	_scan_has_findings
	not _should_reject
	_effective_action.verdict == "allowed"
}

# --- Scan: warning (findings present but below the block threshold) ---

verdict := "warning" if {
	_scan_has_findings
	not _should_reject
	not _effective_action.verdict == "allowed"
}

reason := sprintf("findings present (max %s) — allowed with warning", [input.scan_result.max_severity]) if {
	_scan_has_findings
	not _should_reject
	not _effective_action.verdict == "allowed"
}

# --- Helper rules ---

_scan_considered if {
	not _is_blocked
	not _is_allow_bypassed
	_has_scan
}

_scan_has_findings if {
	_scan_considered
	not _scan_failed
	input.scan_result.total_findings > 0
}

_scan_failed if object.get(input.scan_result, "scan_error", "") != ""

_scan_failed if object.get(input.scan_result, "exit_code", 0) != 0

# A list entry matches on type and name. An entry that pins a source_path
# (asset_policy source_path_contains) also requires the presented path to
# contain it as whole path components (F-0941), so an allow or block for one
# on-disk asset never transfers to a different asset that reuses the name.
_is_blocked if {
	some entry in input.block_list
	entry.target_name == input.target_name
	entry.target_type == input.target_type
	_entry_path_matches(entry)
}

_is_explicit_allow_listed if {
	some entry in input.allow_list
	entry.target_name == input.target_name
	entry.target_type == input.target_type
	_entry_path_matches(entry)
}

_entry_path_matches(entry) if {
	object.get(entry, "source_path", "") == ""
}

_entry_path_matches(entry) if {
	entry.source_path != ""
	_provenance_prefix_matches(input.path, entry.source_path)
}

_is_policy_allow_listed if count(_first_party_matches) > 0

# An array comprehension keeps entry order, so the first matching reason
# agrees with EvaluateAdmissionFallback when names appear more than once.
_first_party_matches := [entry |
	some i
	entry := input.admission.first_party_allow_list[i]
	entry.name == input.target_name
	_path_has_component_marker(input.path, entry.source_path_contains)
]

_path_has_component_marker(path, markers) if {
	some marker in markers
	_provenance_prefix_matches(path, marker)
}

# F-0543: match provenance markers by whole path *components* (a contiguous
# slice of components), not a bare substring, so `.defenseclaw-evil` never
# satisfies a `.defenseclaw` marker. policy.EvaluateAdmissionFallback and the
# Python `_matches_provenance` use the same matcher.
_provenance_prefix_matches(path, prefix) if {
	path_comps := _path_components(path)
	prefix_comps := _path_components(prefix)
	n := count(prefix_comps)
	n > 0
	count(path_comps) >= n
	some i in numbers.range(0, count(path_comps) - n)
	array.slice(path_comps, i, i + n) == prefix_comps
}

_path_components(value) := comps if {
	normalized := replace(lower(value), "\\", "/")
	comps := [part | some part in split(normalized, "/"); part != ""]
}

_is_allow_bypassed if {
	_is_explicit_allow_listed
}

_is_allow_bypassed if {
	_is_policy_allow_listed
	input.admission.allow_list_bypass_scan == true
}

_has_scan if input.scan_result

# --- Action resolution ---
# scanner_overrides[scanner_name][severity] first, then actions[severity]. A
# severity no action covers fails closed.

_sev := upper(object.get(input.scan_result, "max_severity", ""))

_effective_action := action if {
	action := input.admission.scanner_overrides[input.scan_result.scanner_name][_sev]
} else := action if {
	action := input.admission.actions[_sev]
} else := {"install": "block", "file": "none", "runtime": "block"}

_should_reject if {
	_effective_action.runtime == "block"
}

_should_reject if {
	_effective_action.install == "block"
}

_should_reject if {
	_effective_action.file == "quarantine"
}

# --- Structured outputs: file_action, install_action, runtime_action ---

file_action := "quarantine" if {
	_scan_considered
	_scan_failed
}

file_action := action if {
	_scan_has_findings
	action := _effective_action.file
}

default file_action := "none"

install_action := "block" if {
	_scan_considered
	_scan_failed
}

install_action := action if {
	_scan_has_findings
	action := _effective_action.install
}

default install_action := "none"

runtime_action := "block" if {
	_scan_considered
	_scan_failed
}

runtime_action := action if {
	_scan_has_findings
	action := _effective_action.runtime
}

default runtime_action := "allow"

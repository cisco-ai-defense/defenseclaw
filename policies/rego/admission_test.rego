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

package defenseclaw.admission_test

import rego.v1

import data.defenseclaw.admission

# The compiled admission the gateway sends for a skill with the built-in
# defaults (policy.CompileAdmission of an empty admission: section).
_quarantine := {"install": "block", "file": "quarantine", "runtime": "block"}

_warn := {"install": "none", "file": "none", "runtime": "allow"}

_skill_admission := {
	"scan_on_install": true,
	"allow_list_bypass_scan": true,
	"actions": {"CRITICAL": _quarantine, "HIGH": _quarantine, "MEDIUM": _warn, "LOW": _warn, "INFO": _warn},
	"first_party_allow_list": [{"name": "codeguard", "source_path_contains": [".claude/skills/codeguard"]}],
}

_input(extra) := object.union(
	{
		"target_type": "skill",
		"target_name": "s1",
		"path": "/home/u/.claude/skills/s1",
		"block_list": [],
		"allow_list": [],
		"admission": _skill_admission,
	},
	extra,
)

_scan(sev, n) := {"scan_result": {"max_severity": sev, "total_findings": n, "scanner_name": "skill-scanner"}}

test_pre_scan_needs_scan if {
	admission.verdict == "scan" with input as _input({})
}

test_block_list_wins_over_allow_list if {
	entry := {"target_type": "skill", "target_name": "s1", "reason": "operator"}
	admission.verdict == "blocked" with input as _input({"block_list": [entry], "allow_list": [entry]})
}

test_block_list_is_typed if {
	entry := {"target_type": "mcp", "target_name": "s1", "reason": "operator"}
	admission.verdict == "scan" with input as _input({"block_list": [entry]})
}

test_allow_list_skips_scan if {
	entry := {"target_type": "skill", "target_name": "s1", "reason": "vetted"}
	admission.verdict == "allowed" with input as _input(object.union({"allow_list": [entry]}, _scan("CRITICAL", 1)))
}

# F-0941: a path-pinned allow entry does not transfer to another path.
test_allow_list_source_path_pin if {
	entry := {"target_type": "skill", "target_name": "s1", "reason": "vetted", "source_path": "/opt/vetted/s1"}
	admission.verdict == "allowed" with input as _input({"allow_list": [entry], "path": "/opt/vetted/s1"})
	admission.verdict == "scan" with input as _input({"allow_list": [entry], "path": "/tmp/attacker/s1"})
}

test_first_party_bypass_needs_component_match if {
	admission.verdict == "allowed" with input as _input({"target_name": "codeguard", "path": "/home/u/.claude/skills/codeguard"})
	admission.verdict == "scan" with input as _input({"target_name": "codeguard", "path": "/tmp/x.claude/skills/codeguard-evil"})
}

test_first_party_bypass_off if {
	adm := object.union(_skill_admission, {"allow_list_bypass_scan": false})
	admission.verdict == "scan" with input as _input({"target_name": "codeguard", "path": "/home/u/.claude/skills/codeguard", "admission": adm})
}

test_scan_on_install_false_allows_without_scan if {
	adm := object.union(_skill_admission, {"scan_on_install": false})
	admission.verdict == "allowed" with input as _input({"admission": adm})
}

test_clean_scan if {
	result := admission with input as _input(_scan("INFO", 0))
	result.verdict == "clean"
	result.install_action == "none"
}

test_high_rejects_and_quarantines if {
	result := admission with input as _input(_scan("high", 2))
	result.verdict == "rejected"
	result.file_action == "quarantine"
	result.install_action == "block"
	result.runtime_action == "block"
}

test_medium_warns if {
	result := admission with input as _input(_scan("MEDIUM", 1))
	result.verdict == "warning"
	result.runtime_action == "allow"
}

test_allow_action_verdict_allowed if {
	adm := object.union(_skill_admission, {"actions": {"MEDIUM": object.union(_warn, {"verdict": "allowed"})}})
	admission.verdict == "allowed" with input as _input(object.union({"admission": adm}, _scan("MEDIUM", 1)))
}

test_scanner_override_by_scanner_name if {
	adm := object.union(_skill_admission, {"scanner_overrides": {"codeguard": {"MEDIUM": _quarantine}}})
	vt := {"scan_result": {"max_severity": "MEDIUM", "total_findings": 1, "scanner_name": "codeguard"}}
	admission.verdict == "rejected" with input as _input(object.union({"admission": adm}, vt))
	admission.verdict == "warning" with input as _input(object.union({"admission": adm}, _scan("MEDIUM", 1)))
}

test_unknown_severity_fails_closed if {
	result := admission with input as _input(_scan("BOGUS", 1))
	result.verdict == "rejected"
	result.install_action == "block"
}

test_missing_admission_fails_closed if {
	inp := object.remove(_input(_scan("LOW", 1)), ["admission"])
	admission.verdict == "rejected" with input as inp
}

test_scan_error_rejects if {
	failed := {"scan_result": {"max_severity": "INFO", "total_findings": 0, "scan_error": "timeout"}}
	result := admission with input as _input(failed)
	result.verdict == "rejected"
	result.file_action == "quarantine"
}

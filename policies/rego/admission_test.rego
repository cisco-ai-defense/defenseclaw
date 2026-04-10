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

# --- Blocked ---

test_blocked_skill if {
	result := admission with input as {
		"target_type": "skill",
		"target_name": "evil-skill",
		"path": "/tmp/evil",
		"block_list": [{"target_type": "skill", "target_name": "evil-skill", "reason": "malware"}],
		"allow_list": [],
	}
		with data.config as {"allow_list_bypass_scan": true, "scan_on_install": true}
		with data.actions as {}
		with data.scanner_overrides as {}
		with data.severity_ranking as {}

	result.verdict == "blocked"
}

test_blocked_reason if {
	result := admission with input as {
		"target_type": "mcp",
		"target_name": "bad-mcp",
		"path": "/tmp/bad",
		"block_list": [{"target_type": "mcp", "target_name": "bad-mcp", "reason": "vuln"}],
		"allow_list": [],
	}
		with data.config as {"allow_list_bypass_scan": true, "scan_on_install": true}
		with data.actions as {}
		with data.scanner_overrides as {}
		with data.severity_ranking as {}

	contains(result.reason, "block list")
}

test_not_blocked_different_name if {
	result := admission with input as {
		"target_type": "skill",
		"target_name": "safe-skill",
		"path": "/tmp/safe",
		"block_list": [{"target_type": "skill", "target_name": "other-skill", "reason": "x"}],
		"allow_list": [],
	}
		with data.config as {"allow_list_bypass_scan": true, "scan_on_install": true}
		with data.actions as {}
		with data.scanner_overrides as {}
		with data.severity_ranking as {}

	result.verdict != "blocked"
}

# --- Allowed via allow list ---

test_allowed_bypass_scan if {
	result := admission with input as {
		"target_type": "skill",
		"target_name": "trusted-skill",
		"path": "/tmp/trusted",
		"block_list": [],
		"allow_list": [{"target_type": "skill", "target_name": "trusted-skill", "reason": "vendor"}],
	}
		with data.config as {"allow_list_bypass_scan": true, "scan_on_install": true}
		with data.actions as {}
		with data.scanner_overrides as {}
		with data.severity_ranking as {}

	result.verdict == "allowed"
}

test_allowed_no_bypass_falls_through if {
	result := admission with input as {
		"target_type": "skill",
		"target_name": "trusted-skill",
		"path": "/tmp/trusted",
		"block_list": [],
		"allow_list": [{"target_type": "skill", "target_name": "trusted-skill", "reason": "vendor"}],
	}
		with data.config as {"allow_list_bypass_scan": false, "scan_on_install": true}
		with data.actions as {}
		with data.scanner_overrides as {}
		with data.first_party_allow_list as []
		with data.severity_ranking as {}

	result.verdict == "allowed"
}

test_policy_allow_no_bypass_falls_through if {
	result := admission with input as {
		"target_type": "skill",
		"target_name": "codeguard",
		"path": "/tmp/codeguard",
		"block_list": [],
		"allow_list": [],
	}
		with data.config as {"allow_list_bypass_scan": false, "scan_on_install": true}
		with data.actions as {}
		with data.scanner_overrides as {}
		with data.first_party_allow_list as [{"target_type": "skill", "target_name": "codeguard", "reason": "first-party"}]
		with data.severity_ranking as {}

	result.verdict == "scan"
}

# --- scan_on_install disabled ---

test_scan_on_install_false_allows_without_scan if {
	result := admission with input as {
		"target_type": "skill",
		"target_name": "new-skill",
		"path": "/tmp/new",
		"block_list": [],
		"allow_list": [],
	}
		with data.config as {"allow_list_bypass_scan": false, "scan_on_install": false}
		with data.actions as {}
		with data.scanner_overrides as {}
		with data.severity_ranking as {}

	result.verdict == "allowed"
	contains(result.reason, "scan_on_install disabled")
}

test_scan_on_install_true_requires_scan if {
	result := admission with input as {
		"target_type": "skill",
		"target_name": "new-skill",
		"path": "/tmp/new",
		"block_list": [],
		"allow_list": [],
	}
		with data.config as {"allow_list_bypass_scan": false, "scan_on_install": true}
		with data.actions as {}
		with data.scanner_overrides as {}
		with data.severity_ranking as {}

	result.verdict == "scan"
}

# --- Clean scan ---

test_clean_scan if {
	result := admission with input as {
		"target_type": "skill",
		"target_name": "good-skill",
		"path": "/tmp/good",
		"block_list": [],
		"allow_list": [],
		"scan_result": {"max_severity": "INFO", "total_findings": 0, "findings": []},
	}
		with data.config as {"allow_list_bypass_scan": true, "scan_on_install": true}
		with data.actions as {"INFO": {"runtime": "allow", "file": "none", "install": "none"}}
		with data.scanner_overrides as {}
		with data.severity_ranking as {"INFO": 1}

	result.verdict == "clean"
}

# --- Rejected (HIGH severity with default policy) ---

test_rejected_high if {
	result := admission with input as {
		"target_type": "skill",
		"target_name": "risky-skill",
		"path": "/tmp/risky",
		"block_list": [],
		"allow_list": [],
		"scan_result": {"max_severity": "HIGH", "total_findings": 2, "findings": [
			{"severity": "HIGH", "title": "vuln1", "scanner": "test"},
			{"severity": "MEDIUM", "title": "vuln2", "scanner": "test"},
		]},
	}
		with data.config as {"allow_list_bypass_scan": true, "scan_on_install": true}
		with data.actions as {
			"HIGH": {"runtime": "block", "file": "quarantine", "install": "block"},
			"MEDIUM": {"runtime": "allow", "file": "none", "install": "none"},
		}
		with data.scanner_overrides as {}
		with data.severity_ranking as {"HIGH": 4, "MEDIUM": 3, "LOW": 2, "INFO": 1}

	result.verdict == "rejected"
	result.file_action == "quarantine"
	result.install_action == "block"
}

# --- Warning (MEDIUM severity with default policy) ---

test_warning_medium if {
	result := admission with input as {
		"target_type": "skill",
		"target_name": "okish-skill",
		"path": "/tmp/ok",
		"block_list": [],
		"allow_list": [],
		"scan_result": {"max_severity": "MEDIUM", "total_findings": 1, "findings": [
			{"severity": "MEDIUM", "title": "minor-issue", "scanner": "test"},
		]},
	}
		with data.config as {"allow_list_bypass_scan": true, "scan_on_install": true}
		with data.actions as {
			"CRITICAL": {"runtime": "block", "file": "quarantine", "install": "block"},
			"HIGH": {"runtime": "block", "file": "quarantine", "install": "block"},
			"MEDIUM": {"runtime": "allow", "file": "none", "install": "none"},
		}
		with data.scanner_overrides as {}
		with data.severity_ranking as {"CRITICAL": 5, "HIGH": 4, "MEDIUM": 3, "LOW": 2, "INFO": 1}

	result.verdict == "warning"
}

# --- No scan result => default "scan" ---

test_default_scan_verdict if {
	result := admission with input as {
		"target_type": "skill",
		"target_name": "new-skill",
		"path": "/tmp/new",
		"block_list": [],
		"allow_list": [],
	}
		with data.config as {"allow_list_bypass_scan": true, "scan_on_install": true}
		with data.actions as {}
		with data.scanner_overrides as {}
		with data.severity_ranking as {}

	result.verdict == "scan"
}

# --- Block list takes priority over allow list ---

test_block_overrides_allow if {
	result := admission with input as {
		"target_type": "skill",
		"target_name": "dual-listed",
		"path": "/tmp/dual",
		"block_list": [{"target_type": "skill", "target_name": "dual-listed", "reason": "banned"}],
		"allow_list": [{"target_type": "skill", "target_name": "dual-listed", "reason": "trusted"}],
	}
		with data.config as {"allow_list_bypass_scan": true, "scan_on_install": true}
		with data.actions as {}
		with data.scanner_overrides as {}
		with data.severity_ranking as {}

	result.verdict == "blocked"
}

# --- Per-scanner overrides: MCP blocked on MEDIUM ---

test_scanner_override_mcp_medium_blocked if {
	result := admission with input as {
		"target_type": "mcp",
		"target_name": "risky-mcp",
		"path": "/tmp/mcp",
		"block_list": [],
		"allow_list": [],
		"scan_result": {"max_severity": "MEDIUM", "total_findings": 1, "scanner_name": "mcp-scanner", "findings": [
			{"severity": "MEDIUM", "title": "issue", "scanner": "mcp-scanner"},
		]},
	}
		with data.config as {"allow_list_bypass_scan": false, "scan_on_install": true}
		with data.actions as {
			"MEDIUM": {"runtime": "allow", "file": "none", "install": "none"},
		}
		with data.scanner_overrides as {
			"mcp": {"MEDIUM": {"runtime": "block", "file": "quarantine", "install": "block"}},
		}
		with data.severity_ranking as {"MEDIUM": 3}

	result.verdict == "rejected"
	result.file_action == "quarantine"
	result.install_action == "block"
}

# --- Per-scanner overrides: skill uses global (no override) ---

test_scanner_override_skill_uses_global if {
	result := admission with input as {
		"target_type": "skill",
		"target_name": "med-skill",
		"path": "/tmp/med",
		"block_list": [],
		"allow_list": [],
		"scan_result": {"max_severity": "MEDIUM", "total_findings": 1, "findings": [
			{"severity": "MEDIUM", "title": "issue", "scanner": "skill-scanner"},
		]},
	}
		with data.config as {"allow_list_bypass_scan": false, "scan_on_install": true}
		with data.actions as {
			"MEDIUM": {"runtime": "allow", "file": "none", "install": "none"},
		}
		with data.scanner_overrides as {
			"mcp": {"MEDIUM": {"runtime": "block", "file": "quarantine", "install": "block"}},
		}
		with data.severity_ranking as {"MEDIUM": 3}

	result.verdict == "warning"
}

# --- Per-scanner overrides: plugin stricter than global ---

test_scanner_override_plugin_high_blocked if {
	result := admission with input as {
		"target_type": "plugin",
		"target_name": "risky-plugin",
		"path": "/tmp/plugin",
		"block_list": [],
		"allow_list": [],
		"scan_result": {"max_severity": "HIGH", "total_findings": 1, "findings": [
			{"severity": "HIGH", "title": "vuln", "scanner": "plugin-scanner"},
		]},
	}
		with data.config as {"allow_list_bypass_scan": false, "scan_on_install": true}
		with data.actions as {
			"HIGH": {"runtime": "allow", "file": "none", "install": "none"},
		}
		with data.scanner_overrides as {
			"plugin": {"HIGH": {"runtime": "block", "file": "quarantine", "install": "block"}},
		}
		with data.severity_ranking as {"HIGH": 4}

	result.verdict == "rejected"
}

# --- Strict policy: MEDIUM triggers reject ---

test_strict_medium_rejected if {
	result := admission with input as {
		"target_type": "skill",
		"target_name": "med-skill",
		"path": "/tmp/med",
		"block_list": [],
		"allow_list": [],
		"scan_result": {"max_severity": "MEDIUM", "total_findings": 1, "findings": [
			{"severity": "MEDIUM", "title": "issue", "scanner": "test"},
		]},
	}
		with data.config as {"allow_list_bypass_scan": false, "scan_on_install": true, "policy_name": "strict"}
		with data.actions as {"MEDIUM": {"runtime": "block", "file": "quarantine", "install": "block"}}
		with data.scanner_overrides as {}
		with data.severity_ranking as {"MEDIUM": 3, "LOW": 2, "INFO": 1}

	result.verdict == "rejected"
}

# --- Permissive policy: HIGH triggers warning, not reject ---

test_permissive_high_warning if {
	result := admission with input as {
		"target_type": "skill",
		"target_name": "high-skill",
		"path": "/tmp/high",
		"block_list": [],
		"allow_list": [],
		"scan_result": {"max_severity": "HIGH", "total_findings": 1, "findings": [
			{"severity": "HIGH", "title": "issue", "scanner": "test"},
		]},
	}
		with data.config as {"allow_list_bypass_scan": true, "scan_on_install": true, "policy_name": "permissive"}
		with data.actions as {"HIGH": {"runtime": "allow", "file": "none", "install": "none"}}
		with data.scanner_overrides as {}
		with data.severity_ranking as {"HIGH": 4, "MEDIUM": 3, "LOW": 2, "INFO": 1}

	result.verdict == "warning"
}

# --- Plugin target type ---

test_plugin_blocked if {
	result := admission with input as {
		"target_type": "plugin",
		"target_name": "evil-plugin",
		"path": "/tmp/evil-plugin",
		"block_list": [{"target_type": "plugin", "target_name": "evil-plugin", "reason": "malicious"}],
		"allow_list": [],
	}
		with data.config as {"allow_list_bypass_scan": true, "scan_on_install": true}
		with data.actions as {}
		with data.scanner_overrides as {}
		with data.severity_ranking as {}

	result.verdict == "blocked"
}

test_plugin_allowed if {
	result := admission with input as {
		"target_type": "plugin",
		"target_name": "trusted-plugin",
		"path": "/tmp/trusted-plugin",
		"block_list": [],
		"allow_list": [{"target_type": "plugin", "target_name": "trusted-plugin", "reason": "vendor"}],
	}
		with data.config as {"allow_list_bypass_scan": true, "scan_on_install": true}
		with data.actions as {}
		with data.scanner_overrides as {}
		with data.severity_ranking as {}

	result.verdict == "allowed"
}

test_plugin_rejected_critical if {
	result := admission with input as {
		"target_type": "plugin",
		"target_name": "bad-plugin",
		"path": "/tmp/bad-plugin",
		"block_list": [],
		"allow_list": [],
		"scan_result": {"max_severity": "CRITICAL", "total_findings": 1, "findings": [
			{"severity": "CRITICAL", "title": "credential theft", "scanner": "plugin-scanner"},
		]},
	}
		with data.config as {"allow_list_bypass_scan": true, "scan_on_install": true}
		with data.actions as {"CRITICAL": {"runtime": "block", "file": "quarantine", "install": "block"}}
		with data.scanner_overrides as {}
		with data.severity_ranking as {"CRITICAL": 5, "HIGH": 4, "MEDIUM": 3}

	result.verdict == "rejected"
	result.file_action == "quarantine"
	result.install_action == "block"
}

test_plugin_clean_scan if {
	result := admission with input as {
		"target_type": "plugin",
		"target_name": "safe-plugin",
		"path": "/tmp/safe-plugin",
		"block_list": [],
		"allow_list": [],
		"scan_result": {"max_severity": "INFO", "total_findings": 0, "findings": []},
	}
		with data.config as {"allow_list_bypass_scan": true, "scan_on_install": true}
		with data.actions as {"INFO": {"runtime": "allow", "file": "none", "install": "none"}}
		with data.scanner_overrides as {}
		with data.severity_ranking as {"INFO": 1}

	result.verdict == "clean"
}

test_plugin_warning_medium if {
	result := admission with input as {
		"target_type": "plugin",
		"target_name": "med-plugin",
		"path": "/tmp/med-plugin",
		"block_list": [],
		"allow_list": [],
		"scan_result": {"max_severity": "MEDIUM", "total_findings": 1, "findings": [
			{"severity": "MEDIUM", "title": "minor perm", "scanner": "plugin-scanner"},
		]},
	}
		with data.config as {"allow_list_bypass_scan": true, "scan_on_install": true}
		with data.actions as {
			"CRITICAL": {"runtime": "block", "file": "quarantine", "install": "block"},
			"HIGH": {"runtime": "block", "file": "quarantine", "install": "block"},
			"MEDIUM": {"runtime": "allow", "file": "none", "install": "none"},
		}
		with data.scanner_overrides as {}
		with data.severity_ranking as {"CRITICAL": 5, "HIGH": 4, "MEDIUM": 3}

	result.verdict == "warning"
}

test_plugin_not_cross_matched_with_skill if {
	result := admission with input as {
		"target_type": "plugin",
		"target_name": "my-plugin",
		"path": "/tmp/my-plugin",
		"block_list": [{"target_type": "skill", "target_name": "my-plugin", "reason": "wrong type"}],
		"allow_list": [],
	}
		with data.config as {"allow_list_bypass_scan": true, "scan_on_install": true}
		with data.actions as {}
		with data.scanner_overrides as {}
		with data.severity_ranking as {}

	result.verdict != "blocked"
}

# --- Production data.json integrity tests ---
# These tests use the real data.json loaded by OPA (no `with data.actions as ...`
# overrides) to catch regressions if someone weakens the production policy.

test_production_high_rejects if {
	result := admission with input as {
		"target_type": "skill",
		"target_name": "exploit-skill",
		"path": "/tmp/exploit",
		"block_list": [],
		"allow_list": [],
		"scan_result": {"max_severity": "HIGH", "total_findings": 1, "findings": [
			{"severity": "HIGH", "title": "RCE", "scanner": "skill-scanner"},
		]},
	}

	result.verdict == "rejected"
	result.file_action == "quarantine"
}

test_production_critical_rejects if {
	result := admission with input as {
		"target_type": "mcp",
		"target_name": "evil-mcp",
		"path": "/tmp/evil-mcp",
		"block_list": [],
		"allow_list": [],
		"scan_result": {"max_severity": "CRITICAL", "total_findings": 1, "findings": [
			{"severity": "CRITICAL", "title": "credential exfil", "scanner": "mcp-scanner"},
		]},
	}

	result.verdict == "rejected"
	result.file_action == "quarantine"
}

test_production_medium_warns_not_rejects if {
	result := admission with input as {
		"target_type": "skill",
		"target_name": "okish-skill",
		"path": "/tmp/ok",
		"block_list": [],
		"allow_list": [],
		"scan_result": {"max_severity": "MEDIUM", "total_findings": 1, "findings": [
			{"severity": "MEDIUM", "title": "minor perm", "scanner": "test"},
		]},
	}

	result.verdict == "warning"
}

test_production_policy_name_is_default if {
	data.config.policy_name == "default"
}

test_production_sandbox_update_policy_disabled_by_default if {
	data.sandbox.update_policy == false
}

test_production_max_enforcement_delay_is_two if {
	data.config.max_enforcement_delay_seconds == 2
}

test_production_audit_retention_at_least_90 if {
	data.audit.retention_days >= 90
}

test_production_first_party_plugin_allowed if {
	result := admission with input as {
		"target_type": "plugin",
		"target_name": "defenseclaw",
		"path": "/home/user/.openclaw/extensions/defenseclaw",
		"block_list": [],
		"allow_list": [],
	}

	result.verdict == "allowed"
}

test_production_first_party_skill_allowed if {
	result := admission with input as {
		"target_type": "skill",
		"target_name": "codeguard",
		"path": "/home/user/.openclaw/workspace/skills/codeguard",
		"block_list": [],
		"allow_list": [],
	}

	result.verdict == "allowed"
}

test_first_party_allow_list_bypass_scan if {
	result := admission with input as {
		"target_type": "plugin",
		"target_name": "defenseclaw",
		"path": "/tmp/defenseclaw",
		"block_list": [],
		"allow_list": [],
		"scan_result": {"max_severity": "MEDIUM", "total_findings": 2, "findings": []},
	}
		with data.config as {"allow_list_bypass_scan": true, "scan_on_install": true}
		with data.first_party_allow_list as [
			{"target_type": "plugin", "target_name": "defenseclaw", "reason": "first-party"},
		]
		with data.actions as {"MEDIUM": {"runtime": "allow", "file": "none", "install": "none"}}
		with data.scanner_overrides as {}
		with data.severity_ranking as {"MEDIUM": 3}

	result.verdict == "allowed"
}

test_first_party_block_list_takes_precedence if {
	result := admission with input as {
		"target_type": "plugin",
		"target_name": "defenseclaw",
		"path": "/tmp/defenseclaw",
		"block_list": [{"target_type": "plugin", "target_name": "defenseclaw", "reason": "manual block"}],
		"allow_list": [],
	}
		with data.config as {"allow_list_bypass_scan": true, "scan_on_install": true}
		with data.first_party_allow_list as [
			{"target_type": "plugin", "target_name": "defenseclaw", "reason": "first-party"},
		]
		with data.actions as {}
		with data.scanner_overrides as {}
		with data.severity_ranking as {}

	result.verdict == "blocked"
}

test_first_party_bad_provenance_falls_through if {
	result := admission with input as {
		"target_type": "plugin",
		"target_name": "defenseclaw",
		"path": "/tmp/unrelated/plugin",
		"block_list": [],
		"allow_list": [],
	}
		with data.config as {"allow_list_bypass_scan": true, "scan_on_install": true}
		with data.first_party_allow_list as [
			{"target_type": "plugin", "target_name": "defenseclaw", "reason": "first-party", "source_path_contains": ["defenseclaw", ".defenseclaw"]},
		]
		with data.actions as {}
		with data.scanner_overrides as {}
		with data.severity_ranking as {}

	result.verdict == "scan"
}

test_first_party_temp_dir_does_not_match if {
	result := admission with input as {
		"target_type": "plugin",
		"target_name": "defenseclaw",
		"path": "/tmp/dclaw-plugin-fetch-abc123/defenseclaw",
		"block_list": [],
		"allow_list": [],
	}

	result.verdict == "scan"
}

test_first_party_no_constraints_allows if {
	result := admission with input as {
		"target_type": "plugin",
		"target_name": "defenseclaw",
		"path": "/tmp/anything",
		"block_list": [],
		"allow_list": [],
	}
		with data.config as {"allow_list_bypass_scan": true, "scan_on_install": true}
		with data.first_party_allow_list as [
			{"target_type": "plugin", "target_name": "defenseclaw", "reason": "first-party"},
		]
		with data.actions as {}
		with data.scanner_overrides as {}
		with data.severity_ranking as {}

	result.verdict == "allowed"
}

test_production_plugin_medium_warns_not_rejects if {
	result := admission with input as {
		"target_type": "plugin",
		"target_name": "some-plugin",
		"path": "/tmp/some-plugin",
		"block_list": [],
		"allow_list": [],
		"scan_result": {"max_severity": "MEDIUM", "total_findings": 1, "findings": [
			{"severity": "MEDIUM", "title": "minor issue", "scanner": "plugin-scanner"},
		]},
	}

	result.verdict == "warning"
}

# --- install_action and file_action output ---

test_install_action_block_on_critical if {
	result := admission with input as {
		"target_type": "skill",
		"target_name": "bad-skill",
		"path": "/tmp/bad",
		"block_list": [],
		"allow_list": [],
		"scan_result": {"max_severity": "CRITICAL", "total_findings": 1, "findings": []},
	}
		with data.config as {"allow_list_bypass_scan": false, "scan_on_install": true}
		with data.actions as {"CRITICAL": {"runtime": "block", "file": "quarantine", "install": "block"}}
		with data.scanner_overrides as {}
		with data.severity_ranking as {"CRITICAL": 5}

	result.install_action == "block"
	result.file_action == "quarantine"
}

test_install_block_alone_triggers_reject if {
	result := admission with input as {
		"target_type": "skill",
		"target_name": "partial-block-skill",
		"path": "/tmp/partial",
		"block_list": [],
		"allow_list": [],
		"scan_result": {"max_severity": "HIGH", "total_findings": 1, "findings": []},
	}
		with data.config as {"allow_list_bypass_scan": false, "scan_on_install": true}
		with data.actions as {"HIGH": {"runtime": "allow", "file": "none", "install": "block"}}
		with data.scanner_overrides as {}
		with data.severity_ranking as {"HIGH": 4}

	result.verdict == "rejected"
	result.install_action == "block"
}

test_install_action_none_on_warning if {
	result := admission with input as {
		"target_type": "skill",
		"target_name": "ok-skill",
		"path": "/tmp/ok",
		"block_list": [],
		"allow_list": [],
		"scan_result": {"max_severity": "LOW", "total_findings": 1, "findings": []},
	}
		with data.config as {"allow_list_bypass_scan": false, "scan_on_install": true}
		with data.actions as {"LOW": {"runtime": "allow", "file": "none", "install": "none"}}
		with data.scanner_overrides as {}
		with data.severity_ranking as {"LOW": 2}

	result.install_action == "none"
	result.file_action == "none"
}

test_lowercase_severity_still_rejects if {
	result := admission with input as {
		"target_type": "skill",
		"target_name": "lc-skill",
		"path": "/tmp/lc",
		"block_list": [],
		"allow_list": [],
		"scan_result": {"max_severity": "critical", "total_findings": 1, "findings": []},
	}
		with data.config as {"allow_list_bypass_scan": false, "scan_on_install": true}
		with data.actions as {"CRITICAL": {"runtime": "block", "file": "quarantine", "install": "block"}}
		with data.scanner_overrides as {}
		with data.first_party_allow_list as []

	result.verdict == "rejected"
	result.runtime_action == "block"
	result.file_action == "quarantine"
	result.install_action == "block"
}

test_mixed_case_severity_still_rejects if {
	result := admission with input as {
		"target_type": "skill",
		"target_name": "mc-skill",
		"path": "/tmp/mc",
		"block_list": [],
		"allow_list": [],
		"scan_result": {"max_severity": "High", "total_findings": 1, "findings": []},
	}
		with data.config as {"allow_list_bypass_scan": false, "scan_on_install": true}
		with data.actions as {"HIGH": {"runtime": "block", "file": "quarantine", "install": "block"}}
		with data.scanner_overrides as {}
		with data.first_party_allow_list as []

	result.verdict == "rejected"
}

test_high_severity_has_runtime_block if {
	result := admission with input as {
		"target_type": "skill",
		"target_name": "risky-skill",
		"path": "/tmp/risky",
		"block_list": [],
		"allow_list": [],
		"scan_result": {"max_severity": "HIGH", "total_findings": 3, "findings": []},
	}
		with data.config as {"allow_list_bypass_scan": false, "scan_on_install": true}
		with data.actions as {"HIGH": {"runtime": "block", "file": "quarantine", "install": "block"}}
		with data.scanner_overrides as {}
		with data.first_party_allow_list as []

	result.runtime_action == "block"
}

test_install_only_block_has_runtime_allow if {
	result := admission with input as {
		"target_type": "skill",
		"target_name": "install-only-skill",
		"path": "/tmp/install-only",
		"block_list": [],
		"allow_list": [],
		"scan_result": {"max_severity": "MEDIUM", "total_findings": 1, "findings": []},
	}
		with data.config as {"allow_list_bypass_scan": false, "scan_on_install": true}
		with data.actions as {"MEDIUM": {"runtime": "allow", "file": "none", "install": "block"}}
		with data.scanner_overrides as {}
		with data.first_party_allow_list as []

	result.runtime_action == "allow"
	result.install_action == "block"
	result.verdict == "rejected"
}

test_no_scan_has_runtime_allow if {
	result := admission with input as {
		"target_type": "skill",
		"target_name": "clean-skill",
		"path": "/tmp/clean",
		"block_list": [],
		"allow_list": [],
	}
		with data.config as {"allow_list_bypass_scan": false, "scan_on_install": true}
		with data.actions as {}
		with data.scanner_overrides as {}
		with data.first_party_allow_list as []

	result.runtime_action == "allow"
}

test_no_scan_result_actions_default_none if {
	result := admission with input as {
		"target_type": "skill",
		"target_name": "new-skill",
		"path": "/tmp/new",
		"block_list": [],
		"allow_list": [],
	}
		with data.config as {"allow_list_bypass_scan": false, "scan_on_install": true}
		with data.actions as {}
		with data.scanner_overrides as {}
		with data.severity_ranking as {}

	result.file_action == "none"
	result.install_action == "none"
}

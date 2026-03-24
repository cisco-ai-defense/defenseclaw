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
		with data.config as {"allow_list_bypass_scan": true}
		with data.actions as {}
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
		with data.config as {"allow_list_bypass_scan": true}
		with data.actions as {}
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
		with data.config as {"allow_list_bypass_scan": true}
		with data.actions as {}
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
		with data.config as {"allow_list_bypass_scan": true}
		with data.actions as {}
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
		with data.config as {"allow_list_bypass_scan": false}
		with data.actions as {}
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
		with data.config as {"allow_list_bypass_scan": true}
		with data.actions as {"INFO": {"runtime": "allow", "file": "none"}}
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
		with data.config as {"allow_list_bypass_scan": true}
		with data.actions as {
			"HIGH": {"runtime": "block", "file": "quarantine"},
			"MEDIUM": {"runtime": "allow", "file": "none"},
		}
		with data.severity_ranking as {"HIGH": 4, "MEDIUM": 3, "LOW": 2, "INFO": 1}

	result.verdict == "rejected"
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
		with data.config as {"allow_list_bypass_scan": true}
		with data.actions as {
			"CRITICAL": {"runtime": "block", "file": "quarantine"},
			"HIGH": {"runtime": "block", "file": "quarantine"},
			"MEDIUM": {"runtime": "allow", "file": "none"},
		}
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
		with data.config as {"allow_list_bypass_scan": true}
		with data.actions as {}
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
		with data.config as {"allow_list_bypass_scan": true}
		with data.actions as {}
		with data.severity_ranking as {}

	result.verdict == "blocked"
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
		with data.config as {"allow_list_bypass_scan": false, "policy_name": "strict"}
		with data.actions as {"MEDIUM": {"runtime": "block", "file": "quarantine"}}
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
		with data.config as {"allow_list_bypass_scan": true, "policy_name": "permissive"}
		with data.actions as {"HIGH": {"runtime": "allow", "file": "none"}}
		with data.severity_ranking as {"HIGH": 4, "MEDIUM": 3, "LOW": 2, "INFO": 1}

	result.verdict == "warning"
}

package defenseclaw.skill_actions_test

import rego.v1

import data.defenseclaw.skill_actions

test_critical_blocks if {
	result := skill_actions with input as {"severity": "CRITICAL"}
		with data.actions as {
			"CRITICAL": {"runtime": "block", "file": "quarantine"},
		}

	result.runtime_action == "block"
	result.file_action == "quarantine"
	result.should_block == true
	result.should_quarantine == true
}

test_medium_allows if {
	result := skill_actions with input as {"severity": "MEDIUM"}
		with data.actions as {
			"MEDIUM": {"runtime": "allow", "file": "none"},
		}

	result.runtime_action == "allow"
	result.file_action == "none"
	not result.should_block
	not result.should_quarantine
}

test_high_blocks_default if {
	result := skill_actions with input as {"severity": "HIGH"}
		with data.actions as {
			"HIGH": {"runtime": "block", "file": "quarantine"},
		}

	result.runtime_action == "block"
	result.should_block == true
}

test_unknown_severity_defaults if {
	result := skill_actions with input as {"severity": "UNKNOWN"}
		with data.actions as {}

	result.runtime_action == "allow"
	result.file_action == "none"
}

test_info_allows if {
	result := skill_actions with input as {"severity": "INFO"}
		with data.actions as {
			"INFO": {"runtime": "allow", "file": "none"},
		}

	result.runtime_action == "allow"
	result.file_action == "none"
}

test_permissive_high_allows if {
	result := skill_actions with input as {"severity": "HIGH"}
		with data.actions as {
			"HIGH": {"runtime": "allow", "file": "none"},
		}

	result.runtime_action == "allow"
	not result.should_block
}

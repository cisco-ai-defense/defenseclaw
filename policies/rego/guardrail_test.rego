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

package defenseclaw.guardrail_test

import data.defenseclaw.guardrail
import rego.v1

_guardrail_data := {
	"severity_rank": {"NONE": 0, "LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4},
	"block_threshold": 3,
	"alert_threshold": 2,
	"cisco_trust_level": "full",
}

test_allow_when_no_findings if {
	result := guardrail with input as {
		"direction": "prompt",
		"model": "test-model",
		"mode": "action",
		"scanner_mode": "local",
		"local_result": {"action": "allow", "severity": "NONE", "findings": [], "reason": ""},
		"cisco_result": null,
		"content_length": 100,
	}
		with data.guardrail as _guardrail_data

	result.action == "allow"
	result.severity == "NONE"
}

test_block_on_high_local if {
	result := guardrail with input as {
		"direction": "prompt",
		"model": "test-model",
		"mode": "action",
		"scanner_mode": "local",
		"local_result": {"action": "block", "severity": "HIGH", "findings": ["ignore previous"], "reason": "matched: ignore previous"},
		"cisco_result": null,
		"content_length": 200,
	}
		with data.guardrail as _guardrail_data

	result.action == "block"
	result.severity == "HIGH"
}

test_alert_on_medium_local if {
	result := guardrail with input as {
		"direction": "prompt",
		"model": "test-model",
		"mode": "action",
		"scanner_mode": "local",
		"local_result": {"action": "alert", "severity": "MEDIUM", "findings": ["sk-"], "reason": "matched: sk-"},
		"cisco_result": null,
		"content_length": 150,
	}
		with data.guardrail as _guardrail_data

	result.action == "alert"
	result.severity == "MEDIUM"
}

test_observe_mode_never_blocks if {
	result := guardrail with input as {
		"direction": "prompt",
		"model": "test-model",
		"mode": "observe",
		"scanner_mode": "local",
		"local_result": {"action": "block", "severity": "HIGH", "findings": ["jailbreak"], "reason": "matched: jailbreak"},
		"cisco_result": null,
		"content_length": 200,
	}
		with data.guardrail as _guardrail_data

	result.action == "alert"
	result.severity == "HIGH"
}

test_observe_mode_medium_still_alerts if {
	result := guardrail with input as {
		"direction": "prompt",
		"model": "test-model",
		"mode": "observe",
		"scanner_mode": "local",
		"local_result": {"action": "alert", "severity": "MEDIUM", "findings": ["sk-"], "reason": "matched: sk-"},
		"cisco_result": null,
		"content_length": 150,
	}

	result.action == "alert"
	result.severity == "MEDIUM"
}

test_observe_mode_critical_alerts_not_blocks if {
	result := guardrail with input as {
		"direction": "prompt",
		"model": "test-model",
		"mode": "observe",
		"scanner_mode": "local",
		"local_result": {"action": "block", "severity": "CRITICAL", "findings": ["jailbreak"], "reason": "matched: jailbreak"},
		"cisco_result": null,
		"content_length": 200,
	}

	result.action == "alert"
	result.severity == "CRITICAL"
}

test_observe_mode_clean_stays_allow if {
	result := guardrail with input as {
		"direction": "prompt",
		"model": "test-model",
		"mode": "observe",
		"scanner_mode": "local",
		"local_result": {"action": "allow", "severity": "NONE", "findings": [], "reason": ""},
		"cisco_result": null,
		"content_length": 100,
	}

	result.action == "allow"
	result.severity == "NONE"
}

test_cisco_only_block if {
	result := guardrail with input as {
		"direction": "prompt",
		"model": "test-model",
		"mode": "action",
		"scanner_mode": "remote",
		"local_result": null,
		"cisco_result": {"action": "block", "severity": "HIGH", "findings": ["Prompt Injection"], "reason": "cisco: Prompt Injection"},
		"content_length": 300,
	}
		with data.guardrail as _guardrail_data

	result.action == "block"
	result.severity == "HIGH"
}

test_both_mode_cisco_escalates if {
	result := guardrail with input as {
		"direction": "prompt",
		"model": "test-model",
		"mode": "action",
		"scanner_mode": "both",
		"local_result": {"action": "allow", "severity": "NONE", "findings": [], "reason": ""},
		"cisco_result": {"action": "block", "severity": "HIGH", "findings": ["SECURITY_VIOLATION"], "reason": "cisco: SECURITY_VIOLATION"},
		"content_length": 400,
	}
		with data.guardrail as _guardrail_data

	result.action == "block"
	result.severity == "HIGH"
}

test_both_mode_combined_reasons if {
	result := guardrail with input as {
		"direction": "prompt",
		"model": "test-model",
		"mode": "action",
		"scanner_mode": "both",
		"local_result": {"action": "alert", "severity": "MEDIUM", "findings": ["sk-"], "reason": "matched: sk-"},
		"cisco_result": {"action": "block", "severity": "HIGH", "findings": ["Data Leak"], "reason": "cisco: Data Leak"},
		"content_length": 500,
	}
		with data.guardrail as _guardrail_data

	result.severity == "HIGH"
	result.action == "block"
	contains(result.reason, "matched: sk-")
	contains(result.reason, "cisco: Data Leak")
}

test_advisory_cisco_downgrades_to_alert if {
	result := guardrail with input as {
		"direction": "prompt",
		"model": "test-model",
		"mode": "action",
		"scanner_mode": "both",
		"local_result": {"action": "allow", "severity": "NONE", "findings": [], "reason": ""},
		"cisco_result": {"action": "block", "severity": "HIGH", "findings": ["Prompt Injection"], "reason": "cisco: Prompt Injection"},
		"content_length": 300,
	}
		with data.guardrail as object.union(_guardrail_data, {"cisco_trust_level": "advisory"})

	result.action == "alert"
}

test_scanner_sources_populated if {
	result := guardrail with input as {
		"direction": "prompt",
		"model": "test-model",
		"mode": "action",
		"scanner_mode": "both",
		"local_result": {"action": "alert", "severity": "MEDIUM", "findings": ["sk-"], "reason": "matched: sk-"},
		"cisco_result": {"action": "block", "severity": "HIGH", "findings": ["Prompt Injection"], "reason": "cisco: Prompt Injection"},
		"content_length": 500,
	}
		with data.guardrail as _guardrail_data

	"local-pattern" in result.scanner_sources
	"ai-defense" in result.scanner_sources
	"opa-policy" in result.scanner_sources
}

test_cisco_trust_none_ignores_cisco if {
	result := guardrail with input as {
		"direction": "prompt",
		"model": "test-model",
		"mode": "action",
		"scanner_mode": "both",
		"local_result": {"action": "allow", "severity": "NONE", "findings": [], "reason": ""},
		"cisco_result": {"action": "block", "severity": "HIGH", "findings": ["Prompt Injection"], "reason": "cisco: Prompt Injection"},
		"content_length": 300,
	}
		with data.guardrail as object.union(_guardrail_data, {"cisco_trust_level": "none"})

	result.action == "allow"
	result.severity == "NONE"
}

# ---------------------------------------------------------------------------
# Taint escalation tests
#
# These pin the contract between the Go-side TaintTracker (which produces
# input.taint_context) and the Rego policy (which decides whether and how
# much to escalate). The fixtures below cover:
#   - Strong path (consumer references a tainted file)
#   - Weak path (consumer in a tainted session, no file evidence)
#   - Tier knob differentiation (default vs strict vs permissive)
#   - Observe mode short-circuiting
#   - Network-exclusion suppressing weak escalation
#   - Confidence floor suppressing weak escalation
#   - Severity cap at CRITICAL
# ---------------------------------------------------------------------------

_taint_data := {
	"severity_rank": {"NONE": 0, "LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4},
	"block_threshold": 3,
	"alert_threshold": 2,
	"cisco_trust_level": "full",
	"taint": {
		"default": {
			"mode": "action",
			"escalation_steps_strong": 2,
			"escalation_steps_weak": 1,
			"require_taint_source": true,
			"min_consumer_confidence": 0.80,
		},
		"strict": {
			"mode": "action",
			"escalation_steps_strong": 2,
			"escalation_steps_weak": 1,
			"require_taint_source": false,
			"min_consumer_confidence": 0.50,
		},
		"permissive": {
			"mode": "observe",
			"escalation_steps_strong": 0,
			"escalation_steps_weak": 0,
			"require_taint_source": true,
			"min_consumer_confidence": 0.90,
		},
	},
}

test_taint_strong_escalates_medium_to_critical if {
	# Base MEDIUM (rank 2) + strong escalation (steps=2) ⇒ CRITICAL (rank 4).
	result := guardrail with input as {
		"direction": "prompt",
		"model": "test",
		"mode": "action",
		"scanner_mode": "local",
		"local_result": {"action": "alert", "severity": "MEDIUM", "findings": ["CMD-CURL-UPLOAD"], "reason": "curl upload"},
		"cisco_result": null,
		"content_length": 100,
		"policy_tier": "default",
		"taint_context": {
			"has_strong_consumer": true,
			"has_weak_consumer": false,
			"has_taint_source_in_session": true,
			"tainted_files_referenced": ["/tmp/stolen"],
			"source_findings": ["CHAIN-CRED-FILE-READ"],
			"max_consumer_confidence": 0.85,
			"network_dest_excluded": false,
			"events_since_source": 2,
		},
	}
		with data.guardrail as _taint_data

	result.severity == "CRITICAL"
	result.action == "block"
	result.taint_escalation.path == "strong"
	result.taint_escalation.steps == 2
	"taint-tracker" in result.scanner_sources
}

test_taint_weak_escalates_medium_to_high_default if {
	result := guardrail with input as {
		"direction": "prompt",
		"model": "test",
		"mode": "action",
		"scanner_mode": "local",
		"local_result": {"action": "alert", "severity": "MEDIUM", "findings": ["CMD-CURL-UPLOAD"], "reason": "curl upload"},
		"cisco_result": null,
		"content_length": 100,
		"policy_tier": "default",
		"taint_context": {
			"has_strong_consumer": false,
			"has_weak_consumer": true,
			"has_taint_source_in_session": true,
			"tainted_files_referenced": [],
			"source_findings": ["CHAIN-CRED-FILE-READ"],
			"max_consumer_confidence": 0.85,
			"network_dest_excluded": false,
			"events_since_source": 3,
		},
	}
		with data.guardrail as _taint_data

	result.severity == "HIGH"
	result.action == "block"
	result.taint_escalation.path == "weak"
	result.taint_escalation.steps == 1
}

test_taint_weak_blocked_by_low_confidence if {
	# Base MEDIUM, weak path, but consumer confidence below the floor.
	# No escalation; verdict stays at MEDIUM/alert.
	result := guardrail with input as {
		"direction": "prompt",
		"model": "test",
		"mode": "action",
		"scanner_mode": "local",
		"local_result": {"action": "alert", "severity": "MEDIUM", "findings": ["X"], "reason": "x"},
		"cisco_result": null,
		"content_length": 100,
		"policy_tier": "default",
		"taint_context": {
			"has_strong_consumer": false,
			"has_weak_consumer": true,
			"has_taint_source_in_session": true,
			"tainted_files_referenced": [],
			"source_findings": ["CHAIN-CRED"],
			"max_consumer_confidence": 0.50,
			"network_dest_excluded": false,
			"events_since_source": 1,
		},
	}
		with data.guardrail as _taint_data

	result.severity == "MEDIUM"
	result.action == "alert"
	not result.taint_escalation
}

test_taint_weak_blocked_by_excluded_destination if {
	result := guardrail with input as {
		"direction": "prompt",
		"model": "test",
		"mode": "action",
		"scanner_mode": "local",
		"local_result": {"action": "alert", "severity": "MEDIUM", "findings": ["CMD-CURL-UPLOAD"], "reason": "curl upload"},
		"cisco_result": null,
		"content_length": 100,
		"policy_tier": "default",
		"taint_context": {
			"has_strong_consumer": false,
			"has_weak_consumer": true,
			"has_taint_source_in_session": true,
			"tainted_files_referenced": [],
			"source_findings": ["CHAIN-CRED"],
			"max_consumer_confidence": 0.85,
			"network_dest_excluded": true,
			"events_since_source": 1,
		},
	}
		with data.guardrail as _taint_data

	result.severity == "MEDIUM"
	result.action == "alert"
	not result.taint_escalation
}

test_taint_strict_lower_confidence_floor if {
	# Strict drops min_consumer_confidence to 0.5 — same input that
	# default rejects now triggers weak escalation.
	result := guardrail with input as {
		"direction": "prompt",
		"model": "test",
		"mode": "action",
		"scanner_mode": "local",
		"local_result": {"action": "alert", "severity": "MEDIUM", "findings": ["X"], "reason": "x"},
		"cisco_result": null,
		"content_length": 100,
		"policy_tier": "strict",
		"taint_context": {
			"has_strong_consumer": false,
			"has_weak_consumer": true,
			"has_taint_source_in_session": true,
			"tainted_files_referenced": [],
			"source_findings": ["CHAIN-CRED"],
			"max_consumer_confidence": 0.55,
			"network_dest_excluded": false,
			"events_since_source": 1,
		},
	}
		with data.guardrail as _taint_data

	result.severity == "HIGH"
	result.action == "block"
}

test_taint_permissive_observe_mode_no_escalation if {
	# Permissive tier sets mode=observe ⇒ taint_steps stays 0 even with
	# unambiguous strong-path evidence.
	result := guardrail with input as {
		"direction": "prompt",
		"model": "test",
		"mode": "action",
		"scanner_mode": "local",
		"local_result": {"action": "alert", "severity": "MEDIUM", "findings": ["CMD-CURL-UPLOAD"], "reason": "curl upload"},
		"cisco_result": null,
		"content_length": 100,
		"policy_tier": "permissive",
		"taint_context": {
			"has_strong_consumer": true,
			"has_weak_consumer": false,
			"has_taint_source_in_session": true,
			"tainted_files_referenced": ["/tmp/stolen"],
			"source_findings": ["CHAIN-CRED-FILE-READ"],
			"max_consumer_confidence": 0.95,
			"network_dest_excluded": false,
			"events_since_source": 1,
		},
	}
		with data.guardrail as _taint_data

	result.severity == "MEDIUM"
	result.action == "alert"
	not result.taint_escalation
}

test_taint_no_taint_source_blocks_weak_in_default if {
	# require_taint_source=true (default tier) ⇒ weak path needs a live
	# session source flag. Without it, no escalation.
	result := guardrail with input as {
		"direction": "prompt",
		"model": "test",
		"mode": "action",
		"scanner_mode": "local",
		"local_result": {"action": "alert", "severity": "MEDIUM", "findings": ["X"], "reason": "x"},
		"cisco_result": null,
		"content_length": 100,
		"policy_tier": "default",
		"taint_context": {
			"has_strong_consumer": false,
			"has_weak_consumer": true,
			"has_taint_source_in_session": false,
			"tainted_files_referenced": [],
			"source_findings": [],
			"max_consumer_confidence": 0.85,
			"network_dest_excluded": false,
			"events_since_source": 0,
		},
	}
		with data.guardrail as _taint_data

	result.severity == "MEDIUM"
	result.action == "alert"
	not result.taint_escalation
}

test_taint_strict_no_session_source_still_escalates_weak if {
	# strict tier sets require_taint_source=false ⇒ weak escalation
	# fires on consumer alone if confidence high enough.
	result := guardrail with input as {
		"direction": "prompt",
		"model": "test",
		"mode": "action",
		"scanner_mode": "local",
		"local_result": {"action": "alert", "severity": "MEDIUM", "findings": ["X"], "reason": "x"},
		"cisco_result": null,
		"content_length": 100,
		"policy_tier": "strict",
		"taint_context": {
			"has_strong_consumer": false,
			"has_weak_consumer": true,
			"has_taint_source_in_session": false,
			"tainted_files_referenced": [],
			"source_findings": [],
			"max_consumer_confidence": 0.85,
			"network_dest_excluded": false,
			"events_since_source": 0,
		},
	}
		with data.guardrail as _taint_data

	result.severity == "HIGH"
	result.action == "block"
}

test_taint_severity_capped_at_critical if {
	# Base HIGH (3) + strong steps=2 would be 5; must cap at CRITICAL (4).
	result := guardrail with input as {
		"direction": "prompt",
		"model": "test",
		"mode": "action",
		"scanner_mode": "local",
		"local_result": {"action": "block", "severity": "HIGH", "findings": ["X"], "reason": "x"},
		"cisco_result": null,
		"content_length": 100,
		"policy_tier": "default",
		"taint_context": {
			"has_strong_consumer": true,
			"has_weak_consumer": false,
			"has_taint_source_in_session": true,
			"tainted_files_referenced": ["/tmp/stolen"],
			"source_findings": ["CHAIN-CRED"],
			"max_consumer_confidence": 0.95,
			"network_dest_excluded": false,
			"events_since_source": 1,
		},
	}
		with data.guardrail as _taint_data

	result.severity == "CRITICAL"
}

test_taint_unknown_tier_falls_back_to_default if {
	result := guardrail with input as {
		"direction": "prompt",
		"model": "test",
		"mode": "action",
		"scanner_mode": "local",
		"local_result": {"action": "alert", "severity": "MEDIUM", "findings": ["X"], "reason": "x"},
		"cisco_result": null,
		"content_length": 100,
		"policy_tier": "nonexistent",
		"taint_context": {
			"has_strong_consumer": true,
			"has_weak_consumer": false,
			"has_taint_source_in_session": true,
			"tainted_files_referenced": ["/tmp/x"],
			"source_findings": ["CHAIN-CRED"],
			"max_consumer_confidence": 0.95,
			"network_dest_excluded": false,
			"events_since_source": 1,
		},
	}
		with data.guardrail as _taint_data

	# Default tier escalation_steps_strong=2 ⇒ MEDIUM+2=CRITICAL.
	result.severity == "CRITICAL"
	result.taint_escalation.tier == "default"
}

test_taint_observe_mode_overrides_block_action if {
	# Even with strong escalation, mode=observe must keep action=alert.
	result := guardrail with input as {
		"direction": "prompt",
		"model": "test",
		"mode": "observe",
		"scanner_mode": "local",
		"local_result": {"action": "alert", "severity": "MEDIUM", "findings": ["X"], "reason": "x"},
		"cisco_result": null,
		"content_length": 100,
		"policy_tier": "default",
		"taint_context": {
			"has_strong_consumer": true,
			"has_weak_consumer": false,
			"has_taint_source_in_session": true,
			"tainted_files_referenced": ["/tmp/x"],
			"source_findings": ["CHAIN-CRED"],
			"max_consumer_confidence": 0.95,
			"network_dest_excluded": false,
			"events_since_source": 1,
		},
	}
		with data.guardrail as _taint_data

	result.severity == "CRITICAL"
	result.action == "alert"
}

test_taint_no_context_no_escalation if {
	# Backward compatibility: callers that don't provide taint_context
	# get the original behavior.
	result := guardrail with input as {
		"direction": "prompt",
		"model": "test",
		"mode": "action",
		"scanner_mode": "local",
		"local_result": {"action": "alert", "severity": "MEDIUM", "findings": ["X"], "reason": "x"},
		"cisco_result": null,
		"content_length": 100,
	}
		with data.guardrail as _taint_data

	result.severity == "MEDIUM"
	result.action == "alert"
	not result.taint_escalation
}
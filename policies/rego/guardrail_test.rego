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

_thresholds := {"block": 4, "alert": 2, "cisco_trust_level": "full"}

test_allow_when_no_findings if {
	result := guardrail with input as {
		"direction": "prompt",
		"model": "test-model",
		"mode": "action",
		"scanner_mode": "local",
		"local_result": {"action": "allow", "severity": "NONE", "findings": [], "reason": ""},
		"cisco_result": null,
		"content_length": 100,
		"thresholds": _thresholds,
	}

	result.action == "allow"
	result.severity == "NONE"
}

test_alert_on_high_local_balanced if {
	result := guardrail with input as {
		"direction": "prompt",
		"model": "test-model",
		"mode": "action",
		"scanner_mode": "local",
		"local_result": {"action": "block", "severity": "HIGH", "findings": ["ignore previous"], "reason": "matched: ignore previous"},
		"cisco_result": null,
		"content_length": 200,
		"thresholds": _thresholds,
	}

	result.action == "alert"
	result.severity == "HIGH"
}

test_block_on_critical_local_balanced if {
	result := guardrail with input as {
		"direction": "prompt",
		"model": "test-model",
		"mode": "action",
		"scanner_mode": "local",
		"local_result": {"action": "block", "severity": "CRITICAL", "findings": ["private key"], "reason": "matched: private key"},
		"cisco_result": null,
		"content_length": 200,
		"thresholds": _thresholds,
	}

	result.action == "block"
	result.severity == "CRITICAL"
}

test_confirm_on_high_when_hilt_enabled if {
	result := guardrail with input as {
		"direction": "prompt",
		"model": "test-model",
		"mode": "action",
		"scanner_mode": "local",
		"local_result": {"action": "block", "severity": "HIGH", "findings": ["ignore previous"], "reason": "matched: ignore previous"},
		"cisco_result": null,
		"content_length": 200,
		"thresholds": _thresholds,
		"hilt": {"enabled": true, "min_severity": "HIGH"},
	}

	result.action == "confirm"
	result.severity == "HIGH"
}

test_strict_blocks_medium_before_hilt if {
	result := guardrail with input as {
		"direction": "prompt",
		"model": "test-model",
		"mode": "action",
		"scanner_mode": "local",
		"local_result": {"action": "alert", "severity": "MEDIUM", "findings": ["sk-"], "reason": "matched: sk-"},
		"cisco_result": null,
		"content_length": 150,
		"thresholds": object.union(_thresholds, {"block": 2, "alert": 1}),
		"hilt": {"enabled": true, "min_severity": "HIGH"},
	}

	result.action == "block"
	result.severity == "MEDIUM"
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
		"thresholds": _thresholds,
	}

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
		"thresholds": _thresholds,
	}

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
		"thresholds": _thresholds,
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
		"thresholds": _thresholds,
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
		"thresholds": _thresholds,
	}

	result.action == "allow"
	result.severity == "NONE"
}

test_cisco_only_high_alerts_balanced if {
	result := guardrail with input as {
		"direction": "prompt",
		"model": "test-model",
		"mode": "action",
		"scanner_mode": "remote",
		"local_result": null,
		"cisco_result": {"action": "block", "severity": "HIGH", "findings": ["Prompt Injection"], "reason": "cisco: Prompt Injection"},
		"content_length": 300,
		"thresholds": _thresholds,
	}

	result.action == "alert"
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
		"thresholds": _thresholds,
	}

	result.action == "alert"
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
		"thresholds": _thresholds,
	}

	result.severity == "HIGH"
	result.action == "alert"
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
		"thresholds": object.union(_thresholds, {"cisco_trust_level": "advisory"}),
	}

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
		"thresholds": _thresholds,
	}

	"local-pattern" in result.scanner_sources
	"ai-defense" in result.scanner_sources
	"opa-policy" in result.scanner_sources
}

# --- input.hilt (config.yaml guardrail.hilt -> Rego) ---

test_input_hilt_enabled_confirms if {
	result := guardrail with input as {
		"direction": "prompt",
		"model": "test-model",
		"mode": "action",
		"scanner_mode": "local",
		"local_result": {"action": "block", "severity": "HIGH", "findings": ["ignore previous"], "reason": "matched: ignore previous"},
		"cisco_result": null,
		"content_length": 200,
		"hilt": {"enabled": true, "min_severity": "HIGH"},
		"thresholds": _thresholds,
	}

	result.action == "confirm"
	result.severity == "HIGH"
}

test_input_hilt_min_severity_critical_skips_high_confirm if {
	# input.hilt.min_severity raises the bar to CRITICAL; a HIGH finding
	# must not trigger `confirm` — it falls through to `alert`.
	result := guardrail with input as {
		"direction": "prompt",
		"model": "test-model",
		"mode": "action",
		"scanner_mode": "local",
		"local_result": {"action": "block", "severity": "HIGH", "findings": ["ignore previous"], "reason": "matched: ignore previous"},
		"cisco_result": null,
		"content_length": 200,
		"hilt": {"enabled": true, "min_severity": "CRITICAL"},
		"thresholds": _thresholds,
	}

	result.action == "alert"
	result.severity == "HIGH"
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
		"thresholds": object.union(_thresholds, {"cisco_trust_level": "none"}),
	}

	result.action == "allow"
	result.severity == "NONE"
}

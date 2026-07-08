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

package defenseclaw.agent_control_guardrail_test

import data.defenseclaw.guardrail
import rego.v1

_local := {
	"severity_rank": {"NONE": 0, "LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4},
	"block_threshold": 4,
	"alert_threshold": 2,
	"hilt": {"enabled": false, "min_severity": "HIGH"},
	"cisco_trust_level": "none",
}

_high_local_input := {
	"direction": "prompt",
	"model": "test-model",
	"mode": "action",
	"scanner_mode": "local",
	"local_result": {"action": "alert", "severity": "HIGH", "findings": ["test"], "reason": "test"},
	"cisco_result": null,
	"content_length": 4,
}

test_stricter_remote_threshold_blocks_high if {
	result := guardrail with input as _high_local_input
		with data.guardrail as _local
		with data.agent_control as {
			"enabled": true,
			"precedence": "stricter",
			"guardrail": {"block_threshold": 3, "alert_threshold": 2, "cisco_trust_level": "full"},
		}

	result.action == "block"
}

test_remote_precedence_uses_remote_threshold if {
	result := guardrail with input as _high_local_input
		with data.guardrail as object.union(_local, {"block_threshold": 2})
		with data.agent_control as {
			"enabled": true,
			"precedence": "remote",
			"guardrail": {"block_threshold": 4, "alert_threshold": 2, "cisco_trust_level": "none"},
		}

	result.action == "alert"
}

test_stricter_trust_uses_full_remote_result if {
	result := guardrail with input as object.union(_high_local_input, {
		"local_result": null,
		"cisco_result": {"action": "block", "severity": "HIGH", "findings": ["remote"], "reason": "remote", "is_safe": false},
	})
		with data.guardrail as _local
		with data.agent_control as {
			"enabled": true,
			"precedence": "stricter",
			"guardrail": {"block_threshold": 3, "alert_threshold": 2, "cisco_trust_level": "full"},
		}

	result.action == "block"
	result.severity == "HIGH"
}

test_disabled_overlay_preserves_local_baseline if {
	result := guardrail with input as _high_local_input
		with data.guardrail as _local
		with data.agent_control as {"enabled": false, "precedence": "stricter"}

	result.action == "alert"
}

test_stricter_thresholds_choose_lower_rank_matrix if {
	cases := [
		{"local": 1, "remote": 4, "want": 1},
		{"local": 2, "remote": 2, "want": 2},
		{"local": 3, "remote": 1, "want": 1},
		{"local": 4, "remote": 3, "want": 3},
	]
	every case in cases {
		block := guardrail._effective_block_threshold
			with data.guardrail as object.union(_local, {"block_threshold": case.local})
			with data.agent_control as {
				"enabled": true,
				"precedence": "stricter",
				"guardrail": {"block_threshold": case.remote, "alert_threshold": 1, "cisco_trust_level": "none"},
			}
		block == case.want
	}
}

test_stricter_trust_chooses_higher_strictness_matrix if {
	cases := [
		{"local": "none", "remote": "advisory", "want": "advisory"},
		{"local": "advisory", "remote": "none", "want": "advisory"},
		{"local": "advisory", "remote": "full", "want": "full"},
		{"local": "full", "remote": "none", "want": "full"},
	]
	every case in cases {
		trust := guardrail._effective_cisco_trust_level
			with data.guardrail as object.union(_local, {"cisco_trust_level": case.local})
			with data.agent_control as {
				"enabled": true,
				"precedence": "stricter",
				"guardrail": {"block_threshold": 4, "alert_threshold": 2, "cisco_trust_level": case.remote},
			}
		trust == case.want
	}
}

test_remote_precedence_uses_remote_trust if {
	trust := guardrail._effective_cisco_trust_level
		with data.guardrail as object.union(_local, {"cisco_trust_level": "full"})
		with data.agent_control as {
			"enabled": true,
			"precedence": "remote",
			"guardrail": {"block_threshold": 4, "alert_threshold": 2, "cisco_trust_level": "none"},
		}
	trust == "none"
}

test_agent_control_cannot_disable_live_hilt if {
	result := guardrail with input as object.union(_high_local_input, {
		"hilt": {"enabled": true, "min_severity": "HIGH"},
	})
		with data.guardrail as _local
		with data.agent_control as {
			"enabled": true,
			"precedence": "remote",
			"guardrail": {"block_threshold": 4, "alert_threshold": 2, "cisco_trust_level": "none"},
		}

	result.action == "confirm"
}

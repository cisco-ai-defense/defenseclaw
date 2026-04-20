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

package defenseclaw.budget_test

import rego.v1

import data.defenseclaw.budget

_zero_usage := {
	"tokens_last_minute": 0,
	"tokens_last_hour": 0,
	"tokens_last_day": 0,
	"requests_last_minute": 0,
	"requests_last_hour": 0,
	"requests_last_day": 0,
	"cost_last_hour": 0,
	"cost_last_day": 0,
}

_default_data := {"subjects": {"default": {
	"tokens_per_minute": 10000,
	"tokens_per_hour": 100000,
	"tokens_per_day": 1000000,
	"requests_per_minute": 60,
	"requests_per_hour": 1000,
	"requests_per_day": 10000,
	"cost_per_hour": 5.00,
	"cost_per_day": 50.00,
}}}

# --- Allow when within all limits ---

test_allow_within_limits if {
	result := budget with input as {
		"subject": "user:alice",
		"model": "gpt-4o",
		"estimated_tokens": 500,
		"estimated_cost": 0.01,
		"usage": _zero_usage,
	}
		with data.budget as _default_data

	result.action == "allow"
}

# --- Deny: tokens per minute exceeded ---

test_deny_tokens_per_minute if {
	usage := object.union(_zero_usage, {"tokens_last_minute": 9600})
	result := budget with input as {
		"subject": "user:alice",
		"model": "gpt-4o",
		"estimated_tokens": 500,
		"estimated_cost": 0.01,
		"usage": usage,
	}
		with data.budget as _default_data

	result.action == "deny"
	result.rule == "tokens_per_minute"
	result.limit == 10000
}

# --- Deny: tokens per hour exceeded ---

test_deny_tokens_per_hour if {
	usage := object.union(_zero_usage, {"tokens_last_hour": 99600})
	result := budget with input as {
		"subject": "user:alice",
		"model": "gpt-4o",
		"estimated_tokens": 500,
		"estimated_cost": 0.01,
		"usage": usage,
	}
		with data.budget as _default_data

	result.action == "deny"
	result.rule == "tokens_per_hour"
}

# --- Deny: tokens per day exceeded ---

test_deny_tokens_per_day if {
	usage := object.union(_zero_usage, {"tokens_last_day": 999600})
	result := budget with input as {
		"subject": "user:alice",
		"model": "gpt-4o",
		"estimated_tokens": 500,
		"estimated_cost": 0.01,
		"usage": usage,
	}
		with data.budget as _default_data

	result.action == "deny"
	result.rule == "tokens_per_day"
}

# --- Deny: requests per minute exceeded ---

test_deny_requests_per_minute if {
	usage := object.union(_zero_usage, {"requests_last_minute": 60})
	result := budget with input as {
		"subject": "user:alice",
		"model": "gpt-4o",
		"estimated_tokens": 10,
		"estimated_cost": 0.0001,
		"usage": usage,
	}
		with data.budget as _default_data

	result.action == "deny"
	result.rule == "requests_per_minute"
}

# --- Deny: cost per hour exceeded ---

test_deny_cost_per_hour if {
	usage := object.union(_zero_usage, {"cost_last_hour": 4.99})
	result := budget with input as {
		"subject": "user:alice",
		"model": "gpt-4o",
		"estimated_tokens": 10,
		"estimated_cost": 0.05,
		"usage": usage,
	}
		with data.budget as _default_data

	result.action == "deny"
	result.rule == "cost_per_hour"
}

# --- Deny: cost per day exceeded ---

test_deny_cost_per_day if {
	usage := object.union(_zero_usage, {"cost_last_day": 49.99})
	result := budget with input as {
		"subject": "user:alice",
		"model": "gpt-4o",
		"estimated_tokens": 10,
		"estimated_cost": 0.05,
		"usage": usage,
	}
		with data.budget as _default_data

	result.action == "deny"
	result.rule == "cost_per_day"
}

# --- Subject-specific override takes precedence over default ---

test_subject_specific_limits if {
	data_with_override := {"subjects": {
		"default": {
			"tokens_per_minute": 10000,
			"tokens_per_hour": 100000,
			"tokens_per_day": 1000000,
			"requests_per_minute": 60,
			"requests_per_hour": 1000,
			"requests_per_day": 10000,
			"cost_per_hour": 5.00,
			"cost_per_day": 50.00,
		},
		"user:limited": {
			"tokens_per_minute": 100,
			"tokens_per_hour": 1000,
			"tokens_per_day": 10000,
			"requests_per_minute": 5,
			"requests_per_hour": 100,
			"requests_per_day": 500,
			"cost_per_hour": 0.10,
			"cost_per_day": 1.00,
		},
	}}

	result := budget with input as {
		"subject": "user:limited",
		"model": "gpt-4o",
		"estimated_tokens": 200,
		"estimated_cost": 0.0001,
		"usage": _zero_usage,
	}
		with data.budget as data_with_override

	result.action == "deny"
	result.rule == "tokens_per_minute"
	result.limit == 100
}

# --- Zero limit means "unlimited" (no enforcement) ---

test_zero_limit_means_unlimited if {
	unlimited_data := {"subjects": {"default": {
		"tokens_per_minute": 0,
		"tokens_per_hour": 0,
		"tokens_per_day": 0,
		"requests_per_minute": 0,
		"requests_per_hour": 0,
		"requests_per_day": 0,
		"cost_per_hour": 0,
		"cost_per_day": 0,
	}}}

	usage := {
		"tokens_last_minute": 999999,
		"tokens_last_hour": 999999,
		"tokens_last_day": 999999,
		"requests_last_minute": 999,
		"requests_last_hour": 999,
		"requests_last_day": 999,
		"cost_last_hour": 999,
		"cost_last_day": 999,
	}

	result := budget with input as {
		"subject": "user:bob",
		"model": "gpt-4o",
		"estimated_tokens": 999999,
		"estimated_cost": 999,
		"usage": usage,
	}
		with data.budget as unlimited_data

	result.action == "allow"
}

# --- Missing subject falls back to default ---

test_unknown_subject_uses_default if {
	result := budget with input as {
		"subject": "user:newcomer",
		"model": "gpt-4o",
		"estimated_tokens": 500,
		"estimated_cost": 0.01,
		"usage": _zero_usage,
	}
		with data.budget as _default_data

	result.action == "allow"
}

# --- Precedence: tokens-per-minute deny reported before request-rate deny ---

test_token_precedence_over_requests if {
	usage := {
		"tokens_last_minute": 9600,
		"tokens_last_hour": 0,
		"tokens_last_day": 0,
		"requests_last_minute": 60,
		"requests_last_hour": 0,
		"requests_last_day": 0,
		"cost_last_hour": 0,
		"cost_last_day": 0,
	}

	result := budget with input as {
		"subject": "user:alice",
		"model": "gpt-4o",
		"estimated_tokens": 500,
		"estimated_cost": 0.01,
		"usage": usage,
	}
		with data.budget as _default_data

	result.action == "deny"
	result.rule == "tokens_per_minute"
}

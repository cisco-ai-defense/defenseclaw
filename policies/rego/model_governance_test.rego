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

package defenseclaw.model_governance_test

import rego.v1

import data.defenseclaw.model_governance

# ── Empty lists allow everything ──

test_empty_lists_allow_all if {
	result := model_governance with input as {"provider": "openai", "model": "gpt-4o"}
		with data.model_governance as {
			"providers": {"allow": [], "deny": []},
			"models": {"allow": [], "deny": []},
		}
	result.action == "allow"
}

# ── Provider deny ──

test_provider_deny if {
	result := model_governance with input as {"provider": "bedrock", "model": "claude-3.5-sonnet"}
		with data.model_governance as {
			"providers": {"allow": [], "deny": ["bedrock"]},
			"models": {"allow": [], "deny": []},
		}
	result.action == "deny"
	result.rule == "provider-deny"
}

test_provider_not_denied_passes if {
	result := model_governance with input as {"provider": "openai", "model": "gpt-4o"}
		with data.model_governance as {
			"providers": {"allow": [], "deny": ["bedrock"]},
			"models": {"allow": [], "deny": []},
		}
	result.action == "allow"
}

# ── Provider allow ──

test_provider_allow_blocks_unlisted if {
	result := model_governance with input as {"provider": "gemini", "model": "gemini-pro"}
		with data.model_governance as {
			"providers": {"allow": ["openai", "anthropic"], "deny": []},
			"models": {"allow": [], "deny": []},
		}
	result.action == "deny"
	result.rule == "provider-allow"
}

test_provider_allow_passes_listed if {
	result := model_governance with input as {"provider": "openai", "model": "gpt-4o"}
		with data.model_governance as {
			"providers": {"allow": ["openai", "anthropic"], "deny": []},
			"models": {"allow": [], "deny": []},
		}
	result.action == "allow"
}

# ── Model deny with globs ──

test_model_deny_glob if {
	result := model_governance with input as {"provider": "openai", "model": "gpt-3.5-turbo"}
		with data.model_governance as {
			"providers": {"allow": [], "deny": []},
			"models": {"allow": [], "deny": ["gpt-3.5-*"]},
		}
	result.action == "deny"
	result.rule == "model-deny"
}

test_model_deny_exact if {
	result := model_governance with input as {"provider": "openai", "model": "llama-2-13b"}
		with data.model_governance as {
			"providers": {"allow": [], "deny": []},
			"models": {"allow": [], "deny": ["llama-2-13b"]},
		}
	result.action == "deny"
	result.rule == "model-deny"
}

test_model_not_denied_passes if {
	result := model_governance with input as {"provider": "openai", "model": "gpt-4o"}
		with data.model_governance as {
			"providers": {"allow": [], "deny": []},
			"models": {"allow": [], "deny": ["gpt-3.5-*"]},
		}
	result.action == "allow"
}

# ── Model allow with globs ──

test_model_allow_blocks_unlisted if {
	result := model_governance with input as {"provider": "openai", "model": "llama-3-70b"}
		with data.model_governance as {
			"providers": {"allow": [], "deny": []},
			"models": {"allow": ["gpt-4o*", "claude-*"], "deny": []},
		}
	result.action == "deny"
	result.rule == "model-allow"
}

test_model_allow_passes_listed if {
	result := model_governance with input as {"provider": "openai", "model": "gpt-4o-mini"}
		with data.model_governance as {
			"providers": {"allow": [], "deny": []},
			"models": {"allow": ["gpt-4o*", "claude-*"], "deny": []},
		}
	result.action == "allow"
}

# ── Case insensitivity ──

test_case_insensitive_provider if {
	result := model_governance with input as {"provider": "OPENAI", "model": "gpt-4o"}
		with data.model_governance as {
			"providers": {"allow": ["openai"], "deny": []},
			"models": {"allow": [], "deny": []},
		}
	result.action == "allow"
}

test_case_insensitive_model if {
	result := model_governance with input as {"provider": "openai", "model": "GPT-3.5-TURBO"}
		with data.model_governance as {
			"providers": {"allow": [], "deny": []},
			"models": {"allow": [], "deny": ["gpt-3.5-*"]},
		}
	result.action == "deny"
}

# ── Provider deny takes precedence over model checks ──

test_provider_deny_short_circuits_model if {
	result := model_governance with input as {"provider": "bedrock", "model": "gpt-4o"}
		with data.model_governance as {
			"providers": {"allow": [], "deny": ["bedrock"]},
			"models": {"allow": ["gpt-4o"], "deny": []},
		}
	result.action == "deny"
	result.rule == "provider-deny"
}

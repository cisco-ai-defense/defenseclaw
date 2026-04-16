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

package defenseclaw.model_governance

import rego.v1

# Model & provider governance policy.
# Input fields:
#   provider  - inferred provider name (e.g. "openai", "bedrock")
#   model     - model name from request body (e.g. "gpt-4o")
#
# Static data (data.model_governance in data.json):
#   providers.allow  - list of allowed providers (empty = all allowed)
#   providers.deny   - list of denied providers
#   models.allow     - list of allowed model patterns (supports glob via *)
#   models.deny      - list of denied model patterns (supports glob via *)

default action := "allow"
default reason := ""
default rule := ""

# --- Provider checks (evaluated first) ---

# Deny if provider allow list is non-empty and provider is not in it
action := "deny" if {
	count(data.model_governance.providers.allow) > 0
	input.provider != ""
	not _provider_in_allow
}

rule := "provider-allow" if {
	count(data.model_governance.providers.allow) > 0
	input.provider != ""
	not _provider_in_allow
}

reason := sprintf("provider %q is not in the allowed list", [input.provider]) if {
	count(data.model_governance.providers.allow) > 0
	input.provider != ""
	not _provider_in_allow
}

# Deny if provider is explicitly in the deny list
action := "deny" if {
	_provider_in_deny
}

rule := "provider-deny" if {
	_provider_in_deny
}

reason := sprintf("provider %q is explicitly denied", [input.provider]) if {
	_provider_in_deny
}

# --- Model checks (evaluated after provider) ---

# Deny if model allow list is non-empty and model is not in it
action := "deny" if {
	not _provider_denied
	count(data.model_governance.models.allow) > 0
	input.model != ""
	not _model_in_allow
}

rule := "model-allow" if {
	not _provider_denied
	count(data.model_governance.models.allow) > 0
	input.model != ""
	not _model_in_allow
}

reason := sprintf("model %q is not in the allowed list", [input.model]) if {
	not _provider_denied
	count(data.model_governance.models.allow) > 0
	input.model != ""
	not _model_in_allow
}

# Deny if model is explicitly in the deny list
action := "deny" if {
	not _provider_denied
	_model_in_deny
}

rule := "model-deny" if {
	not _provider_denied
	_model_in_deny
}

reason := sprintf("model %q is explicitly denied", [input.model]) if {
	not _provider_denied
	_model_in_deny
}

# --- Helper rules ---

_provider_denied if {
	count(data.model_governance.providers.allow) > 0
	input.provider != ""
	not _provider_in_allow
}

_provider_denied if {
	_provider_in_deny
}

_provider_in_allow if {
	some p in data.model_governance.providers.allow
	lower(p) == lower(input.provider)
}

_provider_in_deny if {
	input.provider != ""
	some p in data.model_governance.providers.deny
	lower(p) == lower(input.provider)
}

_model_in_allow if {
	some pattern in data.model_governance.models.allow
	glob.match(lower(pattern), ["/"], lower(input.model))
}

_model_in_deny if {
	input.model != ""
	some pattern in data.model_governance.models.deny
	glob.match(lower(pattern), ["/"], lower(input.model))
}

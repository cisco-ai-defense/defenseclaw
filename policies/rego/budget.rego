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

package defenseclaw.budget

import rego.v1

# Token/cost budget policy. Enforces per-subject rate and spend limits for
# LLM traffic (mitigates LLM04 — Model Denial of Service and uncontrolled
# spend). The Go enforcer maintains in-memory counters and passes the
# current usage window alongside the request estimate; this policy decides
# allow vs deny based on limits defined in data.budget.
#
# Input fields:
#   subject          - identity of the caller (e.g. "user:alice", "team:eng",
#                      or "default")
#   model            - model name (used to look up pricing and per-model limits)
#   estimated_tokens - projected total tokens (prompt + max completion)
#   estimated_cost   - projected USD cost for this request
#   usage:
#     tokens_last_minute, tokens_last_hour, tokens_last_day
#     requests_last_minute, requests_last_hour, requests_last_day
#     cost_last_hour, cost_last_day
#
# Static data (data.budget):
#   subjects.<subject-id> limits:
#     tokens_per_minute, tokens_per_hour, tokens_per_day
#     requests_per_minute, requests_per_hour, requests_per_day
#     cost_per_hour, cost_per_day
#   subjects.default            - fallback limits when subject has no overrides
#   global                      - hard cap across all subjects
#
# Output:
#   action    - "allow" or "deny"
#   reason    - human-readable explanation
#   rule      - which limit was hit ("tokens_per_minute", "cost_per_day", ...)
#   limit     - the numeric threshold that was hit (0 when N/A)
#   remaining - tokens/requests/cost remaining in the window (0 when denied)

default action := "allow"

default reason := ""

default rule := ""

default limit := 0

default remaining := 0

# ---------------------------------------------------------------------------
# Effective limits for the subject (with fallback to default entry).
# ---------------------------------------------------------------------------

_subject_limits := data.budget.subjects[input.subject] if {
	input.subject != ""
	data.budget.subjects[input.subject]
}

_subject_limits := data.budget.subjects.default if {
	not data.budget.subjects[input.subject]
	data.budget.subjects.default
}

_subject_limits := {} if {
	not data.budget.subjects[input.subject]
	not data.budget.subjects.default
}

_global_limits := data.budget.global if {
	data.budget.global
}

_global_limits := {} if {
	not data.budget.global
}

# ---------------------------------------------------------------------------
# Deny rules — token budgets
# ---------------------------------------------------------------------------

action := "deny" if {
	limit_val := _subject_limits.tokens_per_minute
	limit_val > 0
	(input.usage.tokens_last_minute + input.estimated_tokens) > limit_val
}

rule := "tokens_per_minute" if {
	limit_val := _subject_limits.tokens_per_minute
	limit_val > 0
	(input.usage.tokens_last_minute + input.estimated_tokens) > limit_val
}

reason := sprintf("subject %q exceeded %d tokens/minute (used=%d, estimate=%d)", [
	input.subject,
	_subject_limits.tokens_per_minute,
	input.usage.tokens_last_minute,
	input.estimated_tokens,
]) if {
	limit_val := _subject_limits.tokens_per_minute
	limit_val > 0
	(input.usage.tokens_last_minute + input.estimated_tokens) > limit_val
}

limit := _subject_limits.tokens_per_minute if {
	limit_val := _subject_limits.tokens_per_minute
	limit_val > 0
	(input.usage.tokens_last_minute + input.estimated_tokens) > limit_val
}

# Tokens per hour.
action := "deny" if {
	limit_val := _subject_limits.tokens_per_hour
	limit_val > 0
	(input.usage.tokens_last_hour + input.estimated_tokens) > limit_val
}

rule := "tokens_per_hour" if {
	not _tpm_exceeded
	limit_val := _subject_limits.tokens_per_hour
	limit_val > 0
	(input.usage.tokens_last_hour + input.estimated_tokens) > limit_val
}

reason := sprintf("subject %q exceeded %d tokens/hour (used=%d, estimate=%d)", [
	input.subject,
	_subject_limits.tokens_per_hour,
	input.usage.tokens_last_hour,
	input.estimated_tokens,
]) if {
	not _tpm_exceeded
	limit_val := _subject_limits.tokens_per_hour
	limit_val > 0
	(input.usage.tokens_last_hour + input.estimated_tokens) > limit_val
}

limit := _subject_limits.tokens_per_hour if {
	not _tpm_exceeded
	limit_val := _subject_limits.tokens_per_hour
	limit_val > 0
	(input.usage.tokens_last_hour + input.estimated_tokens) > limit_val
}

# Tokens per day.
action := "deny" if {
	limit_val := _subject_limits.tokens_per_day
	limit_val > 0
	(input.usage.tokens_last_day + input.estimated_tokens) > limit_val
}

rule := "tokens_per_day" if {
	not _tpm_exceeded
	not _tph_exceeded
	limit_val := _subject_limits.tokens_per_day
	limit_val > 0
	(input.usage.tokens_last_day + input.estimated_tokens) > limit_val
}

reason := sprintf("subject %q exceeded %d tokens/day (used=%d, estimate=%d)", [
	input.subject,
	_subject_limits.tokens_per_day,
	input.usage.tokens_last_day,
	input.estimated_tokens,
]) if {
	not _tpm_exceeded
	not _tph_exceeded
	limit_val := _subject_limits.tokens_per_day
	limit_val > 0
	(input.usage.tokens_last_day + input.estimated_tokens) > limit_val
}

limit := _subject_limits.tokens_per_day if {
	not _tpm_exceeded
	not _tph_exceeded
	limit_val := _subject_limits.tokens_per_day
	limit_val > 0
	(input.usage.tokens_last_day + input.estimated_tokens) > limit_val
}

# ---------------------------------------------------------------------------
# Deny rules — request rate limits
# ---------------------------------------------------------------------------

action := "deny" if {
	limit_val := _subject_limits.requests_per_minute
	limit_val > 0
	(input.usage.requests_last_minute + 1) > limit_val
}

rule := "requests_per_minute" if {
	not _token_exceeded
	limit_val := _subject_limits.requests_per_minute
	limit_val > 0
	(input.usage.requests_last_minute + 1) > limit_val
}

reason := sprintf("subject %q exceeded %d requests/minute (used=%d)", [
	input.subject,
	_subject_limits.requests_per_minute,
	input.usage.requests_last_minute,
]) if {
	not _token_exceeded
	limit_val := _subject_limits.requests_per_minute
	limit_val > 0
	(input.usage.requests_last_minute + 1) > limit_val
}

limit := _subject_limits.requests_per_minute if {
	not _token_exceeded
	limit_val := _subject_limits.requests_per_minute
	limit_val > 0
	(input.usage.requests_last_minute + 1) > limit_val
}

# Requests per hour.
action := "deny" if {
	limit_val := _subject_limits.requests_per_hour
	limit_val > 0
	(input.usage.requests_last_hour + 1) > limit_val
}

rule := "requests_per_hour" if {
	not _token_exceeded
	not _rpm_exceeded
	limit_val := _subject_limits.requests_per_hour
	limit_val > 0
	(input.usage.requests_last_hour + 1) > limit_val
}

reason := sprintf("subject %q exceeded %d requests/hour (used=%d)", [
	input.subject,
	_subject_limits.requests_per_hour,
	input.usage.requests_last_hour,
]) if {
	not _token_exceeded
	not _rpm_exceeded
	limit_val := _subject_limits.requests_per_hour
	limit_val > 0
	(input.usage.requests_last_hour + 1) > limit_val
}

limit := _subject_limits.requests_per_hour if {
	not _token_exceeded
	not _rpm_exceeded
	limit_val := _subject_limits.requests_per_hour
	limit_val > 0
	(input.usage.requests_last_hour + 1) > limit_val
}

# Requests per day.
action := "deny" if {
	limit_val := _subject_limits.requests_per_day
	limit_val > 0
	(input.usage.requests_last_day + 1) > limit_val
}

rule := "requests_per_day" if {
	not _token_exceeded
	not _rpm_exceeded
	not _rph_exceeded
	limit_val := _subject_limits.requests_per_day
	limit_val > 0
	(input.usage.requests_last_day + 1) > limit_val
}

reason := sprintf("subject %q exceeded %d requests/day (used=%d)", [
	input.subject,
	_subject_limits.requests_per_day,
	input.usage.requests_last_day,
]) if {
	not _token_exceeded
	not _rpm_exceeded
	not _rph_exceeded
	limit_val := _subject_limits.requests_per_day
	limit_val > 0
	(input.usage.requests_last_day + 1) > limit_val
}

limit := _subject_limits.requests_per_day if {
	not _token_exceeded
	not _rpm_exceeded
	not _rph_exceeded
	limit_val := _subject_limits.requests_per_day
	limit_val > 0
	(input.usage.requests_last_day + 1) > limit_val
}

# ---------------------------------------------------------------------------
# Deny rules — cost caps
# ---------------------------------------------------------------------------

action := "deny" if {
	limit_val := _subject_limits.cost_per_hour
	limit_val > 0
	(input.usage.cost_last_hour + input.estimated_cost) > limit_val
}

rule := "cost_per_hour" if {
	not _token_exceeded
	not _request_exceeded
	limit_val := _subject_limits.cost_per_hour
	limit_val > 0
	(input.usage.cost_last_hour + input.estimated_cost) > limit_val
}

reason := sprintf("subject %q exceeded $%.2f/hour cost cap (used=$%.4f, estimate=$%.4f)", [
	input.subject,
	_subject_limits.cost_per_hour,
	input.usage.cost_last_hour,
	input.estimated_cost,
]) if {
	not _token_exceeded
	not _request_exceeded
	limit_val := _subject_limits.cost_per_hour
	limit_val > 0
	(input.usage.cost_last_hour + input.estimated_cost) > limit_val
}

# Cost per day.
action := "deny" if {
	limit_val := _subject_limits.cost_per_day
	limit_val > 0
	(input.usage.cost_last_day + input.estimated_cost) > limit_val
}

rule := "cost_per_day" if {
	not _token_exceeded
	not _request_exceeded
	not _cost_hour_exceeded
	limit_val := _subject_limits.cost_per_day
	limit_val > 0
	(input.usage.cost_last_day + input.estimated_cost) > limit_val
}

reason := sprintf("subject %q exceeded $%.2f/day cost cap (used=$%.4f, estimate=$%.4f)", [
	input.subject,
	_subject_limits.cost_per_day,
	input.usage.cost_last_day,
	input.estimated_cost,
]) if {
	not _token_exceeded
	not _request_exceeded
	not _cost_hour_exceeded
	limit_val := _subject_limits.cost_per_day
	limit_val > 0
	(input.usage.cost_last_day + input.estimated_cost) > limit_val
}

# ---------------------------------------------------------------------------
# Helper rules — compact exclusion predicates to layer precedence cleanly.
# ---------------------------------------------------------------------------

_tpm_exceeded if {
	limit_val := _subject_limits.tokens_per_minute
	limit_val > 0
	(input.usage.tokens_last_minute + input.estimated_tokens) > limit_val
}

_tph_exceeded if {
	limit_val := _subject_limits.tokens_per_hour
	limit_val > 0
	(input.usage.tokens_last_hour + input.estimated_tokens) > limit_val
}

_tpd_exceeded if {
	limit_val := _subject_limits.tokens_per_day
	limit_val > 0
	(input.usage.tokens_last_day + input.estimated_tokens) > limit_val
}

_token_exceeded if _tpm_exceeded

_token_exceeded if _tph_exceeded

_token_exceeded if _tpd_exceeded

_rpm_exceeded if {
	limit_val := _subject_limits.requests_per_minute
	limit_val > 0
	(input.usage.requests_last_minute + 1) > limit_val
}

_rph_exceeded if {
	limit_val := _subject_limits.requests_per_hour
	limit_val > 0
	(input.usage.requests_last_hour + 1) > limit_val
}

_rpd_exceeded if {
	limit_val := _subject_limits.requests_per_day
	limit_val > 0
	(input.usage.requests_last_day + 1) > limit_val
}

_request_exceeded if _rpm_exceeded

_request_exceeded if _rph_exceeded

_request_exceeded if _rpd_exceeded

_cost_hour_exceeded if {
	limit_val := _subject_limits.cost_per_hour
	limit_val > 0
	(input.usage.cost_last_hour + input.estimated_cost) > limit_val
}

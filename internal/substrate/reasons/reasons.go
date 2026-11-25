// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
// SPDX-License-Identifier: Apache-2.0

// Package reasons is the one table of Substrate secret reason codes: the
// stable code the gateway or the policy render returns, the words a person
// reads and the next step. The gateway returns only the code; the CLI looks
// the words up here; the TUI shows the CLI's message; the docs table is
// generated from it (go run ./internal/substrate/reasons/gen). A drift test
// fails on any secret reason code used in the code but missing here.
package reasons

import "strings"

// Where says which part of DefenseClaw returns a code.
type Where string

const (
	// API is an answer of the gateway's admin API (an HTTP status and a
	// {"reason": code} body).
	API Where = "api"
	// Render is a policy render drop: the binding is left out of an
	// agent's network policy, with this code as the reason.
	Render Where = "render"
	// Launcher is a refusal of the launcher itself, before any request.
	Launcher Where = "launcher"
)

// Audience says who can act on the fix.
type Audience string

const (
	Person Audience = "person"
	Admin  Audience = "admin"
)

// Reason is one row of the table.
type Reason struct {
	Code     string
	HTTP     int // 0 when the code is not an HTTP answer
	Where    Where
	Words    string // what happened, one sentence
	Fix      string // what to do next, one sentence
	Audience Audience
}

// Table is every secret and sign-in reason code. Keep it sorted by where, then code
// meaning; the docs table follows this order.
var Table = []Reason{
	{"shared_secret_admin_only", 403, API, "A shared secret is set by an administrator, in the store its source names.", "Ask your administrator to change it.", Person},
	{"secret_managed_outside_defenseclaw", 409, API, "Its value lives in Vault or a cloud secret store, not in a Kubernetes Secret.", "Change the value in that store.", Person},
	{"secret_not_found", 404, API, "No secret by that name is yours or bound to your profile.", "See the secrets you can use with: defenseclaw substrate secrets list", Person},
	{"secret_agent_not_found", 404, API, "You have no live agent of that name, so no secrets are listed for it.", "See your agents with: defenseclaw substrate list", Person},
	{"secret_test_agent_invalid", 400, API, "secrets test --agent takes the agent as ATESPACE/NAME.", "Give the agent as ATESPACE/NAME, as listed by: defenseclaw substrate list", Person},
	{"value_required", 400, API, "The value is empty, over 56 KiB or not UTF-8.", "Give the value again.", Person},
	{"secret_not_managed_by_defenseclaw", 409, API, "That Kubernetes Secret exists but DefenseClaw did not create it (it is not labelled as managed by DefenseClaw), and DefenseClaw changes only Secrets it created.", "Ask your administrator.", Admin},
	{"secret_store_unavailable", 503, API, "The gateway cannot reach the Kubernetes secret store.", "Try again in a minute; an administrator can check it with: defenseclaw-gateway substrate doctor --cluster", Admin},
	{"registrations_unavailable", 503, API, "The gateway cannot read the cluster's agent registrations right now.", "This is usually brief: try again in a minute, and if it stays, run defenseclaw substrate doctor.", Person},
	{"secret_not_stored", 502, API, "The secret store refused the write.", "Try again in a minute.", Person},
	{"secret_not_removed", 502, API, "The secret store refused the removal.", "Try again in a minute.", Person},
	{"secret_binding_outside_templates", 202, API, "No approved template covers that host, so an administrator was asked; your value is stored and is not used until then.", "See the ask with: defenseclaw substrate approvals", Person},
	{"secret_binding_outside_refused", 403, API, "No approved template covers that host, and your administrator does not take asks for other hosts.", "Use a host a template covers (see: defenseclaw substrate secrets templates), or ask your administrator to add a template.", Person},
	{"ask_admin_only", 403, API, "Only an administrator answers an ask for a secret binding, including your own.", "Wait for an administrator, or remove the binding with: defenseclaw substrate secrets rm NAME", Person},
	{"secret_bindings_locked", 403, API, "Your administrator allows values only: you can set the value of a secret they listed; your own bindings are not added or used.", "Set a listed secret with: defenseclaw substrate secrets set NAME", Person},
	{"secret_bindings_off", 404, API, "Self-service secrets are off on this cluster.", "Ask your administrator.", Person},
	{"secret_template_unknown", 400, API, "No approved template by that name is open to your profile.", "See the templates you can use with: defenseclaw substrate secrets templates", Person},
	{"secret_binding_limit", 409, API, "You have the most bindings allowed.", "Remove one with: defenseclaw substrate secrets rm NAME", Person},
	{"secret_name_taken", 409, API, "You or your administrator already have a secret by that name.", "Pick another name.", Person},
	{"signin_ended", 401, API, "This sign-in was ended on the cluster: you signed out, or an administrator ended it.", "Sign in again: defenseclaw substrate login", Person},
	{"revocation_unavailable", 503, API, "The cluster can't check ended sign-ins right now.", "Try again in a minute; if it stays, run defenseclaw substrate doctor.", Person},
	{"signin_no_issue_time", 400, API, "This sign-in has no issue time the cluster can use (a static Kubernetes token, a legacy Secret-based ServiceAccount token, or a token whose issue time is ahead of the cluster's clock), so the cluster can't tell your later sign-ins from it.", "To stop the token everywhere, remove it at the cluster; to end only this sign-in, run defenseclaw substrate logout.", Person},
	{"person_unknown", 404, API, "No sign-in of that person has been seen.", "Use issuer#subject to end the sign-ins of a person before a first sign-in.", Admin},

	{"secret_on_passthrough", 0, Render, "That host is not inspected (it is in allow_passthrough_for), so no secret is added there.", "An administrator can remove the host from allow_passthrough_for.", Admin},
	{"secret_not_for_profile", 0, Render, "The agent's profile is not one this secret is for.", "Run the agent with one of the secret's profiles.", Person},
	{"secret_not_in_allowed_credentials", 0, Render, "The profile limits which secrets its agents may use, and this one is not listed.", "Start the agent with --secret NAME, or ask your administrator to list it.", Person},
	{"secret_needs_person", 0, Render, "A personal secret needs a signed-in person, and this agent has none.", "Start the agent while signed in, with: defenseclaw substrate run", Person},
	{"secret_echo_host", 0, Render, "The host returns the requests it gets, so the cluster does not add a secret there: the real value would come back to the agent.", "Bind the secret to the API host that needs it. An administrator who wants the echo can set inject.allow_echo: true on the entry.", Person},
	{"secret_expired", 0, Render, "The binding passed its expiry, so the cluster no longer adds it.", "Add it again: defenseclaw substrate secrets rm NAME, then defenseclaw substrate secrets add NAME --template T --host H --expires 90d", Person},
	{"secret_binding_denied", 0, Render, "An administrator denied the binding, so the cluster does not add it.", "Ask your administrator, or remove it with: defenseclaw substrate secrets rm NAME", Person},
	{"secret_binding_ask_expired", 0, Render, "Nobody answered the administrator ask for the binding in time, so it is not used.", "Remove it with: defenseclaw substrate secrets rm NAME, then add it again to ask again.", Person},
	{"secret_binding_not_applied", 0, Render, "An administrator approved the binding, but the binding store was not updated, so it is not used yet.", "Ask your administrator to approve it again with: defenseclaw substrate approve ID", Person},
	{"secret_binding_not_covered", 0, Render, "The binding's template no longer covers its host, so the cluster does not add it.", "Remove it with: defenseclaw substrate secrets rm NAME, then add it again to ask an administrator.", Person},
	{"secret_binding_form_changed", 0, Render, "The binding's template changed its form since the value was stored, so the stored value no longer fits the header.", "Store the value again with: defenseclaw substrate secrets set NAME", Person},
	{"secret_not_set", 0, Render, "No value is stored for the secret yet.", "Store it with: defenseclaw substrate secrets set NAME", Person},
	{"secret_binding_other_person", 0, Render, "Your own binding goes only to your own agents, and this agent belongs to another person.", "Test it against one of your agents.", Person},
	{"secret_not_in_policy", 0, Render, "The agent's network policy does not carry the secret: the cluster updates a policy within seconds, or a host rule leaves it out.", "Test again in a few seconds; see the agent's rules with: defenseclaw substrate policy explain AGENT", Person},
	{"secret_invalid", 0, Render, "The secret's entry is malformed (the detail names the field).", "An administrator can fix the entry in substrate.secrets.", Admin},
	{"secret_header_conflict", 0, Render, "Another secret already sets that header on that host.", "Remove one of the two bindings.", Admin},
	{"secret_too_many_headers", 0, Render, "The host already has the most secret headers allowed.", "Remove a binding on that host.", Admin},
	{"invalid_pattern", 0, Render, "The host pattern is not valid.", "Bind the secret to an exact host or a *.domain pattern.", Admin},
	{"provider_host", 0, Render, "The host is a model provider, which agents reach only through the model proxy.", "Bind the secret to a different host.", Admin},
	{"defenseclaw_internal", 0, Render, "The host is one of DefenseClaw's own services.", "Bind the secret to a different host.", Admin},
	{"blocked", 0, Render, "The host is blocked for this agent.", "Bind the secret to a different host, or ask your administrator.", Admin},
	{"not_in_allow_only", 0, Render, "The host is outside the agent's allow list.", "Ask your administrator to allow the host for your profile.", Admin},

	{"secret_source_tool_missing", 0, Launcher, "The tool that source reads from is not installed or not on PATH (the detail names it).", "Install it, or give the value another way: --from-file, --stdin or the prompt.", Person},
	{"secret_source_unsupported", 0, Launcher, "That source does not exist on this computer (the macOS keychain is only on a Mac).", "Use --from-op, --from-file, --stdin or the prompt.", Person},
	{"secret_source_failed", 0, Launcher, "The source tool did not give a value (the detail says why).", "Sign in to that tool or fix the reference, then try again; or give the value another way.", Person},
}

// Status is a secret status the gateway reports (list and test).
type Status struct {
	Status string
	Words  string
}

// Statuses are the secret statuses, in the order the docs list them.
var Statuses = []Status{
	{"set", "The value is stored."},
	{"not set", "No value is stored yet."},
	{"managed outside DefenseClaw", "The value lives in Vault or a cloud store; DefenseClaw does not read it."},
	{"unknown", "The gateway could not read the store just now."},
	{"waiting on admin", "The binding waits for an administrator; the value is stored and not used until then."},
	{"denied", "An administrator denied the binding."},
	{"ask expired", "Nobody answered the ask in time; the binding is not used."},
	{"expired", "The binding passed its expiry and is not used."},
	{"not covered", "The binding's template no longer covers its host; the binding is not used."},
	{"template changed", "The binding's template changed its form since the value was stored; store the value again."},
	{"approved, not applied", "An administrator approved the binding, and the cluster has not applied it yet."},
	{"locked", "Your administrator allows values only, so your own bindings are not used."},
}

var byCode = func() map[string]Reason {
	m := make(map[string]Reason, len(Table))
	for _, r := range Table {
		m[r.Code] = r
	}
	return m
}()

// Lookup returns the row of code.
func Lookup(code string) (Reason, bool) {
	r, ok := byCode[code]
	return r, ok
}

// Known reports whether code is in the table.
func Known(code string) bool {
	_, ok := byCode[code]
	return ok
}

// Message is the one-line text a person reads for code: the words, the
// code in parentheses and the fix. It is "" for a code not in the table.
func Message(code string) string {
	r, ok := byCode[code]
	if !ok {
		return ""
	}
	return strings.TrimSuffix(r.Words, ".") + " (" + r.Code + "). " + r.Fix
}

// Must returns code and panics when it is not in the table. Use it where
// a new code is introduced so a missing row fails the first test that
// reaches it.
func Must(code string) string {
	if !Known(code) {
		panic("reasons: code not in the table: " + code)
	}
	return code
}

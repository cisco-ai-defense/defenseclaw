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

//go:build !windows

package gateway

import (
	"encoding/json"
	"net/http"
	"slices"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/substrate/identity"
)

// GAP-0653 (substrate-1): policy explain with no agent named said only the
// resolved profile. A person whose assignment selected nobody (a groups
// entry that names a group the token does not carry) was not told that they
// get default_profile, nor which assignment did not select them. The answer
// now carries default_profile, the source of the profile, the matched
// assignment, and the consulted assignments that did not select the caller
// with the selector keys that failed. A person is shown no other person's
// profile, group or account; an administrator is also shown the profile of
// each assignment.
func TestSubstratePolicyExplainSaysWhyAProfileAppliesGAP0653(t *testing.T) {
	opsPerson := identity.Person{Kind: identity.PersonHuman, Issuer: "https://idp.example", Subject: "olga", Principal: "olga@example.com", Groups: []string{"dc-ops"}}
	setup := func(defaultProfile string) func(*SubstrateConfig) {
		cfg := &config.Config{}
		cfg.Guardrail.DefaultProfile = defaultProfile
		cfg.Guardrail.ProfileAssignments = []config.ProfileAssignment{
			{Profile: "secretops", Match: config.ProfileMatch{Groups: []string{"dc-ops-group-id-77"}}},
			{Profile: "secretciso", Match: config.ProfileMatch{Users: []string{"carol@example.com"}}},
			{Profile: "opsprofile", Match: config.ProfileMatch{Groups: []string{"dc-ops"}}},
		}
		cfg.Substrate.LauncherAtespaces = map[string][]string{"eng": {"eng-web"}, "opsprofile": {"ops-web"}}
		return func(c *SubstrateConfig) {
			c.Profiles = SubstrateLauncherProfiles(cfg)
			c.ProfileWhy = SubstrateProfileWhyFor(cfg)
			c.People = fakePeople{"p-alice": alice, "p-admin": admin, "p-olga": opsPerson}
		}
	}
	explain := func(f *substrateFixture, tok string) (map[string]any, string) {
		rec := f.do(t, f.admin, http.MethodGet, "/api/v1/substrate/policy/explain", tok, "")
		if rec.Code != http.StatusOK {
			t.Fatalf("explain as %s: %d %s", tok, rec.Code, rec.Body)
		}
		var m map[string]any
		if err := json.Unmarshal(rec.Body.Bytes(), &m); err != nil {
			t.Fatal(err)
		}
		return m, rec.Body.String()
	}
	keys := func(v any) []string {
		var out []string
		for _, k := range v.([]any) {
			out = append(out, k.(string))
		}
		return out
	}

	f := newSubstrateFixture(t, setup("eng"))
	// alice matches nobody: default_profile applies, and the two entries
	// before the end of the list that did not select her are named by place.
	got, raw := explain(f, "p-alice")
	if got["profile"] != "eng" || got["default_profile"] != "eng" || got["profile_source"] != "default_profile" {
		t.Fatalf("a person no assignment selects is not told default_profile applies: %v", got)
	}
	miss, _ := got["unmatched_assignments"].([]any)
	if len(miss) != 3 {
		t.Fatalf("unmatched_assignments = %v, want the 3 consulted assignments", got["unmatched_assignments"])
	}
	first := miss[0].(map[string]any)
	if first["assignment"] != float64(1) || !slices.Equal(keys(first["did_not_select_you"]), []string{"groups"}) {
		t.Fatalf("assignment 1 is not reported as a groups miss: %v", first)
	}
	if second := miss[1].(map[string]any); second["assignment"] != float64(2) || !slices.Equal(keys(second["did_not_select_you"]), []string{"users"}) {
		t.Fatalf("assignment 2 is not reported as a users miss: %v", second)
	}
	// Privacy: no other profile, group or account in a person's answer.
	for _, leak := range []string{"secretops", "secretciso", "opsprofile", "dc-ops-group-id-77", "carol@example.com"} {
		if strings.Contains(raw, leak) {
			t.Fatalf("a person's explain shows %q: %s", leak, raw)
		}
	}
	if _, has := got["matched_assignment"]; has {
		t.Fatalf("matched_assignment set when none matched: %v", got)
	}

	// An assignment that selects the caller is named; the ones before it are
	// the unmatched.
	got, _ = explain(f, "p-olga")
	if got["profile"] != "opsprofile" || got["profile_source"] != "assignment" || got["matched_assignment"] != float64(3) || got["default_profile"] != "eng" {
		t.Fatalf("a person an assignment selects: %v", got)
	}
	if miss, _ := got["unmatched_assignments"].([]any); len(miss) != 2 {
		t.Fatalf("unmatched before the match = %v, want 2", got["unmatched_assignments"])
	}

	// An administrator also sees the profile of each consulted assignment.
	got, _ = explain(f, "p-admin")
	if miss, _ := got["unmatched_assignments"].([]any); len(miss) != 3 || miss[0].(map[string]any)["profile"] != "secretops" {
		t.Fatalf("an administrator is not shown the assignments' profiles: %v", got)
	}

	// No assignment and no default_profile: the answer says none, and the
	// reason stays the launcher's.
	f = newSubstrateFixture(t, setup(""))
	got, _ = explain(f, "p-alice")
	if got["profile_source"] != "none" || got["default_profile"] != "" || got["profile"] != "" {
		t.Fatalf("no default_profile: %v", got)
	}
}

// The selector-key classification and the launcher's own decision are the
// same code: an assignment selects the caller exactly when it misses
// nothing.
func TestSubstrateAssignmentMissesAgreeWithSelectsGAP0653(t *testing.T) {
	p := identity.Person{Kind: identity.PersonHuman, Subject: "s1", Principal: "a@example.com", Groups: []string{"g1"}}
	cases := []struct {
		m    config.ProfileMatch
		conn string
		want []string
	}{
		{config.ProfileMatch{}, "", []string{"match"}},
		{config.ProfileMatch{Groups: []string{"g1"}}, "", nil},
		{config.ProfileMatch{Groups: []string{"g2"}, Users: []string{"b@example.com"}}, "", []string{"groups", "users"}},
		{config.ProfileMatch{Groups: []string{"g1"}, Connectors: []string{"codex"}}, "", []string{"connectors"}},
		{config.ProfileMatch{Groups: []string{"g1"}, Connectors: []string{"codex"}}, "codex", nil},
		{config.ProfileMatch{Agents: []string{"agt-0123456789abcdef"}}, "", []string{"agent"}},
		{config.ProfileMatch{Substrate: &config.ProfileMatchSubstrate{Atespaces: []string{"a"}}}, "", []string{"agent"}},
		{config.ProfileMatch{Substrate: &config.ProfileMatchSubstrate{Workloads: []string{"repo:x:*"}}}, "", []string{"workloads"}},
	}
	for i, c := range cases {
		got := substrateAssignmentMisses(c.m, p, c.conn)
		if !slices.Equal(got, c.want) {
			t.Errorf("case %d: misses %v, want %v", i, got, c.want)
		}
		if sel := substrateAssignmentSelects(c.m, p, c.conn); sel != (len(c.want) == 0) {
			t.Errorf("case %d: selects %v with misses %v", i, sel, c.want)
		}
	}
}

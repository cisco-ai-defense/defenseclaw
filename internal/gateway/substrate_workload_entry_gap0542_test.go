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
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/substrate/identity"
)

func gap0542Config() *config.Config {
	cfg := &config.Config{}
	cfg.Guardrail.ProfileAssignments = []config.ProfileAssignment{
		{Profile: "eng", Match: config.ProfileMatch{Groups: []string{"eng"}}},
		{Profile: "ci-main", Match: config.ProfileMatch{Substrate: &config.ProfileMatchSubstrate{Workloads: []string{"repo:acme/web:ref:refs/heads/main"}}}},
		{Profile: "ci-any", Match: config.ProfileMatch{Substrate: &config.ProfileMatchSubstrate{Workloads: []string{"repo:acme@1/web@2:*"}}}},
	}
	return cfg
}

// GAP-0542: a match.substrate.workloads entry written in another form than
// the token's subject (GitHub puts owner and repository ids in it) matched
// nothing, and the workload got the default profile with no word. The
// actor list now tells a workload caller which entry its verified subject
// matched, or that none did.
func TestGAP0542SubstrateWorkloadEntry(t *testing.T) {
	cfg := gap0542Config()
	for sub, want := range map[string][2]string{
		"repo:acme/web:ref:refs/heads/main":      {"repo:acme/web:ref:refs/heads/main", "ci-main"},
		"repo:acme@1/web@2:ref:refs/heads/main":  {"repo:acme@1/web@2:*", "ci-any"},
		"repo:acme@1/web@2:ref:refs/heads/dev":   {"repo:acme@1/web@2:*", "ci-any"},
		"repo:other@9/web@2:ref:refs/heads/main": {"", ""},
	} {
		if e, p := SubstrateWorkloadEntry(cfg, sub); e != want[0] || p != want[1] {
			t.Errorf("%s: entry %q profile %q, want %v", sub, e, p, want)
		}
	}
	if e, p := SubstrateWorkloadEntry(nil, "x"); e != "" || p != "" {
		t.Errorf("nil config: %q %q", e, p)
	}
}

func TestGAP0542ActorListAnswersAWorkloadCaller(t *testing.T) {
	cfg := gap0542Config()
	ci := identity.Person{Kind: identity.PersonWorkload, Issuer: "https://token.actions.githubusercontent.com", Subject: "repo:acme@1/web@2:ref:refs/heads/main"}
	stray := identity.Person{Kind: identity.PersonWorkload, Issuer: "https://token.actions.githubusercontent.com", Subject: "repo:other@9/web@2:ref:refs/heads/main"}
	f := newSubstrateFixture(t, func(c *SubstrateConfig) {
		c.People = fakePeople{"p-alice": alice, "p-ci": ci, "p-stray": stray}
		c.WorkloadEntry = func(subject string) (string, string) { return SubstrateWorkloadEntry(cfg, subject) }
	})
	list := func(tok string) map[string]json.RawMessage {
		t.Helper()
		rec := f.do(t, f.admin, http.MethodGet, "/api/v1/substrate/actors", tok, "")
		if rec.Code != http.StatusOK {
			t.Fatalf("%s: list %d %s", tok, rec.Code, rec.Body)
		}
		var body map[string]json.RawMessage
		if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
			t.Fatal(err)
		}
		return body
	}
	workload := func(tok string) map[string]string {
		t.Helper()
		raw, ok := list(tok)["workload"]
		if !ok {
			t.Fatalf("%s: no workload answer", tok)
		}
		var w map[string]string
		if err := json.Unmarshal(raw, &w); err != nil {
			t.Fatal(err)
		}
		return w
	}
	if w := workload("p-ci"); w["subject"] != ci.Subject || w["entry"] != "repo:acme@1/web@2:*" || w["profile"] != "ci-any" {
		t.Errorf("matching workload: %v", w)
	}
	if w := workload("p-stray"); w["subject"] != stray.Subject || w["entry"] != "" || w["profile"] != "" {
		t.Errorf("stray workload: %v", w)
	}
	if _, ok := list("p-alice")["workload"]; ok {
		t.Error("a person got a workload answer")
	}
}

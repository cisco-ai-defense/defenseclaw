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

package config

import (
	"slices"
	"strings"
	"testing"
)

// TestSandboxAskKeysGAP0171: ask_hosts and url_rules are checked, added
// together by TightenSandboxAdmin (admin's first), left out of the host
// floor digest, and refused in openshell.admin.
func TestSandboxAskKeysGAP0171(t *testing.T) {
	ok := SandboxAdminConfig{AskHosts: []string{"uploads.example.com", "*.files.example.com"},
		URLRules: []SandboxURLRule{{Name: "r1", Hosts: []string{"api.example.com"}, Methods: []string{"POST"}, PathPrefix: "/admin/", Action: "Deny"}}}
	if err := ok.validateAskKeys("sandbox"); err != nil {
		t.Fatal(err)
	}
	for _, c := range []struct {
		cfg  SandboxAdminConfig
		want string
	}{
		{SandboxAdminConfig{AskHosts: []string{}}, "sandbox.ask_hosts: an empty list is refused"},
		{SandboxAdminConfig{AskHosts: []string{"https://x.example"}}, `sandbox.ask_hosts[0]: "https://x.example" must be a lower-case host name`},
		{SandboxAdminConfig{AskHosts: []string{"*"}}, `sandbox.ask_hosts[0]: "*" must be`},
		{SandboxAdminConfig{URLRules: []SandboxURLRule{}}, "sandbox.url_rules: an empty list is refused"},
		{SandboxAdminConfig{URLRules: []SandboxURLRule{{Hosts: []string{"a.example"}, Action: "allow"}}}, `sandbox.url_rules[0].action "allow" must be one of deny, ask`},
		{SandboxAdminConfig{URLRules: []SandboxURLRule{{Action: "deny"}}}, "sandbox.url_rules[0].hosts: name one to 64 hosts"},
		{SandboxAdminConfig{URLRules: []SandboxURLRule{{Hosts: []string{"a.example"}, Methods: []string{"post"}, Action: "deny"}}}, `sandbox.url_rules[0].methods[0]: "post" must be an HTTP method`},
		{SandboxAdminConfig{URLRules: []SandboxURLRule{{Hosts: []string{"a.example"}, PathPrefix: "/a%2Fb", Action: "deny"}}}, `sandbox.url_rules[0].path_prefix "/a%2Fb" must start with "/"`},
		{SandboxAdminConfig{URLRules: []SandboxURLRule{{Hosts: []string{"a.example"}, PathPrefix: "admin", Action: "deny"}}}, `path_prefix "admin" must start with "/"`},
		{SandboxAdminConfig{URLRules: []SandboxURLRule{{Name: "bad name", Hosts: []string{"a.example"}, Action: "ask"}}}, `sandbox.url_rules[0].name "bad name" must be letters`},
	} {
		if err := c.cfg.validateAskKeys("sandbox"); err == nil || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%+v: %v, want %q", c.cfg, err, c.want)
		}
	}

	floor := SandboxAdminConfig{AskHosts: []string{"a.example"},
		URLRules: []SandboxURLRule{{Name: "floor", Hosts: []string{"x.example"}, Action: "deny"}}}
	got, err := TightenSandboxAdmin(floor, &SandboxAdminConfig{AskHosts: []string{"b.example", "a.example"},
		URLRules: []SandboxURLRule{{Name: "prof", Hosts: []string{"y.example"}, Action: "ask"}, floor.URLRules[0]}})
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(got.AskHosts, []string{"a.example", "b.example"}) || len(got.URLRules) != 2 ||
		got.URLRules[0].Name != "floor" || got.URLRules[1].Name != "prof" {
		t.Fatalf("tightened %+v", got)
	}
	// The overlay's slices are not shared with the result.
	got.URLRules[0].Hosts[0] = "changed.example"
	if floor.URLRules[0].Hosts[0] != "x.example" {
		t.Fatal("tighten shares the floor's url rule hosts")
	}

	// Substrate keys: no change to the host floor digest.
	base, err := sandboxFloorDigest(SandboxAdminConfig{}, "")
	if err != nil {
		t.Fatal(err)
	}
	with, _ := sandboxFloorDigest(floor, "")
	if with != base {
		t.Fatal("ask keys change the host floor digest")
	}
	if floor.IsZero() || !(SandboxAdminConfig{}).IsZero() {
		t.Fatal("IsZero ignores the ask keys")
	}
	if err := floor.hostScopeError("admin"); err == nil || !strings.Contains(err.Error(), "admin.ask_hosts is an Agent Substrate key") ||
		!strings.Contains(err.Error(), "admin.url_rules is an Agent Substrate key") {
		t.Fatalf("openshell.admin: %v", err)
	}
}

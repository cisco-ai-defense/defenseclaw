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

package sandboxcli

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/openshell/packs"
	"github.com/defenseclaw/defenseclaw/internal/openshell/sandboxapi"
)

// A pack is tested here, without the daemon: the decisions are the egress
// decider's, a fixture mismatch exits 1, and the folder's repository policy
// counts as it would for a run.
func TestPolicyTestAPack(t *testing.T) {
	ta := newTestApp(t, "")
	ta.API = sandboxapi.NewClient("http://127.0.0.1:1", "x") // no daemon
	ta.ok(t, ta.PolicyTest(bg, PolicyTestOptions{Pack: "balanced", Host: "registry.npmjs.org:443", Binary: "/usr/bin/node"}))
	has(t, ta.output(), "pack balanced · profile balanced · network allowlist", "registry.npmjs.org:443 (/usr/bin/node)", "allowed",
		"DefenseClaw's curated allowlist")

	if err := os.MkdirAll(filepath.Join(ta.project, ".defenseclaw"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(ta.project, packs.RepoPolicyPath), []byte("version: 1\negress: {block: [github.com]}\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	fixture := filepath.Join(ta.home, "egress.yaml")
	if err := os.WriteFile(fixture, []byte(`
- {host: registry.npmjs.org, port: 443, expect: allow}
- {host: pastebin.com, port: 443, binary: /usr/bin/curl, expect: block, rule: feed}
- {host: github.com, port: 443, expect: allow}
`), 0o644); err != nil {
		t.Fatal(err)
	}
	err := ta.fresh().PolicyTest(bg, PolicyTestOptions{Pack: "balanced", Fixture: fixture, Output: OutputJSON})
	var exit *ExitError
	if !errors.As(err, &exit) || exit.Code != 1 {
		t.Fatalf("a mismatch: %v", err)
	}
	var report struct {
		Expected  int `json:"expected"`
		Failed    int `json:"failed"`
		Decisions []sandboxapi.PolicyDecision
		Results   []struct {
			Host string `json:"host"`
			Pass bool   `json:"pass"`
		} `json:"results"`
	}
	if err := json.Unmarshal(ta.out.Bytes(), &report); err != nil {
		t.Fatalf("%v: %s", err, ta.output())
	}
	if report.Expected != 3 || report.Failed != 1 || report.Results[2].Pass || report.Decisions[2].Rule != string(packs.RuleBlock) ||
		report.Decisions[2].Source != packs.RepoPolicyConstraint || !report.Results[1].Pass {
		t.Fatalf("report = %+v", report)
	}

	for _, o := range []PolicyTestOptions{
		{Sandbox: "x", Pack: "strict", Host: "a.example"},
		{Pack: "strict"},
		{Fixture: fixture, Host: "a.example"},
		{Pack: "strict", Host: "a.example:99999"},
	} {
		if err := ta.PolicyTest(bg, o); err == nil {
			t.Fatalf("%+v was accepted", o)
		}
	}
}

// A sandbox is tested by its daemon (its unblocks count), and a provider
// that opens the destination around the proxy is named.
func TestPolicyTestASandbox(t *testing.T) {
	ta := newTestApp(t, "")
	ta.daemon.policyTest = func(req sandboxapi.PolicyTestRequest) *sandboxapi.PolicyTestResult {
		return &sandboxapi.PolicyTestResult{Sandbox: req.Sandbox, Pack: "strict", Profile: "strict", NetworkMode: "deny",
			Decisions: []sandboxapi.PolicyDecision{{PolicyCheck: req.Checks[0], Rule: string(packs.RuleNetworkDeny),
				Source: "network.mode deny (profile strict from pack strict)", Direct: "the model provider (p) opens it directly for the harness's own programs"}}}
	}
	ta.ok(t, ta.PolicyTest(bg, PolicyTestOptions{Sandbox: "web", Host: "api.anthropic.com", Port: 443}))
	has(t, ta.output(), "sandbox web · pack strict", "blocked", "network_deny", "api.anthropic.com: the model provider (p) opens it directly")
	calls := ta.daemon.callsTo("POST", sandboxapi.PathPolicyTest)
	var req sandboxapi.PolicyTestRequest
	if len(calls) != 1 || json.Unmarshal(calls[0].Body, &req) != nil || req.Sandbox != "web" || req.Checks[0].Port != 443 {
		t.Fatalf("calls = %+v", calls)
	}
}

func TestRepoPolicyText(t *testing.T) {
	if got := repoPolicyText(nil); got != "" {
		t.Fatalf("no policy: %q", got)
	}
	got := repoPolicyText(&sandboxapi.RepoPolicy{Path: "/p/" + packs.RepoPolicyPath, Tightened: []string{"network.mode", "egress.block"}})
	if got != "repo policy .defenseclaw/sandbox.yaml: tightened 2 settings (network.mode, egress.block)" {
		t.Fatalf("banner text %q", got)
	}
	// A copy that does not match its digest is not used.
	if _, err := parseRepoPolicy(&sandboxapi.RepoPolicy{Content: []byte("version: 1\n"), Digest: "sha256:00"}); err == nil {
		t.Fatal("a mismatched copy was used")
	}
}

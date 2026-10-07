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

package manager

import (
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/openshell/packs"
	"github.com/defenseclaw/defenseclaw/internal/openshell/sandboxapi"
)

// A create reads the project's repository policy and keeps the copy it
// read, so an edit applies from the next run on; a client that resolved
// another copy, and a policy that would loosen, are refused.
func TestCreateKeepsTheRepoPolicy(t *testing.T) {
	e := newEnv(t, nil)
	file := writeFile(t, filepath.Join(e.project, packs.RepoPolicyPath), "version: 1\nnetwork: {mode: allowlist}\nharness: {yolo: false}\n")
	ex, err := e.m.Explain(t.Context(), sandboxapi.ExplainRequest{Harness: "claudecode", Project: e.project})
	must(t, err)
	if rp := ex.RepoPolicy; rp == nil || rp.Path != file || !slices.Equal(rp.Tightened, []string{"network.mode", "harness.yolo"}) ||
		len(rp.Content) == 0 || ex.Profile != "balanced" {
		t.Fatalf("explain = profile %s repo %+v", ex.Profile, ex.RepoPolicy)
	}

	_, err = e.tryCreate(sandboxapi.CreateRequest{Name: "stale", RepoPolicyDigest: sandboxapi.NoRepoPolicy})
	if apiErr := wantCode(t, err, sandboxapi.CodeConflict); !strings.Contains(apiErr.Message, "changed while the run started") {
		t.Fatalf("stale digest: %v", err)
	}
	e.create(sandboxapi.CreateRequest{Name: "repo", RepoPolicyDigest: ex.RepoPolicy.Digest})
	if rec := loadRecord(t, e, "repo"); rec == nil || rec.Flags.RepoPolicy == nil || rec.Flags.RepoPolicy.Digest != ex.RepoPolicy.Digest ||
		rec.Profile != "balanced" || rec.Yolo {
		t.Fatalf("record = %+v", rec)
	}

	// An edit made after the create (inside a live mount, say) waits for
	// the next run.
	writeFile(t, file, "version: 1\nnetwork: {mode: deny}\n")
	kept, err := e.m.Explain(t.Context(), sandboxapi.ExplainRequest{Sandbox: "repo"})
	must(t, err)
	if kept.Profile != "balanced" || kept.RepoPolicy == nil || kept.RepoPolicy.Digest != ex.RepoPolicy.Digest {
		t.Fatalf("the sandbox follows the edited file: profile %s repo %+v", kept.Profile, kept.RepoPolicy)
	}

	// A key that would loosen refuses the create and says which.
	other := e.otherProject("loose")
	writeFile(t, filepath.Join(other, packs.RepoPolicyPath), "version: 1\nharness: {yolo: true}\n")
	_, err = e.tryCreate(sandboxapi.CreateRequest{Name: "loose", Project: other})
	if apiErr := wantCode(t, err, sandboxapi.CodePolicyViolation); apiErr.Violation == nil || apiErr.Violation.Key != "harness.yolo" ||
		!strings.Contains(apiErr.Message, packs.RepoPolicyPath) {
		t.Fatalf("loosening: %v", err)
	}
	// A file the daemon cannot read safely refuses it too.
	linked := e.otherProject("linked")
	must(t, os.MkdirAll(filepath.Join(linked, ".defenseclaw"), 0o755))
	must(t, os.Symlink(file, filepath.Join(linked, packs.RepoPolicyPath)))
	_, err = e.tryCreate(sandboxapi.CreateRequest{Name: "linked", Project: linked})
	wantCode(t, err, sandboxapi.CodePackInvalid)
}

// A policy test asks the sandbox's own decider, so its unblocks count, and
// names a provider that opens the destination around the proxy.
func TestPolicyTestUsesTheSandboxDecider(t *testing.T) {
	e := newEnv(t, nil)
	e.create(sandboxapi.CreateRequest{Name: "web"})
	check := func(host string, port int) sandboxapi.PolicyDecision {
		t.Helper()
		res, err := e.m.PolicyTest(t.Context(), sandboxapi.PolicyTestRequest{Sandbox: "web", Checks: []sandboxapi.PolicyCheck{{Host: host, Port: port}}})
		must(t, err)
		if res.Pack != "open" || len(res.Decisions) != 1 {
			t.Fatalf("result = %+v", res)
		}
		return res.Decisions[0]
	}
	if d := check("pastebin.com", 443); d.Allowed || d.Rule != string(packs.RuleFeed) || !d.Unblockable || !strings.Contains(d.Source, "blocklist feed") {
		t.Fatalf("before the unblock: %+v", d)
	}
	_, err := e.m.Unblock(t.Context(), sandboxapi.UnblockRequest{Host: "pastebin.com", Sandbox: "web"})
	must(t, err)
	if d := check("pastebin.com", 443); !d.Allowed || d.Rule != string(packs.RuleUnblock) {
		t.Fatalf("after the unblock: %+v", d)
	}
	_, err = e.m.PolicyTest(t.Context(), sandboxapi.PolicyTestRequest{Sandbox: "web"})
	wantCode(t, err, sandboxapi.CodeInvalid)
	_, err = e.m.PolicyTest(t.Context(), sandboxapi.PolicyTestRequest{Sandbox: "nope", Checks: []sandboxapi.PolicyCheck{{Host: "a.example"}}})
	wantCode(t, err, sandboxapi.CodeNotFound)

	eps := []providerEndpoint{{Provider: "web-llm", Role: roleLLM, Host: "api.anthropic.com", Port: 443}}
	if got := directProvider(eps, "API.Anthropic.com", 0); !strings.Contains(got, "web-llm") {
		t.Fatalf("direct = %q", got)
	}
	if got := directProvider(eps, "api.anthropic.com", 8443); got != "" {
		t.Fatalf("another port: %q", got)
	}
}

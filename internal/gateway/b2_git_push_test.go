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

// newSubstrateFixture is unix-only (substrate_listener_test.go).
//go:build !windows

package gateway

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/substrate/asks"
)

// B2 2.4 (B2-07, B2-08): POST .../push answers allow, ask or deny from the
// actor's profile; an ask is answered inline or in approvals, Always covers
// the same person, profile and host, and only the agent's own person asks.
func TestB2GitPushRoute(t *testing.T) {
	mode := config.SubstrateGitPushAsk
	store := asks.NewMemory()
	f := newSubstrateFixture(t, func(c *SubstrateConfig) {
		c.Asks = store
		c.GitPush = func(profile string) string {
			if profile != "eng" {
				return config.SubstrateGitPushDeny
			}
			return mode
		}
	})
	head := strings.Repeat("a", 40)
	body := func(branch, askID string) string {
		b, _ := json.Marshal(map[string]any{"host": "git.example.test", "repo": "team/app", "branch": branch, "head": head,
			"commits": 3, "files": 5, "ask_id": askID})
		return string(b)
	}
	push := func(person, b string) (int, map[string]any) {
		rec := f.do(t, f.admin, http.MethodPost, "/api/v1/substrate/actors/eng-web/alice-1/push", person, b)
		var v map[string]any
		_ = json.Unmarshal(rec.Body.Bytes(), &v)
		return rec.Code, v
	}
	if code, _ := push("p-bob", body("agent/x", "")); code == http.StatusOK {
		t.Fatal("bob may ask to push alice's agent")
	}
	for _, bad := range []string{"-x", "a..b", "refs/../x", "x.lock", "", "a b"} {
		if code, _ := push("p-alice", body(bad, "")); code != http.StatusBadRequest {
			t.Errorf("branch %q: %d, want 400", bad, code)
		}
	}
	code, v := push("p-alice", body("agent/fix-login", ""))
	id, _ := v["ask_id"].(string)
	if code != http.StatusOK || v["decision"] != "ask" || id == "" ||
		v["summary"] != "Push agent/fix-login at aaaaaaaaaaaa (3 commits, 5 files) to git.example.test/team/app?" {
		t.Fatalf("ask: %d %v", code, v)
	}
	if _, v := push("p-alice", body("agent/fix-login", id)); v["decision"] != "ask" || v["ask_id"] != id {
		t.Fatalf("pending ask read again: %v", v)
	}
	if rec := f.do(t, f.admin, http.MethodPost, "/api/v1/substrate/asks/"+id, "p-alice", `{"decision":"approve","always":true}`); rec.Code/100 != 2 {
		t.Fatalf("approve %d %s", rec.Code, rec.Body)
	}
	if _, v := push("p-alice", body("agent/fix-login", id)); v["decision"] != "allow" {
		t.Fatalf("after approve: %v", v)
	}
	if _, v := push("p-alice", body("agent/other", "")); v["decision"] != "allow" {
		t.Fatalf("always for the same person, profile and host: %v", v)
	}
	reg, _, _ := f.regs.Get(t.Context(), "eng-web", subUID1)
	if len(reg.Approved) != 0 {
		t.Fatalf("a push approval joined the egress approvals: %v", reg.Approved)
	}
	mode = config.SubstrateGitPushDeny
	if _, v := push("p-alice", body("agent/third", "")); v["decision"] != "deny" || v["reason"] != "git_push_denied" {
		t.Fatalf("git_push: deny: %v", v)
	}
	mode = config.SubstrateGitPushAllow
	if _, v := push("p-alice", body("agent/fourth", "")); v["decision"] != "allow" {
		t.Fatalf("git_push: allow: %v", v)
	}
}

// B2 2.4: an Always approval of a push never answers an egress ask.
func TestB2GitPushAlwaysIsNotAnEgressApproval(t *testing.T) {
	approved := asks.Ask{Kind: asks.KindGitPush, Always: true, State: asks.StateApproved, OwnerID: "o", Profile: "eng",
		Host: "git.example.test", Rule: asks.GitPushRule("team/app", "")}
	for _, rule := range []string{"", "ask_hosts:git.example.test", asks.GitPushRule("team/app", "")} {
		if alwaysApprovalCovers(approved, asks.Ask{OwnerID: "o", Profile: "eng", Host: "git.example.test", Rule: rule}) {
			t.Fatalf("push approval answers egress ask rule %q", rule)
		}
	}
}

// B2 2.4: the launcher reports the cluster's push_branch.
func TestB2LauncherReportsPushBranch(t *testing.T) {
	if v := substrateLauncherGit(func() config.SubstrateGitConfig { return config.SubstrateGitConfig{PushBranch: "Deny"} }); v["push_branch_effective"] != "deny" {
		t.Fatalf("launcher git: %v", v)
	}
	if v := substrateLauncherGit(nil); v["push_branch_effective"] != "ask" {
		t.Fatalf("launcher git default: %v", v)
	}
}

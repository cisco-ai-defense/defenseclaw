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

package extproc

import (
	"context"
	"errors"
	"slices"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/substrate/pushgrant"
)

// storeGrants checks pushes against a real leader grant store.
type storeGrants struct {
	s   *pushgrant.Store
	err error
}

func (g *storeGrants) CheckPush(ctx context.Context, atespace, actor, host, repo string, push bool) (bool, bool, string, error) {
	if g.err != nil {
		return false, false, "", g.err
	}
	a, err := g.s.Check(ctx, pushgrant.CheckRequest{Atespace: atespace, Actor: actor, Host: host, Repo: repo, Push: push})
	return a.Active, a.Match, a.Granted, err
}

func gitReq(name, method, host, path string) *Request {
	r := req("other", method, host, path)
	r.Actor.Name = name
	if method == "POST" {
		r.EndOfStream = false
		r.ContentType = "application/x-git-receive-pack-request"
	}
	return r
}

// TestGAP1073PushGrantHoldsThePushToTheApprovedRepo: while pull
// --push-branch holds a grant for git.example.test/team/app, egress refuses
// a git push of that actor to any other repository or host (a push the agent
// redirected inside the actor), lets the approved one and every fetch
// through, and leaves other actors alone. Closed, nothing changes.
func TestGAP1073PushGrantHoldsThePushToTheApprovedRepo(t *testing.T) {
	ctx := context.Background()
	grants := &storeGrants{s: pushgrant.NewStore()}
	h := newHarness(t, func(_ *Config, o *Options) { o.PushGrants = grants })
	g, err := grants.s.Open(ctx, pushgrant.OpenRequest{Atespace: "other", Actor: "a1", UID: "uid-1",
		Host: "git.example.test", Repo: "team/app", Ref: "refs/heads/agent/x"})
	if err != nil {
		t.Fatal(err)
	}
	const rp = "?service=git-receive-pack"
	cases := []struct {
		name, actor, method, host, path string
		allow                           bool
	}{
		{"approved refs", "a1", "GET", "git.example.test", "/team/app.git/info/refs" + rp, true},
		{"approved push", "a1", "POST", "git.example.test", "/team/app.git/git-receive-pack", true},
		{"approved no .git", "a1", "GET", "git.example.test", "/team/app/info/refs" + rp, true},
		{"approved other case", "a1", "GET", "git.example.test", "/Team/App.git/info/refs" + rp, true},
		{"approved escaped", "a1", "POST", "git.example.test", "/team/%61pp.git/git-receive-pack", true},
		{"other repo refs", "a1", "GET", "git.example.test", "/team/other.git/info/refs" + rp, false},
		{"other repo push", "a1", "POST", "git.example.test", "/team/other.git/git-receive-pack", false},
		{"other repo service case", "a1", "GET", "git.example.test", "/team/other.git/info/refs?service=GIT-RECEIVE-PACK", false},
		{"other repo push case", "a1", "POST", "git.example.test", "/team/other.git/GIT-RECEIVE-PACK", false},
		{"other host push", "a1", "POST", "git2.example.test", "/team/app.git/git-receive-pack", false},
		{"dot segments", "a1", "POST", "git.example.test", "/team/app.git/../other.git/git-receive-pack", false},
		{"fetch refs elsewhere", "a1", "GET", "git.example.test", "/team/other.git/info/refs?service=git-upload-pack", true},
		{"fetch elsewhere", "a1", "POST", "git.example.test", "/team/other.git/git-upload-pack", true},
		{"other actor push", "a2", "POST", "git.example.test", "/team/other.git/git-receive-pack", true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			v := h.eng.DecideHeaders(ctx, gitReq(c.actor, c.method, c.host, c.path))
			if v.Allow != c.allow {
				t.Fatalf("allow = %v (%s: %s), want %v", v.Allow, v.Category, v.Reason, c.allow)
			}
			if !c.allow && v.Category != CategoryPushRedirect {
				t.Fatalf("category %q, want %s", v.Category, CategoryPushRedirect)
			}
		})
	}
	closed, _ := grants.s.Close(ctx, pushgrant.CloseRequest{Atespace: "other", Actor: "a1", ID: g.ID})
	if !closed.Found || closed.Pushes < 2 {
		t.Fatalf("close: %+v, want found with the 2 approved pushes counted", closed)
	}
	if v := h.eng.DecideHeaders(ctx, gitReq("a1", "POST", "git.example.test", "/team/other.git/git-receive-pack")); !v.Allow {
		t.Fatalf("after close: %s %s, want the push decided as before", v.Category, v.Reason)
	}
}

// TestGAP1073PushGrantCheckOutage: a grant check with no answer refuses the
// receive-pack POST (retryable) and lets the info/refs GET through with an
// alert; a callout with no grant checker decides pushes as before.
func TestGAP1073PushGrantCheckOutage(t *testing.T) {
	ctx := context.Background()
	h := newHarness(t, func(_ *Config, o *Options) { o.PushGrants = &storeGrants{err: errors.New("leader down")} })
	v := h.eng.DecideHeaders(ctx, gitReq("a1", "POST", "git.example.test", "/team/app.git/git-receive-pack"))
	if v.Allow || v.Category != CategoryPushUnchecked || !v.Retryable {
		t.Fatalf("POST on outage: allow=%v %s retry=%v", v.Allow, v.Category, v.Retryable)
	}
	v = h.eng.DecideHeaders(ctx, gitReq("a1", "GET", "git.example.test", "/team/app.git/info/refs?service=git-receive-pack"))
	if !v.Allow || !v.Alert || !slices.Contains(v.Findings, "push_grant_unchecked") {
		t.Fatalf("GET on outage: allow=%v alert=%v %v", v.Allow, v.Alert, v.Findings)
	}
	if v := h.eng.DecideHeaders(ctx, gitReq("a1", "GET", "git.example.test", "/team/app.git/info/refs?service=git-upload-pack")); !v.Allow || slices.Contains(v.Findings, "push_grant_unchecked") {
		t.Fatalf("fetch on outage checked the grant: %v %v", v.Allow, v.Findings)
	}
	plain := newHarness(t, nil)
	if v := plain.eng.DecideHeaders(ctx, gitReq("a1", "POST", "git.example.test", "/team/other.git/git-receive-pack")); !v.Allow {
		t.Fatalf("no checker: %s %s", v.Category, v.Reason)
	}
}

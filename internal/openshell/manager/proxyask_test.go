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

package manager

import (
	"net/http"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/openshell/egress"
	"github.com/defenseclaw/defenseclaw/internal/openshell/sandboxapi"
	"github.com/defenseclaw/defenseclaw/internal/sandboxrelay"
)

// GAP-0626: under the balanced profile (triaged approvals) a site outside
// the allowlist is not only refused by the proxy: the user gets an ask they
// answer, the agent's next hook says it waits, and approving it for the
// session opens the site (an allow the managed gateway checks with the
// ask's id).
func TestProxyRefusalRaisesAnAsk(t *testing.T) {
	e, auth := managedEnv(t, func(c *config.Config) { c.OpenShell.Profile = config.OpenShellProfileBalanced })
	proxy := startLiveProxyWith(t, e, func(o *egress.Options) { o.Sink = e.m.EgressSink() })
	e.live(sandboxapi.CreateRequest{Name: "pxbox"})
	reg := e.register("pxbox")
	b := e.binding("pxbox")
	for range 2 {
		if status, _ := proxy.connect(t, "pxbox", "example.org:443"); status != http.StatusForbidden {
			t.Fatalf("CONNECT example.org = %d, want the proxy's refusal", status)
		}
	}
	asks := e.waitAsks("pxbox", 1)
	if ask := asks[0]; ask.Host != "example.org" || ask.Port != 443 || ask.Kind != "network_rule" {
		t.Fatalf("ask = %+v", ask)
	}
	if got := e.m.EgressRefusals(b.ID, b.SandboxName); len(got) != 1 || got[0].Note != NoteAsked || got[0].Host != "example.org" {
		t.Fatalf("the agent is told %+v, want that the connection waits for the user", got)
	}
	if e.decideEgress("pxbox", "example.org").Allowed {
		t.Fatal("the proxy allows the site before the user answers")
	}

	// Approve for the session: an allow for the session, named by the ask.
	if _, err := e.m.DecideApproval(t.Context(), asks[0].ID, approve); err != nil {
		t.Fatalf("approve = %v", err)
	}
	e.waitAsks("pxbox", 0)
	if !e.decideEgress("pxbox", "example.org").Allowed {
		t.Fatal("the proxy still refuses the approved site")
	}
	got := auth.decisions()
	if len(got) != 1 || got[0].Registration != reg || got[0].Kind != sandboxrelay.DecisionEgressAllow || got[0].Host != "example.org" ||
		got[0].Scope != sandboxrelay.DecisionScopeSession || got[0].ApprovalID != asks[0].ID {
		t.Fatalf("decisions = %+v, want the session allow naming the ask", got)
	}

	// An unblock made outside the ask answers it.
	if status, _ := proxy.connect(t, "pxbox", "files.example.net:443"); status != http.StatusForbidden {
		t.Fatalf("CONNECT files.example.net = %d", status)
	}
	e.waitAsks("pxbox", 1)
	if _, err := e.m.Unblock(t.Context(), sandboxapi.UnblockRequest{Host: "files.example.net", Sandbox: "pxbox"}); err != nil {
		t.Fatalf("unblock = %v", err)
	}
	e.waitAsks("pxbox", 0)

	// Declined: the site stays refused and the ask does not return at once.
	if status, _ := proxy.connect(t, "pxbox", "other.example.net:443"); status != http.StatusForbidden {
		t.Fatalf("CONNECT other.example.net = %d", status)
	}
	declined := e.waitAsks("pxbox", 1)
	must(t, e.decide(declined[0].ID, sandboxapi.ApprovalDecision{Decision: "reject"}))
	proxy.connect(t, "pxbox", "other.example.net:443")
	time.Sleep(150 * time.Millisecond)
	if asks, _ := e.m.Approvals(t.Context(), "pxbox"); len(asks) != 0 {
		t.Fatalf("a declined site asked again: %+v", asks)
	}
}

// GAP-0626: allow_unblock: false takes "always" and unblocks from the user,
// not the session approval (plan §6.2). The site off the allowlist still
// asks, "always" is refused, and the session approval opens it although the
// decider ignores unblocks.
func TestProxyAskUnderAllowUnblockFalse(t *testing.T) {
	e, auth := managedEnv(t, func(c *config.Config) {
		c.OpenShell.Profile = config.OpenShellProfileBalanced
		c.OpenShell.Admin.AllowUnblock = boolPtr(false)
	})
	proxy := startLiveProxyWith(t, e, func(o *egress.Options) { o.Sink = e.m.EgressSink() })
	e.live(sandboxapi.CreateRequest{Name: "nubox"})
	e.register("nubox")
	if status, _ := proxy.connect(t, "nubox", "example.org:443"); status != http.StatusForbidden {
		t.Fatalf("CONNECT example.org = %d, want the proxy's refusal", status)
	}
	asks := e.waitAsks("nubox", 1)
	if _, err := e.m.DecideApproval(t.Context(), asks[0].ID, sandboxapi.ApprovalDecision{Decision: "approve", Always: true}); err == nil {
		t.Fatal("approved for always under allow_unblock: false")
	}
	if _, err := e.m.DecideApproval(t.Context(), asks[0].ID, approve); err != nil {
		t.Fatalf("approve for the session = %v", err)
	}
	e.waitAsks("nubox", 0)
	if dec := e.decideEgress("nubox", "example.org"); !dec.Allowed || dec.Source != egress.SourceApproval {
		t.Fatalf("decision after the approval = %+v, want the approved ask", dec)
	}
	if got := auth.decisions(); len(got) != 1 || got[0].Kind != sandboxrelay.DecisionEgressAllow || got[0].Scope != sandboxrelay.DecisionScopeSession {
		t.Fatalf("decisions = %+v, want one session allow", got)
	}
	if _, err := e.m.Unblock(t.Context(), sandboxapi.UnblockRequest{Host: "other.example.net", Sandbox: "nubox"}); err == nil {
		t.Fatal("unblocked under allow_unblock: false")
	}
}

// No ask the user can't answer: not when the floor takes the decision from
// them (user_approvals: none) and not when the profile decides itself (open
// network, approvals auto).
func TestProxyRefusalAsksOnlyWhenTheUserDecides(t *testing.T) {
	for name, edit := range map[string]func(*config.Config){
		"user_approvals none": func(c *config.Config) { c.OpenShell.Admin.UserApprovals = config.OpenShellUserApprovalsNone },
	} {
		t.Run(name, func(t *testing.T) {
			e, _ := managedEnv(t, func(c *config.Config) {
				c.OpenShell.Profile = config.OpenShellProfileBalanced
				edit(c)
			})
			proxy := startLiveProxyWith(t, e, func(o *egress.Options) { o.Sink = e.m.EgressSink() })
			e.live(sandboxapi.CreateRequest{Name: "nobox"})
			e.register("nobox")
			if status, _ := proxy.connect(t, "nobox", "example.org:443"); status != http.StatusForbidden {
				t.Fatalf("CONNECT example.org = %d", status)
			}
			eventually(t, "the refusal on the feed", func() bool {
				return len(e.events("nobox", sandboxapi.ActivityEgressBlocked, "")) > 0
			})
			if asks, _ := e.m.Approvals(t.Context(), "nobox"); len(asks) != 0 {
				t.Fatalf("asks the user can't answer: %+v", asks)
			}
		})
	}
}

// GAP-0415: the reject of the egress proxy's ask for a public site called
// it "port 443 on your machine", the words of a host-port ask: both are
// asks DefenseClaw raises itself. It names the destination.
func TestProxyAskRejectNamesTheDestination(t *testing.T) {
	e, _ := managedEnv(t, func(c *config.Config) { c.OpenShell.Profile = config.OpenShellProfileBalanced })
	proxy := startLiveProxyWith(t, e, func(o *egress.Options) { o.Sink = e.m.EgressSink() })
	e.live(sandboxapi.CreateRequest{Name: "rjbox"})
	e.register("rjbox")
	if status, _ := proxy.connect(t, "rjbox", "example.org:443"); status != http.StatusForbidden {
		t.Fatalf("CONNECT example.org = %d, want the proxy's refusal", status)
	}
	asks := e.waitAsks("rjbox", 1)
	res, err := e.m.DecideApproval(t.Context(), asks[0].ID, sandboxapi.ApprovalDecision{Decision: sandboxapi.DecisionReject})
	if err != nil || !strings.HasPrefix(res.Message, "example.org:443 stays closed to rjbox") || strings.Contains(res.Message, "on your machine") {
		t.Fatalf("reject = %+v, %v", res, err)
	}
	if !slices.ContainsFunc(e.events("rjbox", sandboxapi.ActivityApprovalResolved, ""), func(ev sandboxapi.ActivityEvent) bool {
		return ev.Message == "rejected example.org:443"
	}) {
		t.Fatalf("feed = %+v", e.events("rjbox", sandboxapi.ActivityApprovalResolved, ""))
	}
}

// GAP-0508: a sandbox stopped with an ask waiting kept it: approvals listed
// it and status counted it, though nothing could answer it any more. The
// stop ends it as expired.
func TestStoppedSandboxEndsItsAsks(t *testing.T) {
	e, _ := managedEnv(t, func(c *config.Config) { c.OpenShell.Profile = config.OpenShellProfileBalanced })
	proxy := startLiveProxyWith(t, e, func(o *egress.Options) { o.Sink = e.m.EgressSink() })
	e.live(sandboxapi.CreateRequest{Name: "stbox"})
	e.register("stbox")
	if status, _ := proxy.connect(t, "stbox", "example.org:443"); status != http.StatusForbidden {
		t.Fatalf("CONNECT example.org = %d, want the proxy's refusal", status)
	}
	asks := e.waitAsks("stbox", 1)
	if _, err := e.m.Stop(t.Context(), "stbox"); err != nil {
		t.Fatalf("stop = %v", err)
	}
	if left, _ := e.m.Approvals(t.Context(), "stbox"); len(left) != 0 {
		t.Fatalf("asks of the stopped sandbox = %+v", left)
	}
	if v := e.get("stbox"); v.PendingApprovals != 0 {
		t.Fatalf("status counts %d waiting asks", v.PendingApprovals)
	}
	if !slices.ContainsFunc(e.events("stbox", sandboxapi.ActivityApprovalResolved, ""), func(ev sandboxapi.ActivityEvent) bool {
		return ev.ApprovalID == asks[0].ID && ev.Reason == "expired"
	}) {
		t.Fatalf("feed = %+v", e.events("stbox", sandboxapi.ActivityApprovalResolved, ""))
	}
}

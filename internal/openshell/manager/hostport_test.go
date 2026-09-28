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
	"context"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/audit"
	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/openshell"
	"github.com/defenseclaw/defenseclaw/internal/openshell/sandboxapi"
)

// The first denied connection to a declared --host-port becomes an ask,
// and approving it opens the port: live, OpenShell drafted no proposal for
// the host alias, so "opens when you approve the sandbox's first
// connection" never happened and no command could open the port.
func TestDeclaredHostPortAsks(t *testing.T) {
	e := newEnv(t, nil)
	e.run()
	sb := e.create(sandboxapi.CreateRequest{Name: "hpbox", HostPorts: []int{38830}})
	e.watch.waitStarted(t, sb.Name)
	pe := &ownPortsEnv{harnessEnv: e, name: sb.Name}
	pe.push("CONFIG:PUBLISHED [INFO] Policy DNS mapped host.openshell.internal resolved=127.0.0.1 synthetic=198.18.0.2 ports=18971,18972 mapping_id=m1")
	denied := "NET:OPEN [MED] DENIED /usr/bin/curl(0) -> 198.18.0.2:38830 [reason:transparent_tcp_mapping_denied]"
	pe.push(denied)
	pe.push(denied)
	ctx := context.Background()
	asks, err := e.m.Approvals(ctx, sb.Name)
	if err != nil || len(asks) != 1 {
		t.Fatalf("asks = %+v, %v; want one for the declared port", asks, err)
	}
	ask := asks[0]
	if ask.Kind != sandboxapi.ApprovalKindHostPort || ask.Host != openshellHostAlias || ask.Port != 38830 || !ask.Risky ||
		ask.ChunkID != "" || !strings.Contains(ask.Reason, "port 38830 on your machine") {
		t.Fatalf("ask = %+v", ask)
	}
	var requested int
	for _, ev := range e.m.ActivitySince(0, sb.Name) {
		if ev.Kind == sandboxapi.ActivityApprovalRequested && ev.ApprovalID == ask.ID {
			requested++
		}
	}
	if requested != 1 {
		t.Fatalf("approval.requested events = %d, want 1", requested)
	}
	if n := pe.blocked(); n != 2 {
		t.Fatalf("blocked = %d, want both denied connections", n)
	}

	res, err := e.m.DecideApproval(ctx, ask.ID, sandboxapi.ApprovalDecision{Decision: sandboxapi.DecisionApprove})
	if err != nil || res.Approval.Status != sandboxapi.ApprovalQueued {
		t.Fatalf("approve = %+v, %v", res, err)
	}
	rule := hostPortRule(38830)
	eventually(t, "the host port rule", func() bool {
		pol, _ := e.fake.SandboxPolicy(openshell.DefaultWorkspace, sb.Name)
		if pol == nil {
			return false
		}
		r, ok := pol.NetworkPolicies[rule]
		return ok && len(r.Endpoints) == 1 && r.Endpoints[0].Host == openshellHostAlias && r.Endpoints[0].Port == 38830
	})
	eventually(t, "the approval resolved", func() bool {
		for _, ev := range e.m.ActivitySince(0, sb.Name) {
			if ev.Kind == sandboxapi.ActivityApprovalResolved && ev.ApprovalID == ask.ID && strings.Contains(ev.Message, "approved port 38830") {
				return true
			}
		}
		return false
	})
	e.m.mu.Lock()
	origin := e.m.boxes[sb.Name].rec.ApprovedRules[rule]
	e.m.mu.Unlock()
	if origin != actorOperator {
		t.Fatalf("recorded approver = %q, want the operator's", origin)
	}
	e.tel.mu.Lock()
	var approved bool
	for _, a := range e.tel.approvals {
		approved = approved || (a.ApprovalID == ask.ID && a.Stage == audit.SandboxApprovalResolved && a.Result == audit.SandboxApprovalApproved)
	}
	e.tel.mu.Unlock()
	if !approved {
		t.Fatal("no resolved approval record")
	}
	// Enforcement keeps the user's rule.
	e.m.enforceAll(ctx)
	if pol, _ := e.fake.SandboxPolicy(openshell.DefaultWorkspace, sb.Name); pol == nil {
		t.Fatal("no policy")
	} else if _, ok := pol.NetworkPolicies[rule]; !ok {
		t.Fatal("enforcement removed the approved host port")
	}
	// The next denial (the mapping republished with the port) asks again
	// no more.
	pe.push(denied)
	if asks, _ := e.m.Approvals(ctx, sb.Name); len(asks) != 0 {
		t.Fatalf("asks after the approval = %+v", asks)
	}
}

// A port the run did not declare gets one plain feed line that names the
// flag to run with, instead of a synthetic address and a raw reason.
func TestUndeclaredHostPortFeedLine(t *testing.T) {
	pe := newOwnPortsEnv(t)
	pe.push("CONFIG:PUBLISHED [INFO] Policy DNS mapped host.openshell.internal resolved=127.0.0.1 synthetic=198.18.0.2 ports=18971,18972 mapping_id=m1")
	pe.push("NET:OPEN [MED] DENIED /usr/bin/curl(0) -> 198.18.0.2:38590 [reason:transparent_tcp_mapping_denied]")
	pe.push("NET:OPEN [MED] DENIED /usr/bin/curl(0) -> host.openshell.internal:38590 [reason:transparent_tcp_mapping_denied]")
	got := pe.blocks()
	if len(got) != 1 || got[0].Host != openshellHostAlias || got[0].Port != 38590 || got[0].Reason != sandboxapi.ReasonHostPortClosed ||
		!strings.Contains(got[0].Message, "port 38590 on this machine is closed to the sandbox") ||
		!strings.Contains(got[0].Message, "--host-port 38590") {
		t.Fatalf("feed = %+v", got)
	}
	if n := pe.blocked(); n != 2 {
		t.Fatalf("blocked = %d", n)
	}
	if asks, _ := pe.m.Approvals(context.Background(), pe.name); len(asks) != 0 {
		t.Fatalf("asks = %+v; an undeclared port does not ask", asks)
	}
}

// A declared port the organization's policy closes gets the refusal on the
// feed, and no ask.
func TestDeclaredHostPortClosedByPolicy(t *testing.T) {
	e := newEnv(t, nil)
	e.run()
	sb := e.create(sandboxapi.CreateRequest{Name: "hpadmin", HostPorts: []int{38830}})
	e.watch.waitStarted(t, sb.Name)
	e.setConfig(func(c *config.Config) { c.OpenShell.Admin.AllowHostPorts = boolPtr(false) })
	e.m.refreshEgress()
	pe := &ownPortsEnv{harnessEnv: e, name: sb.Name}
	pe.push("NET:OPEN [MED] DENIED /usr/bin/curl(0) -> host.openshell.internal:38830 [reason:transparent_tcp_mapping_denied]")
	got := pe.blocks()
	if len(got) != 1 || got[0].Reason != sandboxapi.ReasonHostPortClosed || !strings.Contains(got[0].Message, "does not open port 38830") {
		t.Fatalf("feed = %+v", got)
	}
	if asks, _ := e.m.Approvals(context.Background(), sb.Name); len(asks) != 0 {
		t.Fatalf("asks = %+v", asks)
	}
}

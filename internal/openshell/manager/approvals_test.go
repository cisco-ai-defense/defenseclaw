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
	"slices"
	"strings"
	"testing"

	"github.com/NVIDIA/OpenShell/sdk/go/openshell/v1/types"

	"github.com/defenseclaw/defenseclaw/internal/audit"
	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/openshell"
	"github.com/defenseclaw/defenseclaw/internal/openshell/sandboxapi"
	"github.com/defenseclaw/defenseclaw/internal/openshell/stream"
)

func boolPtr(v bool) *bool { return &v }

func chunk(rule, host string, port uint32) types.PolicyChunk {
	return types.PolicyChunk{
		RuleName: rule, ReviewToken: "rt-" + rule, Binary: "/usr/bin/curl",
		ProposedRule: &types.NetworkPolicyRule{
			Name:      rule,
			Endpoints: []types.PolicyNetworkEndpoint{{Host: host, Port: port, Protocol: "rest"}},
			Binaries:  []types.PolicyNetworkBinary{{Path: "/usr/bin/curl"}},
		},
	}
}

func chunkStatus(e *harnessEnv, sandbox, id string) string {
	c, _ := e.fake.DraftChunk(openshell.DefaultWorkspace, sandbox, id)
	return c.Status
}

func TestTriageDecidesProposals(t *testing.T) {
	e := newEnv(t, nil)
	e.run()
	sb := e.create(sandboxapi.CreateRequest{Name: "tribox"})
	e.watch.waitStarted(t, sb.Name)
	ok := e.fake.AddDraftChunk(openshell.DefaultWorkspace, sb.Name, chunk("allow_registry", "registry.example.org", 443))
	bad := e.fake.AddDraftChunk(openshell.DefaultWorkspace, sb.Name, chunk("allow_webhook", "webhook.site", 443))
	door := e.fake.AddDraftChunk(openshell.DefaultWorkspace, sb.Name, chunk("allow_pg", "host.openshell.internal", 5432))
	e.watch.push(t, sb.Name, stream.Event{Kind: stream.KindDraft, Draft: &stream.DraftUpdate{NewChunks: 3}})

	eventually(t, "automatic approval", func() bool { return chunkStatus(e, sb.Name, ok) == "approved" })
	if s := chunkStatus(e, sb.Name, bad); s != "rejected" {
		t.Fatalf("blocklisted proposal = %s", s)
	}
	if s := chunkStatus(e, sb.Name, door); s != "pending" {
		t.Fatalf("host-port proposal = %s", s)
	}
	asks, err := e.m.Approvals(context.Background(), "")
	if err != nil || len(asks) != 1 || asks[0].Kind != sandboxapi.ApprovalKindHostPort || asks[0].Port != 5432 || !asks[0].Risky {
		t.Fatalf("asks = %+v, %v", asks, err)
	}
	got, _ := e.m.Get(context.Background(), sb.Name)
	if got.PendingApprovals != 1 {
		t.Fatalf("pending approvals = %d", got.PendingApprovals)
	}

	// A repeated notification does not decide the same chunks twice.
	e.watch.push(t, sb.Name, stream.Event{Kind: stream.KindDraft})

	// The operator approves the host port once.
	res, err := e.m.DecideApproval(context.Background(), asks[0].ID, sandboxapi.ApprovalDecision{Decision: "approve"})
	if err != nil || res.Approval.Status != sandboxapi.ApprovalQueued {
		t.Fatalf("approve = %+v, %v", res, err)
	}
	eventually(t, "operator approval", func() bool { return chunkStatus(e, sb.Name, door) == "approved" })
	if _, err := e.m.DecideApproval(context.Background(), asks[0].ID, sandboxapi.ApprovalDecision{Decision: "approve"}); !sandboxapi.IsCode(err, sandboxapi.CodeConflict) {
		t.Fatalf("second decision: %v", err)
	}

	// Telemetry: requested for all three, resolved approved (automatic and
	// operator) and denied (policy), plus rule_add policy records.
	eventually(t, "approval telemetry", func() bool {
		e.tel.mu.Lock()
		defer e.tel.mu.Unlock()
		var auto, op, denied bool
		for _, a := range e.tel.approvals {
			if a.Stage != audit.SandboxApprovalResolved {
				continue
			}
			auto = auto || (a.Result == audit.SandboxApprovalApproved && a.ActorType == audit.SandboxApprovalByAutomatic)
			op = op || (a.Result == audit.SandboxApprovalApproved && a.ActorType == audit.SandboxApprovalByOperator)
			denied = denied || (a.Result == audit.SandboxApprovalDenied && a.ActorType == audit.SandboxApprovalByPolicy)
		}
		var rules int
		for _, p := range e.tel.policy {
			if p.Operation == audit.SandboxPolicyRuleAdd {
				rules++
			}
		}
		return auto && op && denied && rules == 2
	})

	// The feed shows the block and the ask.
	var kinds []string
	for _, ev := range e.m.ActivitySince(0, sb.Name) {
		kinds = append(kinds, ev.Kind)
	}
	for _, want := range []string{sandboxapi.ActivityEgressBlocked, sandboxapi.ActivityApprovalRequested, sandboxapi.ActivityApprovalResolved} {
		if !slices.Contains(kinds, want) {
			t.Fatalf("feed kinds = %v, missing %s", kinds, want)
		}
	}
}

func TestApprovalRejectAlwaysPersists(t *testing.T) {
	e := newEnv(t, func(c *config.Config) { c.OpenShell.Profile = config.OpenShellProfileBalanced })
	e.run()
	sb := e.create(sandboxapi.CreateRequest{Name: "askbox"})
	e.watch.waitStarted(t, sb.Name)
	id1 := e.fake.AddDraftChunk(openshell.DefaultWorkspace, sb.Name, chunk("allow_a", "a.example.org", 443))
	id2 := e.fake.AddDraftChunk(openshell.DefaultWorkspace, sb.Name, chunk("allow_b", "b.example.org", 443))
	e.watch.push(t, sb.Name, stream.Event{Kind: stream.KindDraft})
	var asks []sandboxapi.Approval
	eventually(t, "two asks", func() bool {
		asks, _ = e.m.Approvals(context.Background(), sb.Name)
		return len(asks) == 2
	})
	byHost := map[string]string{}
	for _, a := range asks {
		byHost[a.Host] = a.ID
		if !strings.Contains(a.Reason, "allowlist") {
			t.Fatalf("ask reason = %q", a.Reason)
		}
	}
	if _, err := e.m.DecideApproval(context.Background(), byHost["a.example.org"], sandboxapi.ApprovalDecision{Decision: "reject", Always: true}); err != nil {
		t.Fatal(err)
	}
	if s := chunkStatus(e, sb.Name, id1); s != "rejected" {
		t.Fatalf("rejected chunk = %s", s)
	}
	res, err := e.m.DecideApproval(context.Background(), byHost["b.example.org"], sandboxapi.ApprovalDecision{Decision: "approve", Always: true})
	if err != nil || !res.Persisted {
		t.Fatalf("approve always = %+v, %v", res, err)
	}
	eventually(t, "approval applied", func() bool { return chunkStatus(e, sb.Name, id2) == "approved" })
	if !slices.Equal(e.persist.block, []string{"a.example.org"}) || !slices.Equal(e.persist.allow, []string{"b.example.org"}) {
		t.Fatalf("persisted allow %v block %v", e.persist.allow, e.persist.block)
	}
	if _, err := e.m.DecideApproval(context.Background(), "ap_missing", sandboxapi.ApprovalDecision{Decision: "approve"}); !sandboxapi.IsCode(err, sandboxapi.CodeNotFound) {
		t.Fatalf("unknown id: %v", err)
	}
}

func TestApprovalAdminDenials(t *testing.T) {
	e := newEnv(t, func(c *config.Config) { c.OpenShell.Profile = config.OpenShellProfileBalanced })
	e.run()
	sb := e.create(sandboxapi.CreateRequest{Name: "denybox"})
	e.watch.waitStarted(t, sb.Name)
	e.fake.AddDraftChunk(openshell.DefaultWorkspace, sb.Name, chunk("allow_a", "a.example.org", 443))
	e.watch.push(t, sb.Name, stream.Event{Kind: stream.KindDraft})
	var asks []sandboxapi.Approval
	eventually(t, "ask", func() bool {
		asks, _ = e.m.Approvals(context.Background(), sb.Name)
		return len(asks) == 1
	})
	// The administrator forbids unblocking after the ask was queued.
	e.setConfig(func(c *config.Config) { c.OpenShell.Admin.AllowUnblock = boolPtr(false) })
	_, err := e.m.DecideApproval(context.Background(), asks[0].ID, sandboxapi.ApprovalDecision{Decision: "approve", Always: true})
	apiErr := wantCode(t, err, sandboxapi.CodeAdminViolation)
	if !strings.Contains(apiErr.Message, sandboxapi.AdminMessage) {
		t.Fatalf("message = %q", apiErr.Message)
	}
	if len(e.persist.allow) != 0 {
		t.Fatal("refused decision was persisted")
	}
	// Approving once is still allowed.
	if _, err := e.m.DecideApproval(context.Background(), asks[0].ID, sandboxapi.ApprovalDecision{Decision: "approve"}); err != nil {
		t.Fatalf("approve once: %v", err)
	}
	var adminHealth bool
	for _, h := range e.tel.health {
		adminHealth = adminHealth || h.ErrorCode == "OPENSHELL_ADMIN_VIOLATION"
	}
	if !adminHealth {
		t.Fatal("admin violation not logged")
	}
}

func TestHostPortApproveAlwaysRefused(t *testing.T) {
	e := newEnv(t, nil)
	e.run()
	sb := e.create(sandboxapi.CreateRequest{Name: "hpbox"})
	e.watch.waitStarted(t, sb.Name)
	e.fake.AddDraftChunk(openshell.DefaultWorkspace, sb.Name, chunk("allow_pg", "host.openshell.internal", 5432))
	e.watch.push(t, sb.Name, stream.Event{Kind: stream.KindDraft})
	var asks []sandboxapi.Approval
	eventually(t, "ask", func() bool {
		asks, _ = e.m.Approvals(context.Background(), sb.Name)
		return len(asks) == 1
	})
	if _, err := e.m.DecideApproval(context.Background(), asks[0].ID, sandboxapi.ApprovalDecision{Decision: "approve", Always: true}); !sandboxapi.IsCode(err, sandboxapi.CodeInvalid) {
		t.Fatalf("approve always host port: %v", err)
	}
}

func TestDeleteDropsApprovals(t *testing.T) {
	e := newEnv(t, nil)
	e.run()
	sb := e.create(sandboxapi.CreateRequest{Name: "dropbox"})
	e.watch.waitStarted(t, sb.Name)
	e.fake.AddDraftChunk(openshell.DefaultWorkspace, sb.Name, chunk("allow_pg", "host.openshell.internal", 5432))
	e.watch.push(t, sb.Name, stream.Event{Kind: stream.KindDraft})
	eventually(t, "ask", func() bool {
		asks, _ := e.m.Approvals(context.Background(), "")
		return len(asks) == 1
	})
	if _, err := e.m.Delete(context.Background(), sb.Name, sandboxapi.DeleteRequest{}); err != nil {
		t.Fatal(err)
	}
	if asks, _ := e.m.Approvals(context.Background(), ""); len(asks) != 0 {
		t.Fatalf("asks left: %v", asks)
	}
}

func TestProposalFloodsCollapse(t *testing.T) {
	e := newEnv(t, nil)
	e.run()
	sb := e.create(sandboxapi.CreateRequest{Name: "floodbox"})
	e.watch.waitStarted(t, sb.Name)
	first := e.fake.AddDraftChunk(openshell.DefaultWorkspace, sb.Name, chunk("allow_pg", "host.openshell.internal", 5432))
	e.fake.AddDraftChunk(openshell.DefaultWorkspace, sb.Name, chunk("allow_hook", "webhook.site", 443))
	e.watch.push(t, sb.Name, stream.Event{Kind: stream.KindDraft})
	eventually(t, "first ask", func() bool {
		asks, _ := e.m.Approvals(context.Background(), sb.Name)
		return len(asks) == 1
	})
	second := e.fake.AddDraftChunk(openshell.DefaultWorkspace, sb.Name, chunk("allow_pg2", "host.openshell.internal", 5432))
	again := e.fake.AddDraftChunk(openshell.DefaultWorkspace, sb.Name, chunk("allow_hook2", "webhook.site", 443))
	e.watch.push(t, sb.Name, stream.Event{Kind: stream.KindDraft})
	eventually(t, "collapsed", func() bool { return chunkStatus(e, sb.Name, again) == "rejected" })
	asks, _ := e.m.Approvals(context.Background(), sb.Name)
	if len(asks) != 1 || asks[0].ChunkID != second {
		t.Fatalf("asks = %+v", asks)
	}
	if s := chunkStatus(e, sb.Name, first); s != "rejected" {
		t.Fatalf("superseded chunk = %s", s)
	}
	requested := 0
	e.tel.mu.Lock()
	for _, a := range e.tel.approvals {
		if a.Stage == audit.SandboxApprovalRequested {
			requested++
		}
	}
	e.tel.mu.Unlock()
	if requested != 2 {
		t.Fatalf("requested records = %d, want one per destination", requested)
	}
	// Approving the collapsed ask approves the newest chunk.
	if _, err := e.m.DecideApproval(context.Background(), asks[0].ID, sandboxapi.ApprovalDecision{Decision: "approve"}); err != nil {
		t.Fatal(err)
	}
	eventually(t, "newest chunk approved", func() bool { return chunkStatus(e, sb.Name, second) == "approved" })
}

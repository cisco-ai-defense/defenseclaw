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
	"fmt"
	"net"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/NVIDIA/OpenShell/sdk/go/openshell/v1/types"

	"github.com/defenseclaw/defenseclaw/internal/audit"
	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/gateway/connector"
	"github.com/defenseclaw/defenseclaw/internal/openshell"
	"github.com/defenseclaw/defenseclaw/internal/openshell/harness"
	"github.com/defenseclaw/defenseclaw/internal/openshell/ocsf"
	"github.com/defenseclaw/defenseclaw/internal/openshell/sandboxapi"
	"github.com/defenseclaw/defenseclaw/internal/openshell/stream"
)

func boolPtr(v bool) *bool { return &v }

// chunk is a draft chunk in the shape OpenShell 0.1.1 drafts for a denied
// direct connection (measured on the host: allow_<host>_<port>, no
// protocol, advisor provenance).
func chunk(rule, host string, port uint32) types.PolicyChunk {
	return types.PolicyChunk{
		RuleName: rule, ReviewToken: "rt-" + rule, Binary: "/usr/bin/curl",
		ProposedRule: &types.NetworkPolicyRule{
			Name:      rule,
			Endpoints: []types.PolicyNetworkEndpoint{{Host: host, Port: port, Ports: []uint32{port}, AdvisorProposed: true}},
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

// TestTriageRejectsHarnessFetches pins that a Codex sandbox's own startup
// tip download, which Codex makes around the proxy, is rejected with the
// reason on the feed instead of approved on the open network (the direct
// rule and the policy reload that closes the session's connections), while
// the same destination from the agent's curl is still approved.
func TestTriageRejectsHarnessFetches(t *testing.T) {
	e := newEnv(t, nil)
	e.images.rec.HarnessVersion = "0.146.0"
	e.images.rec.HookContract = connector.ResolveSandboxHookContract("codex", "0.146.0").Contract.ContractID
	e.run()
	sb := e.create(sandboxapi.CreateRequest{Name: "fetchbox", Harness: "codex"})
	e.watch.waitStarted(t, sb.Name)
	codex := harness.Codex.InstallRoot() + "/lib/node_modules/@openai/codex/node_modules/@openai/codex-linux-arm64/vendor/aarch64-unknown-linux-musl/bin/codex"
	// OpenShell's two denials of the download (the lines 0.1.1 printed): the
	// DNS refusal names no binary, the connection names Codex's. Neither
	// counts as a blocked site or shows on the feed; a curl's does.
	for _, line := range []string{
		"NET:REFUSE [MED] DENIED raw.githubusercontent.com [reason:policy_dns_ineligible]",
		"NET:OPEN [MED] DENIED " + codex + "(0) -> raw.githubusercontent.com:443 [reason:transparent_tcp_policy_denied]",
	} {
		rec, err := ocsf.Parse(line)
		if err != nil {
			t.Fatal(err)
		}
		e.m.ocsfEvent(context.Background(), e.m.boxes[sb.Name], rec, time.Now())
	}
	if got, _ := e.m.Get(context.Background(), sb.Name); got.Egress.Blocked != 0 {
		t.Fatalf("the tip download counted as %d blocked sites", got.Egress.Blocked)
	}
	for _, ev := range e.m.ActivitySince(0, sb.Name) {
		if ev.Kind == sandboxapi.ActivityEgressBlocked {
			t.Fatalf("the tip download's denial is on the feed: %+v", ev)
		}
	}
	tip := chunk("allow_raw_githubusercontent_com_443", "raw.githubusercontent.com", 443)
	tip.Binary = codex
	tip.ProposedRule.Binaries = []types.PolicyNetworkBinary{{Path: codex}}
	fetch := e.fake.AddDraftChunk(openshell.DefaultWorkspace, sb.Name, tip)
	e.watch.push(t, sb.Name, stream.Event{Kind: stream.KindDraft, Draft: &stream.DraftUpdate{NewChunks: 1}})
	eventually(t, "the tip download's rejection", func() bool { return chunkStatus(e, sb.Name, fetch) == "rejected" })
	var msg string
	for _, ev := range e.m.ActivitySince(0, sb.Name) {
		if ev.Kind == sandboxapi.ActivityEgressBlocked && ev.Reason == "harness_background_fetch" {
			msg = ev.Message
		}
	}
	if !strings.Contains(msg, "Codex's startup tip download") || !strings.Contains(msg, "opens no direct rule") {
		t.Fatalf("feed message = %q", msg)
	}

	rec, err := ocsf.Parse("NET:OPEN [MED] DENIED /usr/bin/curl(9) -> raw.githubusercontent.com:443 [reason:transparent_tcp_policy_denied]")
	if err != nil {
		t.Fatal(err)
	}
	e.m.ocsfEvent(context.Background(), e.m.boxes[sb.Name], rec, time.Now())
	if got, _ := e.m.Get(context.Background(), sb.Name); got.Egress.Blocked != 1 {
		t.Fatalf("a curl's denial counted as %d blocked sites, want 1", got.Egress.Blocked)
	}
	curl := e.fake.AddDraftChunk(openshell.DefaultWorkspace, sb.Name, chunk("allow_raw_githubusercontent_com_443", "raw.githubusercontent.com", 443))
	e.watch.push(t, sb.Name, stream.Event{Kind: stream.KindDraft, Draft: &stream.DraftUpdate{NewChunks: 1}})
	eventually(t, "the agent's approval", func() bool { return chunkStatus(e, sb.Name, curl) == "approved" })
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
	// The refusal is a no-change policy record of the sandbox, not a
	// degraded subsystem: a refused request degrades nothing.
	e.tel.mu.Lock()
	defer e.tel.mu.Unlock()
	for _, h := range e.tel.health {
		if h.ErrorCode == "openshell_admin_violation" {
			t.Fatalf("a refused request was recorded as degraded subsystem health: %+v", h)
		}
	}
	var refused bool
	for _, p := range e.tel.policy {
		refused = refused || (p.Operation == audit.SandboxPolicyRuleAdd && p.NoChange && p.Reason == policyReasonAdminRefused &&
			p.Target == "a.example.org" && p.Sandbox.Name == sb.Name)
	}
	if !refused {
		t.Fatal("the admin refusal has no policy record")
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

// TestPruneKeepsUnresolvedApprovals pins that the hourly prune forgets only
// old resolved asks. An ask an operator decision is being applied to has no
// resolvedAt yet; pruning it would orphan the decision in flight.
func TestPruneKeepsUnresolvedApprovals(t *testing.T) {
	e := newEnv(t, nil)
	now := time.Date(2026, 9, 27, 12, 0, 0, 0, time.UTC)
	e.m.now = func() time.Time { return now }
	old, recent := now.Add(-2*time.Hour), now.Add(-time.Minute)
	for _, tc := range []struct {
		status   string
		resolved time.Time
		kept     bool
	}{
		{sandboxapi.ApprovalPending, time.Time{}, true},
		{approvalDeciding, time.Time{}, true},
		{sandboxapi.ApprovalQueued, time.Time{}, true},
		{sandboxapi.ApprovalRejected, recent, true},
		{sandboxapi.ApprovalRejected, old, false},
		{sandboxapi.ApprovalApproved, old, false},
	} {
		id := "ap_" + tc.status + "_" + tc.resolved.Format("1504")
		e.m.mu.Lock()
		e.m.approvals[id] = &approval{id: id, sandbox: "s", status: tc.status, createdAt: old, resolvedAt: tc.resolved}
		e.m.mu.Unlock()
		e.m.pruneApprovals()
		e.m.mu.Lock()
		_, kept := e.m.approvals[id]
		e.m.mu.Unlock()
		if kept != tc.kept {
			t.Errorf("%s ask resolved at %v: kept = %t, want %t", tc.status, tc.resolved, kept, tc.kept)
		}
	}
}

// TestDeniedConnectionTriggersTriage pins that a proposal is decided after
// OpenShell denies a direct connection even when no draft notification
// arrives on the stream.
func TestDeniedConnectionTriggersTriage(t *testing.T) {
	saved := triageDelay
	triageDelay = 10 * time.Millisecond
	t.Cleanup(func() { triageDelay = saved })
	e := newEnv(t, nil)
	e.run()
	sb := e.create(sandboxapi.CreateRequest{Name: "denybox2"})
	e.watch.waitStarted(t, sb.Name)
	id := e.fake.AddDraftChunk(openshell.DefaultWorkspace, sb.Name, chunk("allow_example", "www.example.com", 443))
	line := "NET:OPEN [MED] DENIED /usr/bin/curl(3) -> www.example.com:443 [reason:transparent_tcp_policy_denied]"
	rec, err := ocsf.Parse(line)
	if err != nil {
		t.Fatal(err)
	}
	e.watch.push(t, sb.Name, stream.Event{Kind: stream.KindLog, Log: &stream.Log{Message: line, OCSF: &rec}})
	eventually(t, "triaged without a draft event", func() bool { return chunkStatus(e, sb.Name, id) == "approved" })
}

func TestTriageSweep(t *testing.T) {
	e := newEnv(t, nil)
	e.m.opts.TriageInterval = 20 * time.Millisecond
	e.run()
	sb := e.create(sandboxapi.CreateRequest{Name: "sweepbox"})
	id := e.fake.AddDraftChunk(openshell.DefaultWorkspace, sb.Name, chunk("allow_example", "www.example.com", 443))
	eventually(t, "sweep", func() bool { return chunkStatus(e, sb.Name, id) == "approved" })
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
	// OpenShell drafts the same rule again (a retried connection).
	second := e.fake.AddDraftChunk(openshell.DefaultWorkspace, sb.Name, chunk("allow_pg", "host.openshell.internal", 5432))
	again := e.fake.AddDraftChunk(openshell.DefaultWorkspace, sb.Name, chunk("allow_hook", "webhook.site", 443))
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

func addChunk(e *harnessEnv, sandbox string, c types.PolicyChunk) string {
	return e.fake.AddDraftChunk(openshell.DefaultWorkspace, sandbox, c)
}

func waitAsks(t *testing.T, e *harnessEnv, sandbox string, n int) []sandboxapi.Approval {
	t.Helper()
	var asks []sandboxapi.Approval
	eventually(t, fmt.Sprintf("%d asks", n), func() bool {
		asks, _ = e.m.Approvals(context.Background(), sandbox)
		return len(asks) == n
	})
	return asks
}

// TestApprovalsUseLiveReviewTokens pins that approvals decided before
// another policy change still land: OpenShell's review token changes with
// the policy, so the manager reads a fresh one when it applies.
func TestApprovalsUseLiveReviewTokens(t *testing.T) {
	e := newEnv(t, func(c *config.Config) { c.OpenShell.Approvals.DebounceMs = 150 })
	e.run()
	sb := e.create(sandboxapi.CreateRequest{Name: "tokbox"})
	e.watch.waitStarted(t, sb.Name)

	// An ask waits for the user while an automatic approval lands.
	door := addChunk(e, sb.Name, chunk("allow_host_openshell_internal_5432", "host.openshell.internal", 5432))
	e.watch.push(t, sb.Name, stream.Event{Kind: stream.KindDraft})
	asks := waitAsks(t, e, sb.Name, 1)
	auto := addChunk(e, sb.Name, chunk("allow_registry_example_org_443", "registry.example.org", 443))
	e.watch.push(t, sb.Name, stream.Event{Kind: stream.KindDraft})
	// While the automatic approval is debounced, another client changes
	// the policy, so the token triage read is stale by the time it applies.
	other := addChunk(e, sb.Name, chunk("allow_other_example_org_443", "other.example.org", 443))
	eventually(t, "automatic approval queued", func() bool { return e.m.batcher.Pending(sb.Name) == 1 })
	live, _ := e.fake.DraftChunk(openshell.DefaultWorkspace, sb.Name, other)
	if _, err := e.client.ApproveDraftChunk(context.Background(), sb.Name, other, live.ReviewToken); err != nil {
		t.Fatal(err)
	}
	eventually(t, "automatic approval applied", func() bool { return chunkStatus(e, sb.Name, auto) == "approved" })

	// The ask's token is stale twice over; the operator's approval lands.
	if _, err := e.m.DecideApproval(context.Background(), asks[0].ID, sandboxapi.ApprovalDecision{Decision: "approve"}); err != nil {
		t.Fatal(err)
	}
	eventually(t, "operator approval applied", func() bool { return chunkStatus(e, sb.Name, door) == "approved" })
	eventually(t, "both approvals recorded as approved", func() bool {
		e.m.mu.Lock()
		defer e.m.mu.Unlock()
		for _, a := range e.m.approvals {
			if a.status != sandboxapi.ApprovalApproved {
				return false
			}
		}
		return len(e.m.approvals) == 2
	})
	eventually(t, "rule_add records for both", func() bool {
		var rules []string
		e.tel.mu.Lock()
		for _, p := range e.tel.policy {
			if p.Operation == audit.SandboxPolicyRuleAdd {
				rules = append(rules, p.Target)
			}
		}
		e.tel.mu.Unlock()
		return slices.Contains(rules, "registry.example.org") && slices.Contains(rules, "host.openshell.internal")
	})
}

// TestApprovalShowsAndChecksTheWholeProposal pins that an ask names every
// endpoint, allowed IP and binary, and that the decision re-checks all of
// them against the current policy.
func TestApprovalShowsAndChecksTheWholeProposal(t *testing.T) {
	e := newEnv(t, nil)
	e.run()
	sb := e.create(sandboxapi.CreateRequest{Name: "wholebox"})
	e.watch.waitStarted(t, sb.Name)
	// A proposal naming a second host is rejected: the ask would show the
	// user one destination while approving opens both.
	two := chunk("allow_host_openshell_internal_3000", "host.openshell.internal", 3000)
	two.ProposedRule.Endpoints = append(two.ProposedRule.Endpoints, types.PolicyNetworkEndpoint{Host: "10.1.2.3", Port: 443})
	twoID := addChunk(e, sb.Name, two)
	e.watch.push(t, sb.Name, stream.Event{Kind: stream.KindDraft})
	eventually(t, "the two-host proposal rejected", func() bool { return chunkStatus(e, sb.Name, twoID) == "rejected" })

	c := chunk("allow_host_openshell_internal_3000", "host.openshell.internal", 3000)
	c.ProposedRule.Endpoints[0].Ports = []uint32{3000, 22}
	id := addChunk(e, sb.Name, c)
	e.watch.push(t, sb.Name, stream.Event{Kind: stream.KindDraft})
	asks := waitAsks(t, e, sb.Name, 1)
	got := asks[0]
	want := []sandboxapi.ApprovalEndpoint{{Host: "host.openshell.internal", Port: 3000}, {Host: "host.openshell.internal", Port: 22}}
	if !slices.Equal(got.Endpoints, want) || got.RuleName != "allow_host_openshell_internal_3000" || !slices.Equal(got.Binaries, []string{"/usr/bin/curl"}) {
		t.Fatalf("ask = %+v", got)
	}
	// The ask names every port approving opens.
	if !strings.Contains(got.Reason, "3000, 22") {
		t.Fatalf("ask reason = %q, want both ports", got.Reason)
	}
	// The whole proposal is judged again at the decision.
	e.setConfig(func(c *config.Config) { c.OpenShell.Admin.AllowHostPorts = boolPtr(false) })
	_, err := e.m.DecideApproval(context.Background(), got.ID, sandboxapi.ApprovalDecision{Decision: "approve"})
	wantCode(t, err, sandboxapi.CodeAdminViolation)
	if s := chunkStatus(e, sb.Name, id); s != "pending" {
		t.Fatalf("refused proposal = %s", s)
	}
	// Always is refused for proposals that reach this machine.
	e.setConfig(func(c *config.Config) { c.OpenShell.Admin.AllowHostPorts = nil })
	if _, err := e.m.DecideApproval(context.Background(), got.ID, sandboxapi.ApprovalDecision{Decision: "approve", Always: true}); !sandboxapi.IsCode(err, sandboxapi.CodeInvalid) {
		t.Fatalf("approve always: %v", err)
	}
}

// TestPrivateAllowedIPsAsk pins that allowed_ips reaching the user's network
// ask instead of being approved automatically, and that the decision checks
// them against openshell.admin.allow_unblock.
func TestPrivateAllowedIPsAsk(t *testing.T) {
	e := newEnv(t, nil)
	e.run()
	sb := e.create(sandboxapi.CreateRequest{Name: "ipbox"})
	e.watch.waitStarted(t, sb.Name)
	c := chunk("allow_my_cdn_attacker_example_443", "my-cdn.attacker.example", 443)
	c.ProposedRule.Endpoints[0].AllowedIPs = []string{"10.0.0.0/8"}
	id := addChunk(e, sb.Name, c)
	e.watch.push(t, sb.Name, stream.Event{Kind: stream.KindDraft})
	asks := waitAsks(t, e, sb.Name, 1)
	if s := chunkStatus(e, sb.Name, id); s != "pending" {
		t.Fatalf("private allowed_ips proposal = %s, want an ask", s)
	}
	if !asks[0].Risky || !slices.Equal(asks[0].AllowedIPs, []string{"10.0.0.0/8"}) || !strings.Contains(asks[0].Reason, "10.0.0.0/8") {
		t.Fatalf("ask = %+v", asks[0])
	}
	e.setConfig(func(c *config.Config) { c.OpenShell.Admin.AllowUnblock = boolPtr(false) })
	_, err := e.m.DecideApproval(context.Background(), asks[0].ID, sandboxapi.ApprovalDecision{Decision: "approve"})
	wantCode(t, err, sandboxapi.CodeAdminViolation)
}

// TestChangedProposalDoesNotJoinAnAsk pins that a newer proposal with
// different content (an extra port) gets its own ask instead of replacing
// the one the user is reading.
func TestChangedProposalDoesNotJoinAnAsk(t *testing.T) {
	e := newEnv(t, nil)
	e.run()
	sb := e.create(sandboxapi.CreateRequest{Name: "swapbox"})
	e.watch.waitStarted(t, sb.Name)
	first := addChunk(e, sb.Name, chunk("allow_host_openshell_internal_3000", "host.openshell.internal", 3000))
	e.watch.push(t, sb.Name, stream.Event{Kind: stream.KindDraft})
	asks := waitAsks(t, e, sb.Name, 1)
	read := asks[0]
	swapped := chunk("allow_host_openshell_internal_3000", "host.openshell.internal", 3000)
	swapped.ProposedRule.Endpoints[0].Ports = []uint32{3000, 22}
	second := addChunk(e, sb.Name, swapped)
	e.watch.push(t, sb.Name, stream.Event{Kind: stream.KindDraft})
	waitAsks(t, e, sb.Name, 2)
	if _, err := e.m.DecideApproval(context.Background(), read.ID, sandboxapi.ApprovalDecision{Decision: "approve"}); err != nil {
		t.Fatal(err)
	}
	eventually(t, "the proposal the user read applied", func() bool { return chunkStatus(e, sb.Name, first) == "approved" })
	if s := chunkStatus(e, sb.Name, second); s != "pending" {
		t.Fatalf("the swapped-in proposal = %s", s)
	}
	policy, _ := e.fake.SandboxPolicy(openshell.DefaultWorkspace, sb.Name)
	for _, ep := range policy.NetworkPolicies["allow_host_openshell_internal_3000"].Endpoints {
		if slices.Contains(ep.Ports, 22) || ep.Port == 22 {
			t.Fatalf("port 22 was opened: %+v", ep)
		}
	}
}

// TestProposalFloodIsRateLimited pins the flood limits: automatic approvals
// per window, then asks, and the seen-chunk set tracking only pending
// chunks.
func TestProposalFloodIsRateLimited(t *testing.T) {
	e := newEnv(t, nil)
	e.run()
	sb := e.create(sandboxapi.CreateRequest{Name: "ratebox"})
	e.watch.waitStarted(t, sb.Name)
	total := autoApproveBurst + 5
	for i := 0; i < total; i++ {
		host := fmt.Sprintf("h%d.example.org", i)
		addChunk(e, sb.Name, chunk(fmt.Sprintf("allow_h%d_example_org_443", i), host, 443))
	}
	e.watch.push(t, sb.Name, stream.Event{Kind: stream.KindDraft})
	asks := waitAsks(t, e, sb.Name, total-autoApproveBurst)
	for _, a := range asks {
		if !strings.Contains(a.Reason, "many new destinations") {
			t.Fatalf("ask = %+v", a)
		}
	}
	eventually(t, "automatic approvals applied", func() bool {
		d, _ := e.client.GetDraft(context.Background(), sb.Name, "approved")
		return d != nil && len(d.Chunks) == autoApproveBurst
	})
	// A later poll forgets the decided chunks.
	e.m.triageSandbox(context.Background(), e.m.boxes[sb.Name])
	e.m.mu.Lock()
	seen := len(e.m.boxes[sb.Name].seenChunks)
	e.m.mu.Unlock()
	if seen != total-autoApproveBurst {
		t.Fatalf("seen chunks = %d, want the %d still pending", seen, total-autoApproveBurst)
	}
}

// TestProposalFloodLimits pins the per-session rule ceiling and that a flood
// of rejected proposals is rejected quietly after the first ones.
func TestProposalFloodLimits(t *testing.T) {
	e := newEnv(t, nil)
	e.run()
	sb := e.create(sandboxapi.CreateRequest{Name: "limitbox"})
	e.watch.waitStarted(t, sb.Name)
	total := rejectBurst + 5
	var ids []string
	for i := 0; i < total; i++ {
		ids = append(ids, addChunk(e, sb.Name, chunk(fmt.Sprintf("allow_x%d_pastebin_com_443", i), fmt.Sprintf("x%d.pastebin.com", i), 443)))
	}
	e.watch.push(t, sb.Name, stream.Event{Kind: stream.KindDraft})
	eventually(t, "all rejected", func() bool {
		for _, id := range ids {
			if chunkStatus(e, sb.Name, id) != "rejected" {
				return false
			}
		}
		return true
	})
	var blocked, notices int
	for _, ev := range e.m.ActivitySince(0, sb.Name) {
		if ev.Kind == sandboxapi.ActivityEgressBlocked {
			if ev.Reason == "rate_limited" {
				notices++
			} else {
				blocked++
			}
		}
	}
	if blocked != rejectBurst || notices != 1 {
		t.Fatalf("feed: %d blocked, %d notices; want %d and one", blocked, notices, rejectBurst)
	}

	// The session's rule budget is spent: new proposals are rejected.
	e.m.mu.Lock()
	e.m.boxes[sb.Name].rulesAdded = maxRulesPerSession
	e.m.mu.Unlock()
	id := addChunk(e, sb.Name, chunk("allow_more_example_org_443", "more.example.org", 443))
	e.watch.push(t, sb.Name, stream.Event{Kind: stream.KindDraft})
	eventually(t, "rule limit", func() bool { return chunkStatus(e, sb.Name, id) == "rejected" })
	c, _ := e.fake.DraftChunk(openshell.DefaultWorkspace, sb.Name, id)
	if !strings.Contains(c.RejectionReason, "rules this session") {
		t.Fatalf("rejection = %q", c.RejectionReason)
	}
	// A restart starts a new budget.
	if _, err := e.m.Stop(context.Background(), sb.Name); err != nil {
		t.Fatal(err)
	}
	if _, err := e.m.Start(context.Background(), sb.Name, sandboxapi.StartRequest{}); err != nil {
		t.Fatal(err)
	}
	e.m.mu.Lock()
	spent := e.m.boxes[sb.Name].rulesAdded
	e.m.mu.Unlock()
	if spent != 0 {
		t.Fatalf("rules after a restart = %d", spent)
	}
}

// TestApprovalRecheckedAtApply pins that an approval is judged again, with
// a fresh DNS answer, right before it is applied: a name that resolved to a
// public address at triage time but to this machine by then is never
// approved, whether triage or the operator approved it.
func TestApprovalRecheckedAtApply(t *testing.T) {
	saved := triageDelay
	triageDelay = 10 * time.Millisecond
	t.Cleanup(func() { triageDelay = saved })
	e := newEnv(t, nil)
	e.run()
	sb := e.create(sandboxapi.CreateRequest{Name: "rebindbox"})
	e.watch.waitStarted(t, sb.Name)

	// Automatic approval: public at triage, loopback at apply.
	e.dns.rebindAfter("cdn.rebind.example.org", 1, "127.0.0.1")
	auto := addChunk(e, sb.Name, chunk("allow_cdn_rebind_example_org_443", "cdn.rebind.example.org", 443))
	e.watch.push(t, sb.Name, stream.Event{Kind: stream.KindDraft})
	eventually(t, "the rebound proposal rejected", func() bool { return chunkStatus(e, sb.Name, auto) == "rejected" })
	c, _ := e.fake.DraftChunk(openshell.DefaultWorkspace, sb.Name, auto)
	if !strings.Contains(c.RejectionReason, "this machine") {
		t.Fatalf("rejection = %q", c.RejectionReason)
	}

	// Operator approval of a private-network ask: private at triage and at
	// the decision, loopback at apply.
	e.dns.set("db.rebind.example.org", "10.0.0.5")
	e.dns.rebindAfter("db.rebind.example.org", 2, "127.0.0.1")
	asked := addChunk(e, sb.Name, chunk("allow_db_rebind_example_org_443", "db.rebind.example.org", 443))
	e.watch.push(t, sb.Name, stream.Event{Kind: stream.KindDraft})
	asks := waitAsks(t, e, sb.Name, 1)
	if asks[0].Host != "db.rebind.example.org" || !asks[0].Risky {
		t.Fatalf("ask = %+v", asks[0])
	}
	if _, err := e.m.DecideApproval(context.Background(), asks[0].ID, sandboxapi.ApprovalDecision{Decision: "approve"}); err != nil {
		t.Fatal(err)
	}
	eventually(t, "the operator approval refused at apply", func() bool { return chunkStatus(e, sb.Name, asked) == "rejected" })
	policy, _ := e.fake.SandboxPolicy(openshell.DefaultWorkspace, sb.Name)
	for _, rule := range []string{"allow_cdn_rebind_example_org_443", "allow_db_rebind_example_org_443"} {
		if _, ok := policy.NetworkPolicies[rule]; ok {
			t.Fatalf("rule %s reached the policy", rule)
		}
	}
	var refused bool
	for _, ev := range e.m.ActivitySince(0, sb.Name) {
		refused = refused || (ev.Kind == sandboxapi.ActivityApprovalResolved && ev.Reason == "refused_at_apply")
	}
	if !refused {
		t.Fatal("no refused_at_apply feed event")
	}
}

// TestSlowDNSDefersTriage pins that a resolver slower than the triage
// pass's budget leaves the proposal for the next poll instead of rejecting
// it as unresolvable.
func TestSlowDNSDefersTriage(t *testing.T) {
	savedDelay, savedBudget := triageDelay, triagePassBudget
	triageDelay, triagePassBudget = 20*time.Millisecond, 50*time.Millisecond
	t.Cleanup(func() { triageDelay, triagePassBudget = savedDelay, savedBudget })
	e := newEnv(t, nil)
	e.run()
	sb := e.create(sandboxapi.CreateRequest{Name: "slowbox"})
	e.watch.waitStarted(t, sb.Name)
	e.dns.setHang("slow.example.org", true)
	id := addChunk(e, sb.Name, chunk("allow_slow_example_org_443", "slow.example.org", 443))
	e.watch.push(t, sb.Name, stream.Event{Kind: stream.KindDraft})
	time.Sleep(300 * time.Millisecond)
	if s := chunkStatus(e, sb.Name, id); s != "pending" {
		t.Fatalf("proposal with a hanging lookup = %s, want it left pending", s)
	}
	e.dns.setHang("slow.example.org", false)
	eventually(t, "the deferred proposal approved", func() bool { return chunkStatus(e, sb.Name, id) == "approved" })
}

// TestReconcileRemovesRulesThatResolveToThisMachine pins that an approved
// rule whose name later resolves to this machine is removed on the next
// enforcement pass.
func TestReconcileRemovesRulesThatResolveToThisMachine(t *testing.T) {
	e := newEnv(t, nil)
	e.run()
	sb := e.create(sandboxapi.CreateRequest{Name: "laterbox"})
	e.watch.waitStarted(t, sb.Name)
	keep := addChunk(e, sb.Name, chunk("allow_keep_example_org_443", "keep.example.org", 443))
	later := addChunk(e, sb.Name, chunk("allow_later_example_org_443", "later.example.org", 443))
	e.watch.push(t, sb.Name, stream.Event{Kind: stream.KindDraft})
	eventually(t, "approvals applied", func() bool {
		return chunkStatus(e, sb.Name, keep) == "approved" && chunkStatus(e, sb.Name, later) == "approved"
	})
	e.dns.set("later.example.org", "169.254.169.254")
	e.m.enforceAll(context.Background())
	policy, _ := e.fake.SandboxPolicy(openshell.DefaultWorkspace, sb.Name)
	if _, ok := policy.NetworkPolicies["allow_later_example_org_443"]; ok {
		t.Fatal("a rule that resolves to metadata is still in the policy")
	}
	if _, ok := policy.NetworkPolicies["allow_keep_example_org_443"]; !ok {
		t.Fatal("the public rule was removed")
	}
	var fed bool
	for _, ev := range e.m.ActivitySince(0, sb.Name) {
		fed = fed || (ev.Kind == sandboxapi.ActivityEgressBlocked && ev.Reason == "resolves_to_host")
	}
	if !fed {
		t.Fatal("no feed event for the removed rule")
	}
}

// TestRemovedRulesAreAudited pins the mandatory log.policy.updated records
// of one enforcement pass that removes several approved rules, some the
// administrator now blocks and some that resolve to this machine: one
// record per rule, naming it, with a registered reason token. The
// environment's telemetry runs the production recorder, which refuses an
// upper-case reason or a comma-joined target.
func TestRemovedRulesAreAudited(t *testing.T) {
	e := newEnv(t, nil)
	e.run()
	sb := e.create(sandboxapi.CreateRequest{Name: "auditbox"})
	e.watch.waitStarted(t, sb.Name)
	rules := map[string]string{
		"allow_keep_example_org_443":   "keep.example.org",
		"allow_org1_example_org_443":   "org1.example.org",
		"allow_org2_example_org_443":   "org2.example.org",
		"allow_later1_example_org_443": "later1.example.org",
		"allow_later2_example_org_443": "later2.example.org",
	}
	var ids []string
	for rule, host := range rules {
		ids = append(ids, addChunk(e, sb.Name, chunk(rule, host, 443)))
	}
	e.watch.push(t, sb.Name, stream.Event{Kind: stream.KindDraft})
	eventually(t, "approvals applied", func() bool {
		for _, id := range ids {
			if chunkStatus(e, sb.Name, id) != "approved" {
				return false
			}
		}
		return true
	})
	e.setConfig(func(c *config.Config) {
		c.OpenShell.Admin.EgressBlock = []string{"org1.example.org", "org2.example.org"}
	})
	e.dns.set("later1.example.org", "127.0.0.1")
	e.dns.set("later2.example.org", "169.254.169.254")
	e.m.enforceAll(context.Background())

	want := map[string]string{
		"allow_org1_example_org_443":   "admin_policy",
		"allow_org2_example_org_443":   "admin_policy",
		"allow_later1_example_org_443": "rule_resolves_to_host",
		"allow_later2_example_org_443": "rule_resolves_to_host",
	}
	got := map[string]string{}
	e.tel.mu.Lock()
	for _, p := range e.tel.policy {
		if p.Operation == audit.SandboxPolicyRuleRemove {
			if p.ChangeCount != 1 || p.PolicyHash == "" {
				t.Errorf("rule_remove record %+v, want one change and the policy hash", p)
			}
			got[p.Target] = p.Reason
		}
	}
	e.tel.mu.Unlock()
	if len(got) != len(want) {
		t.Fatalf("rule_remove records = %v, want %v", got, want)
	}
	for rule, reason := range want {
		if got[rule] != reason {
			t.Fatalf("rule_remove %s reason = %q, want %q (records %v)", rule, got[rule], reason, got)
		}
	}
	if refused := e.tel.refusedRecords(); len(refused) > 0 {
		t.Fatalf("the audit recorder refused records: %v", refused)
	}
}

// TestFlakyDNSNeverRejects pins that a lookup that fails temporarily
// (SERVFAIL, a timeout) leaves a proposal pending instead of rejecting it:
// in triage the chunk waits for a later pass, and an approval the user gave
// is retried and then handed back to the user, never rejected in OpenShell.
func TestFlakyDNSNeverRejects(t *testing.T) {
	savedDelay, savedRetry := triageDelay, applyRetryDelay
	triageDelay, applyRetryDelay = 10*time.Millisecond, 10*time.Millisecond
	t.Cleanup(func() { triageDelay, applyRetryDelay = savedDelay, savedRetry })
	servfail := &net.DNSError{Err: "server misbehaving", Name: "flaky", IsTemporary: true}
	e := newEnv(t, nil)
	e.run()
	sb := e.create(sandboxapi.CreateRequest{Name: "flakybox"})
	e.watch.waitStarted(t, sb.Name)

	// Triage: the proposal waits while the resolver fails.
	e.dns.setErr("cdn.flaky.example.org", servfail)
	auto := addChunk(e, sb.Name, chunk("allow_cdn_flaky_example_org_443", "cdn.flaky.example.org", 443))
	e.m.mu.Lock()
	b := e.m.boxes[sb.Name]
	e.m.mu.Unlock()
	e.m.triageSandbox(context.Background(), b)
	e.dns.mu.Lock()
	looked := e.dns.calls["cdn.flaky.example.org."]
	e.dns.mu.Unlock()
	if looked == 0 {
		t.Fatal("the flaky name was not looked up")
	}
	_ = e.m.batcher.Drain(context.Background())
	if s := chunkStatus(e, sb.Name, auto); s != "pending" {
		t.Fatalf("proposal with a failing lookup = %s, want it left pending", s)
	}
	e.dns.setErr("cdn.flaky.example.org", nil)
	e.watch.push(t, sb.Name, stream.Event{Kind: stream.KindDraft})
	eventually(t, "the deferred proposal approved", func() bool { return chunkStatus(e, sb.Name, auto) == "approved" })

	// Apply: the user approves a private-network ask while the resolver
	// fails; the approval is retried, then comes back to the user.
	e.dns.set("db.flaky.example.org", "10.0.0.5")
	asked := addChunk(e, sb.Name, chunk("allow_db_flaky_example_org_443", "db.flaky.example.org", 443))
	e.watch.push(t, sb.Name, stream.Event{Kind: stream.KindDraft})
	asks := waitAsks(t, e, sb.Name, 1)
	e.dns.setErr("db.flaky.example.org", servfail)
	if _, err := e.m.DecideApproval(context.Background(), asks[0].ID, sandboxapi.ApprovalDecision{Decision: "approve"}); err != nil {
		t.Fatal(err)
	}
	eventually(t, "the approval handed back", func() bool {
		var back bool
		for _, ev := range e.m.ActivitySince(0, sb.Name) {
			back = back || (ev.Kind == sandboxapi.ActivityApprovalRequested && ev.ApprovalID == asks[0].ID && ev.Reason == "lookup_failed")
		}
		return back
	})
	if s := chunkStatus(e, sb.Name, asked); s != "pending" {
		t.Fatalf("approved proposal with a failing lookup = %s, want it left pending", s)
	}
	if again := waitAsks(t, e, sb.Name, 1); again[0].ID != asks[0].ID {
		t.Fatalf("asks = %+v, want the same ask back", again)
	}
	e.dns.setErr("db.flaky.example.org", nil)
	if _, err := e.m.DecideApproval(context.Background(), asks[0].ID, sandboxapi.ApprovalDecision{Decision: "approve"}); err != nil {
		t.Fatal(err)
	}
	eventually(t, "the second approval applied", func() bool { return chunkStatus(e, sb.Name, asked) == "approved" })
}

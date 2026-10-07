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
	"encoding/json"
	"fmt"
	"net"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/NVIDIA/OpenShell/sdk/go/openshell/v1/types"

	"github.com/defenseclaw/defenseclaw/internal/audit"
	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/openshell"
	"github.com/defenseclaw/defenseclaw/internal/openshell/egress"
	"github.com/defenseclaw/defenseclaw/internal/openshell/harness"
	"github.com/defenseclaw/defenseclaw/internal/openshell/nestguard"
	"github.com/defenseclaw/defenseclaw/internal/openshell/sandboxapi"
	"github.com/defenseclaw/defenseclaw/internal/openshell/stream"
	"github.com/defenseclaw/defenseclaw/internal/openshell/triage"
)

var (
	approve       = sandboxapi.ApprovalDecision{Decision: "approve"}
	approveAlways = sandboxapi.ApprovalDecision{Decision: "approve", Always: true}
)

// fastTriage shortens the delay before a denied connection's draft poll.
func fastTriage(t *testing.T) {
	saved := triageDelay
	triageDelay = 10 * time.Millisecond
	t.Cleanup(func() { triageDelay = saved })
}

func TestTriageDecidesProposals(t *testing.T) {
	e := liveEnv(t, "tribox", nil)
	ok := e.propose("tribox", "registry.example.org")
	bad := e.propose("tribox", "webhook.site")
	door := e.addChunk("tribox", chunk("allow_pg", "host.openshell.internal", 5432))
	e.watch.push(t, "tribox", stream.Event{Kind: stream.KindDraft, Draft: &stream.DraftUpdate{NewChunks: 3}})
	e.waitChunk("tribox", ok, "approved")
	if s, d := e.chunkStatus("tribox", bad), e.chunkStatus("tribox", door); s != "rejected" || d != "pending" {
		t.Fatalf("blocklisted proposal = %s, host-port proposal = %s", s, d)
	}
	asks := e.waitAsks("tribox", 1)
	if asks[0].Kind != sandboxapi.ApprovalKindHostPort || asks[0].Port != 5432 || !asks[0].Risky || e.get("tribox").PendingApprovals != 1 {
		t.Fatalf("asks = %+v", asks)
	}
	e.draft("tribox") // a repeated notification does not decide the same chunks twice
	res, err := e.m.DecideApproval(t.Context(), asks[0].ID, approve)
	if err != nil || res.Approval.Status != sandboxapi.ApprovalQueued {
		t.Fatalf("approve = %+v, %v", res, err)
	}
	e.waitChunk("tribox", door, "approved")
	if err := e.decide(asks[0].ID, approve); !sandboxapi.IsCode(err, sandboxapi.CodeConflict) {
		t.Fatalf("second decision: %v", err)
	}
	// Resolved approved (automatic and operator) and denied (policy), plus rule_add records.
	eventually(t, "approval telemetry", func() bool {
		var auto, op, denied bool
		for _, a := range where(&e.tel.mu, &e.tel.approvals, func(a audit.SandboxApprovalEvent) bool { return a.Stage == audit.SandboxApprovalResolved }) {
			auto = auto || (a.Result == audit.SandboxApprovalApproved && a.ActorType == audit.SandboxApprovalByAutomatic)
			op = op || (a.Result == audit.SandboxApprovalApproved && a.ActorType == audit.SandboxApprovalByOperator)
			denied = denied || (a.Result == audit.SandboxApprovalDenied && a.ActorType == audit.SandboxApprovalByPolicy)
		}
		return auto && op && denied && len(where(&e.tel.mu, &e.tel.policy, func(p audit.SandboxPolicyEvent) bool {
			return p.Operation == audit.SandboxPolicyRuleAdd
		})) == 2
	})
	for _, want := range []string{sandboxapi.ActivityEgressBlocked, sandboxapi.ActivityApprovalRequested, sandboxapi.ActivityApprovalResolved} {
		if len(e.events("tribox", want, "")) == 0 {
			t.Fatalf("feed misses %s", want)
		}
	}
}

// Codex's startup tip download around the proxy is rejected with the reason
// on the feed, and is no blocked site and no harness work; the agent's curl
// to the same destination is.
func TestTriageRejectsHarnessFetches(t *testing.T) {
	e := newEnv(t, nil)
	useCodex(e)
	e.live(sandboxapi.CreateRequest{Name: "fetchbox", Harness: "codex"})
	codex := harness.Codex.InstallRoot() + "/lib/node_modules/@openai/codex/node_modules/@openai/codex-linux-arm64/vendor/aarch64-unknown-linux-musl/bin/codex"
	firstWork := func() time.Time {
		e.m.mu.Lock()
		defer e.m.mu.Unlock()
		return e.m.boxes["fetchbox"].reach.firstWork
	}
	// OpenShell 0.1.1's two denials of the download: the DNS refusal names no binary.
	e.ocsf("fetchbox", "NET:REFUSE [MED] DENIED raw.githubusercontent.com [reason:policy_dns_ineligible]", time.Now())
	e.ocsf("fetchbox", "NET:OPEN [MED] DENIED "+codex+"(0) -> raw.githubusercontent.com:443 [reason:transparent_tcp_policy_denied]", time.Now())
	if e.get("fetchbox").Egress.Blocked != 0 || !firstWork().IsZero() || len(e.events("fetchbox", sandboxapi.ActivityEgressBlocked, "")) != 0 {
		t.Fatal("the tip download counted as a blocked site, harness work or a feed line")
	}
	tip := chunk(ruleFor("raw.githubusercontent.com"), "raw.githubusercontent.com", 443)
	tip.Binary, tip.ProposedRule.Binaries = codex, []types.PolicyNetworkBinary{{Path: codex}}
	fetch := e.addChunk("fetchbox", tip)
	e.draft("fetchbox")
	e.waitChunk("fetchbox", fetch, "rejected")
	if got := e.events("fetchbox", sandboxapi.ActivityEgressBlocked, "harness_background_fetch"); len(got) != 1 ||
		!strings.Contains(got[0].Message, "Codex's startup tip download") || !strings.Contains(got[0].Message, "opens no direct rule") {
		t.Fatalf("feed = %+v", got)
	}
	// A tool's denied connection counts, but is no model call of the harness either.
	e.ocsf("fetchbox", "NET:OPEN [MED] DENIED /usr/bin/curl(9) -> raw.githubusercontent.com:443 [reason:transparent_tcp_policy_denied]", time.Now())
	if e.get("fetchbox").Egress.Blocked != 1 || !firstWork().IsZero() {
		t.Fatal("a curl's denial was not counted once, or counted as harness work")
	}
	curl := e.propose("fetchbox", "raw.githubusercontent.com")
	e.draft("fetchbox")
	e.waitChunk("fetchbox", curl, "approved")
}

// TestSSHRefusalIsOneFeedLine (GAP-0090, GAP-0111): git over SSH to
// github.com:22 showed "(no OpenShell rule allows it)" and then, from
// triage's rejection of the drafted rule, "(port not allowed)" for the one
// attempt. The rejection of a port-22 draft adds no line: OpenShell's
// denial is on the feed, and the CLI says to use an HTTPS remote.
func TestSSHRefusalIsOneFeedLine(t *testing.T) {
	e := newEnv(t, nil)
	e.live(sandboxapi.CreateRequest{Name: "sshbox"})
	id := e.addChunk("sshbox", chunk("allow_github_com_22", "github.com", 22))
	e.draft("sshbox")
	e.waitChunk("sshbox", id, "rejected")
	if got := e.events("sshbox", sandboxapi.ActivityEgressBlocked, ""); len(got) != 0 {
		t.Fatalf("feed = %+v", got)
	}
}

// TestProxyRefusedHarnessFetchIsQuiet (GAP-0095): OpenCode asks
// models.opencode.ai for its model catalog at every start, through the
// egress proxy, which balanced refuses: each start showed a blocked site
// with an unblock hint, counted one blocked destination and raised a
// shadow AI finding. The refusal is audited only; a tool's request to the
// same host under another harness is the agent's.
func TestProxyRefusedHarnessFetchIsQuiet(t *testing.T) {
	e := newEnv(t, nil)
	claude := e.images.rec
	useOpenCode(t, e)
	e.live(sandboxapi.CreateRequest{Name: "ocbox", Harness: "opencode"})
	refuse := func(name string) {
		e.m.egressEvent(t.Context(), egress.Event{Kind: egress.EventBlocked, SandboxName: name, Host: "models.opencode.ai", Port: 443, Time: time.Now(),
			Category: egress.CategoryNotAllowlisted, Unblockable: true}, 0)
	}
	refuse("ocbox")
	audited := where(&e.tel.mu, &e.tel.egress, func(r audit.SandboxEgressEvent) bool { return r.Host == "models.opencode.ai" && r.Blocked })
	d, err := e.m.Destinations(t.Context(), "ocbox")
	if len(audited) != 1 || audited[0].DecisionCode != audit.SandboxEgressCodeHarnessFetch || audited[0].Severity != "INFO" ||
		err != nil || len(e.events("ocbox", sandboxapi.ActivityEgressBlocked, "")) != 0 || len(d.Destinations) != 0 ||
		e.get("ocbox").Egress.Blocked != 0 || len(e.tel.findingsOf(audit.SandboxFindingShadowAI)) != 0 {
		t.Fatalf("audited %d, feed %+v, destinations %+v (%v), blocked %d", len(audited), e.events("ocbox", sandboxapi.ActivityEgressBlocked, ""), d, err, e.get("ocbox").Egress.Blocked)
	}
	// An open pack lets it through: the harness's vendor, no shadow AI.
	e.m.egressEvent(t.Context(), egress.Event{Kind: egress.EventAllowed, SandboxName: "ocbox", Host: "models.opencode.ai", Port: 443, Time: time.Now(),
		FirstSeen: true}, 0)
	d, err = e.m.Destinations(t.Context(), "ocbox")
	if err != nil || len(d.Destinations) != 1 || d.Destinations[0].Kind != sandboxapi.DestinationHarnessVendor ||
		len(e.tel.findingsOf(audit.SandboxFindingShadowAI)) != 0 {
		t.Fatalf("allowed: destinations %+v (%v), shadow AI %d", d, err, len(e.tel.findingsOf(audit.SandboxFindingShadowAI)))
	}
	e.images.rec = claude
	e.live(sandboxapi.CreateRequest{Name: "claudebox", Copy: true})
	refuse("claudebox")
	if len(e.events("claudebox", sandboxapi.ActivityEgressBlocked, "")) != 1 {
		t.Fatal("another harness's request to the host is not on the feed")
	}
}

// TestOpenShellDenialAuditReadsLikeTheFeed (GAP-0134): one git ls-remote
// over SSH raised two MEDIUM alerts, the refused lookup and the connection,
// whose reasons were OpenShell's tokens. The lookup is audited at INFO under
// a code the alerts leave out, and a denial's reason has the feed's words
// (for SSH: use an HTTPS remote) before the token.
func TestOpenShellDenialAuditReadsLikeTheFeed(t *testing.T) {
	e := liveEnv(t, "gitbox", nil)
	e.ocsf("gitbox", "NET:REFUSE [MED] DENIED github.com [reason:policy_dns_ineligible]", time.Now())
	e.ocsf("gitbox", "NET:OPEN [MED] DENIED /usr/bin/ssh(0) -> github.com:22 [reason:transparent_tcp_policy_denied]", time.Now())
	e.ocsf("gitbox", "NET:OPEN [MED] DENIED /usr/bin/curl(0) -> evil.example.net:443 [reason:transparent_tcp_policy_denied]", time.Now())
	got := where(&e.tel.mu, &e.tel.egress, func(ev audit.SandboxEgressEvent) bool { return ev.Blocked })
	if len(got) != 3 || got[0].DecisionCode != audit.SandboxEgressCodeLookupRefused || got[0].Severity != "INFO" ||
		got[1].DecisionCode != "SANDBOX_EGRESS_OPENSHELL_DENIED" || got[1].Severity != "" ||
		got[1].Reason != "SSH does not leave a sandbox: use an HTTPS remote (https://github.com/…) (transparent_tcp_policy_denied)" ||
		got[2].Reason != "no OpenShell rule allows it (transparent_tcp_policy_denied)" {
		t.Fatalf("audited %+v", got)
	}
}

// Of OpenShell's denials only the connection counts and shows on the feed: a
// refused lookup and the container's own host name are audited only. A
// synthetic address names its mapped destination (the host alias's, the
// closed port, once), and a record from before the daemon started is marked
// replayed.
func TestOpenShellDenialsCountConnections(t *testing.T) {
	e := liveEnv(t, "denialbox", nil)
	feed := func() []sandboxapi.ActivityEvent { return e.events("denialbox", sandboxapi.ActivityEgressBlocked, "") }
	blocked := func() int { return e.get("denialbox").Egress.BlockedRequests }
	push := func(line string) { e.ocsf("denialbox", line, time.Now()) }
	push("NET:REFUSE [MED] DENIED evil.example.net [reason:policy_dns_ineligible]")
	push("NET:OPEN [MED] DENIED /usr/bin/curl(0) -> evil.example.net:443 [reason:transparent_tcp_policy_denied]")
	if got := feed(); blocked() != 1 || len(got) != 1 || got[0].Host != "evil.example.net" || got[0].Replayed {
		t.Fatalf("feed = %+v, blocked %d; want one line for the connection", got, blocked())
	}
	push("NET:REFUSE [MED] DENIED abf22769329d [reason:policy_dns_ineligible]")
	push("NET:OPEN [MED] DENIED /usr/bin/python3(0) -> abf22769329d:80 [reason:transparent_tcp_policy_denied]")
	audited := where(&e.tel.mu, &e.tel.egress, func(ev audit.SandboxEgressEvent) bool { return ev.Host == "abf22769329d" && ev.Blocked })
	if blocked() != 1 || len(audited) != 2 {
		t.Fatalf("the host name: %d blocked requests, %d audit records; want 1 and 2", blocked(), len(audited))
	}
	push("CONFIG:PUBLISHED [INFO] Policy DNS mapped api.example.org resolved=93.184.216.34 synthetic=198.18.0.7 ports=443 mapping_id=m1")
	push("NET:OPEN [MED] DENIED /usr/bin/curl(0) -> 198.18.0.7:8443 [reason:transparent_tcp_mapping_denied]")
	push("NET:OPEN [MED] DENIED /usr/bin/curl(0) -> 198.18.0.9:8443 [reason:transparent_tcp_mapping_denied]")
	if got := feed(); len(got) != 3 || got[1].Host != "api.example.org" || got[1].Port != 8443 || got[2].Host != "198.18.0.9" {
		t.Fatalf("feed = %+v, want the mapped name, then an unmapped address as recorded", got)
	}
	// A port on this machine the run did not declare: the feed names the flag, once, and nothing asks.
	push("CONFIG:PUBLISHED [INFO] Policy DNS mapped host.openshell.internal resolved=127.0.0.1 synthetic=198.18.0.2 ports=18998 mapping_id=m2")
	push("NET:OPEN [MED] DENIED /usr/bin/curl(0) -> 198.18.0.2:29170 [reason:transparent_tcp_mapping_denied]")
	push("NET:OPEN [MED] DENIED /usr/bin/curl(0) -> host.openshell.internal:29170 [reason:transparent_tcp_mapping_denied]")
	if got := feed(); len(got) != 4 || blocked() != 5 || got[3].Host != openshellHostAlias || got[3].Port != 29170 ||
		got[3].Reason != sandboxapi.ReasonHostPortClosed || !strings.Contains(got[3].Message, "port 29170 on this machine is closed to the sandbox") ||
		!strings.Contains(got[3].Message, "--host-port 29170") {
		t.Fatalf("feed = %+v, blocked %d; want the host alias's port named once", got, blocked())
	}
	// The blocked destinations are the feed's: four, however often each was
	// tried.
	if sb := e.get("denialbox"); sb.Egress.Blocked != 4 || sb.Egress.Destinations != 0 {
		t.Fatalf("egress = %+v; want the feed's four blocked destinations and none reached", sb.Egress)
	}
	if asks, _ := e.m.Approvals(t.Context(), "denialbox"); len(asks) != 0 {
		t.Fatalf("asks = %+v; an undeclared port does not ask", asks)
	}
	e.ocsf("denialbox", "NET:OPEN [MED] DENIED /usr/bin/curl(0) -> old.example.org:443 [reason:transparent_tcp_policy_denied]", e.m.startedAt.Add(-time.Minute))
	if got := feed(); len(got) != 5 || !got[4].Replayed {
		t.Fatalf("feed = %+v, want the replayed record marked", got)
	}
}

// "Always" decisions persist a block or an allow; once the administrator
// forbids unblocking, an "always" of an ask queued before is refused and
// recorded as a no-change policy record (not degraded health), while
// approving once still works.
func TestApprovalAlwaysDecisions(t *testing.T) {
	e := liveEnv(t, "askbox", func(c *config.Config) { c.OpenShell.Profile = config.OpenShellProfileBalanced })
	a, b := e.propose("askbox", "a.example.org"), e.propose("askbox", "b.example.org")
	e.propose("askbox", "c.example.org")
	e.draft("askbox")
	byHost := map[string]string{}
	for _, ask := range e.waitAsks("askbox", 3) {
		byHost[ask.Host] = ask.ID
		if !strings.Contains(ask.Reason, "allowlist") {
			t.Fatalf("ask reason = %q", ask.Reason)
		}
	}
	must(t, e.decide(byHost["a.example.org"], sandboxapi.ApprovalDecision{Decision: "reject", Always: true}))
	if s := e.chunkStatus("askbox", a); s != "rejected" {
		t.Fatalf("rejected chunk = %s", s)
	}
	if res, err := e.m.DecideApproval(t.Context(), byHost["b.example.org"], approveAlways); err != nil || !res.Persisted {
		t.Fatalf("approve always = %+v, %v", res, err)
	}
	e.waitChunk("askbox", b, "approved")
	if !slices.Equal(e.persist.block, []string{"a.example.org"}) || !slices.Equal(e.persist.allowed(), []string{"b.example.org"}) {
		t.Fatalf("persisted allow %v block %v", e.persist.allow, e.persist.block)
	}
	if err := e.decide("ap_missing", approve); !sandboxapi.IsCode(err, sandboxapi.CodeNotFound) {
		t.Fatalf("unknown id: %v", err)
	}
	e.setConfig(func(c *config.Config) { c.OpenShell.Admin.AllowUnblock = boolPtr(false) })
	if apiErr := wantCode(t, e.decide(byHost["c.example.org"], approveAlways), sandboxapi.CodeAdminViolation); !strings.Contains(apiErr.Message, sandboxapi.AdminMessage) {
		t.Fatalf("message = %q", apiErr.Message)
	}
	if len(e.persist.allowed()) != 1 {
		t.Fatal("refused decision was persisted")
	}
	must(t, e.decide(byHost["c.example.org"], approve))
	if h := where(&e.tel.mu, &e.tel.health, func(h audit.SandboxHealthEvent) bool { return h.ErrorCode == "openshell_admin_violation" }); len(h) != 0 {
		t.Fatalf("a refused request was recorded as degraded subsystem health: %+v", h)
	}
	if len(where(&e.tel.mu, &e.tel.policy, func(p audit.SandboxPolicyEvent) bool {
		return p.Operation == audit.SandboxPolicyRuleAdd && p.NoChange && p.Reason == policyReasonAdminRefused && p.Target == "c.example.org" && p.Sandbox.Name == "askbox"
	})) == 0 {
		t.Fatal("the admin refusal has no policy record")
	}
}

// "Always" is refused for a destination on the user's network, by name or
// answer (openshell.egress.unblocked never opens one); approving it once works.
func TestPrivateNameApproveAlwaysRefused(t *testing.T) {
	e := liveEnv(t, "lanalways", nil)
	e.dns.set("db.lan.example.org", "10.0.0.5")
	ids := []string{e.propose("lanalways", "wiki.corp"), e.propose("lanalways", "db.lan.example.org")}
	e.draft("lanalways")
	for _, ask := range e.waitAsks("lanalways", 2) {
		if err := e.decide(ask.ID, approveAlways); !sandboxapi.IsCode(err, sandboxapi.CodeInvalid) || !strings.Contains(err.Error(), "openshell.egress.allow") {
			t.Fatalf("approve always %s: %v", ask.Host, err)
		}
		must(t, e.decide(ask.ID, approve))
	}
	for _, id := range ids {
		e.waitChunk("lanalways", id, "approved")
	}
	if len(e.persist.allowed()) != 0 {
		t.Fatalf("persisted %v for future sandboxes", e.persist.allowed())
	}
}

// The hourly prune forgets only old resolved asks: one a decision is being
// applied to has no resolvedAt yet, and pruning it would orphan the decision.
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
		{sandboxapi.ApprovalPending, time.Time{}, true}, {approvalDeciding, time.Time{}, true}, {sandboxapi.ApprovalQueued, time.Time{}, true},
		{sandboxapi.ApprovalRejected, recent, true}, {sandboxapi.ApprovalRejected, old, false}, {sandboxapi.ApprovalApproved, old, false},
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

// A proposal is decided after OpenShell denies a direct connection even when
// no draft notification arrives, and by the periodic sweep.
func TestTriageRunsWithoutADraftEvent(t *testing.T) {
	fastTriage(t)
	e := liveEnv(t, "denybox2", nil)
	id := e.propose("denybox2", "www.example.com")
	line := "NET:OPEN [MED] DENIED /usr/bin/curl(3) -> www.example.com:443 [reason:transparent_tcp_policy_denied]"
	e.watch.push(t, "denybox2", stream.Event{Kind: stream.KindLog, Log: &stream.Log{Message: line, OCSF: parseOCSF(t, line)}})
	e.waitChunk("denybox2", id, "approved")

	e = newEnv(t, nil)
	e.m.opts.TriageInterval = 20 * time.Millisecond
	e.run()
	e.create(sandboxapi.CreateRequest{Name: "sweepbox"})
	e.waitChunk("sweepbox", e.propose("sweepbox", "www.example.com"), "approved")
}

// A retried proposal collapses into its destination's ask (on the newest
// chunk); one with other content (an extra port) gets its own ask instead of
// replacing the one the user is reading.
func TestReproposalsCollapseOnlyWhenUnchanged(t *testing.T) {
	e := liveEnv(t, "floodbox", nil)
	first := e.addChunk("floodbox", chunk("allow_pg", "host.openshell.internal", 5432))
	e.addChunk("floodbox", chunk("allow_hook", "webhook.site", 443))
	e.draft("floodbox")
	e.waitAsks("floodbox", 1)
	second := e.addChunk("floodbox", chunk("allow_pg", "host.openshell.internal", 5432))
	again := e.addChunk("floodbox", chunk("allow_hook", "webhook.site", 443))
	e.draft("floodbox")
	e.waitChunk("floodbox", again, "rejected")
	asks, _ := e.m.Approvals(t.Context(), "floodbox")
	if len(asks) != 1 || asks[0].ChunkID != second || e.chunkStatus("floodbox", first) != "rejected" {
		t.Fatalf("asks = %+v, superseded chunk %s", asks, e.chunkStatus("floodbox", first))
	}
	if n := len(where(&e.tel.mu, &e.tel.approvals, func(a audit.SandboxApprovalEvent) bool { return a.Stage == audit.SandboxApprovalRequested })); n != 2 {
		t.Fatalf("requested records = %d, want one per destination", n)
	}
	must(t, e.decide(asks[0].ID, approve))
	e.waitChunk("floodbox", second, "approved")

	read := e.addChunk("floodbox", chunk("allow_host_openshell_internal_3000", "host.openshell.internal", 3000))
	e.draft("floodbox")
	ask := e.waitAsks("floodbox", 1)[0]
	swapped := chunk("allow_host_openshell_internal_3000", "host.openshell.internal", 3000)
	swapped.ProposedRule.Endpoints[0].Ports = []uint32{3000, 22}
	other := e.addChunk("floodbox", swapped)
	e.draft("floodbox")
	e.waitAsks("floodbox", 2)
	must(t, e.decide(ask.ID, approve))
	e.waitChunk("floodbox", read, "approved")
	if e.chunkStatus("floodbox", other) != "pending" {
		t.Fatalf("the swapped-in proposal = %s", e.chunkStatus("floodbox", other))
	}
	pol, _ := e.fake.SandboxPolicy(openshell.DefaultWorkspace, "floodbox")
	for _, ep := range pol.NetworkPolicies["allow_host_openshell_internal_3000"].Endpoints {
		if slices.Contains(ep.Ports, 22) || ep.Port == 22 {
			t.Fatalf("port 22 was opened: %+v", ep)
		}
	}
}

// Approvals decided before another policy change still land: OpenShell's
// review token changes with the policy, so the manager reads a fresh one.
func TestApprovalsUseLiveReviewTokens(t *testing.T) {
	e := liveEnv(t, "tokbox", func(c *config.Config) { c.OpenShell.Approvals.DebounceMs = 150 })
	door := e.addChunk("tokbox", chunk("allow_host_openshell_internal_5432", "host.openshell.internal", 5432))
	e.draft("tokbox")
	asks := e.waitAsks("tokbox", 1)
	auto := e.propose("tokbox", "registry.example.org")
	e.draft("tokbox")
	// While the automatic approval is debounced, another client changes the policy.
	other := e.propose("tokbox", "other.example.org")
	eventually(t, "automatic approval queued", func() bool { return e.m.batcher.Pending("tokbox") == 1 })
	live, _ := e.fake.DraftChunk(openshell.DefaultWorkspace, "tokbox", other)
	_, err := e.client.ApproveDraftChunk(t.Context(), "tokbox", other, live.ReviewToken)
	must(t, err)
	e.waitChunk("tokbox", auto, "approved")
	// The ask's token is stale twice over; the operator's approval lands.
	must(t, e.decide(asks[0].ID, approve))
	e.waitChunk("tokbox", door, "approved")
	eventually(t, "both approvals recorded as approved, with rule_add records", func() bool {
		e.m.mu.Lock()
		n := 0
		for _, a := range e.m.approvals {
			if a.status == sandboxapi.ApprovalApproved {
				n++
			}
		}
		e.m.mu.Unlock()
		var rules []string
		for _, p := range where(&e.tel.mu, &e.tel.policy, func(p audit.SandboxPolicyEvent) bool { return p.Operation == audit.SandboxPolicyRuleAdd }) {
			rules = append(rules, p.Target)
		}
		return n == 2 && slices.Contains(rules, "registry.example.org") && slices.Contains(rules, "host.openshell.internal")
	})
}

// An ask names every endpoint, allowed IP and binary, a proposal naming a
// second host is rejected (the ask would show one destination while approving
// opens both), and the decision re-checks the whole proposal.
func TestApprovalShowsAndChecksTheWholeProposal(t *testing.T) {
	e := liveEnv(t, "wholebox", nil)
	two := chunk("allow_host_openshell_internal_3000", "host.openshell.internal", 3000)
	two.ProposedRule.Endpoints = append(two.ProposedRule.Endpoints, types.PolicyNetworkEndpoint{Host: "10.1.2.3", Port: 443})
	twoID := e.addChunk("wholebox", two)
	e.draft("wholebox")
	e.waitChunk("wholebox", twoID, "rejected")

	c := chunk("allow_host_openshell_internal_3000", "host.openshell.internal", 3000)
	c.ProposedRule.Endpoints[0].Ports = []uint32{3000, 22}
	id := e.addChunk("wholebox", c)
	e.draft("wholebox")
	got := e.waitAsks("wholebox", 1)[0]
	want := []sandboxapi.ApprovalEndpoint{{Host: "host.openshell.internal", Port: 3000}, {Host: "host.openshell.internal", Port: 22}}
	if !slices.Equal(got.Endpoints, want) || got.RuleName != "allow_host_openshell_internal_3000" || !slices.Equal(got.Binaries, []string{"/usr/bin/curl"}) ||
		!strings.Contains(got.Reason, "3000, 22") {
		t.Fatalf("ask = %+v", got)
	}
	e.setConfig(func(c *config.Config) { c.OpenShell.Admin.AllowHostPorts = boolPtr(false) })
	wantCode(t, e.decide(got.ID, approve), sandboxapi.CodeAdminViolation)
	if s := e.chunkStatus("wholebox", id); s != "pending" {
		t.Fatalf("refused proposal = %s", s)
	}
	// Always is refused for proposals that reach this machine.
	e.setConfig(func(c *config.Config) { c.OpenShell.Admin.AllowHostPorts = nil })
	if err := e.decide(got.ID, approveAlways); !sandboxapi.IsCode(err, sandboxapi.CodeInvalid) {
		t.Fatalf("approve always: %v", err)
	}
}

// allowed_ips reaching the user's network ask instead of being approved
// automatically, the decision checks them against allow_unblock, and a delete
// drops the sandbox's asks.
func TestPrivateAllowedIPsAsk(t *testing.T) {
	e := liveEnv(t, "ipbox", nil)
	c := chunk(ruleFor("my-cdn.attacker.example"), "my-cdn.attacker.example", 443)
	c.ProposedRule.Endpoints[0].AllowedIPs = []string{"10.0.0.0/8"}
	id := e.addChunk("ipbox", c)
	e.draft("ipbox")
	ask := e.waitAsks("ipbox", 1)[0]
	if e.chunkStatus("ipbox", id) != "pending" || !ask.Risky || !slices.Equal(ask.AllowedIPs, []string{"10.0.0.0/8"}) || !strings.Contains(ask.Reason, "10.0.0.0/8") {
		t.Fatalf("ask = %+v", ask)
	}
	e.setConfig(func(c *config.Config) { c.OpenShell.Admin.AllowUnblock = boolPtr(false) })
	wantCode(t, e.decide(ask.ID, approve), sandboxapi.CodeAdminViolation)
	e.deleteBox("ipbox", sandboxapi.DeleteRequest{})
	if asks, _ := e.m.Approvals(t.Context(), ""); len(asks) != 0 {
		t.Fatalf("asks left: %v", asks)
	}
}

// The flood limits: automatic approvals per window then asks, the seen-chunk
// set tracking only pending chunks, a flood of rejections reported quietly
// after the first ones, and the per-session rule ceiling a restart resets.
func TestProposalFloodLimits(t *testing.T) {
	e := liveEnv(t, "ratebox", nil)
	total := autoApproveBurst + 5
	for i := range total {
		e.propose("ratebox", fmt.Sprintf("h%d.example.org", i))
	}
	e.draft("ratebox")
	for _, a := range e.waitAsks("ratebox", total-autoApproveBurst) {
		if !strings.Contains(a.Reason, "many new destinations") {
			t.Fatalf("ask = %+v", a)
		}
	}
	eventually(t, "automatic approvals applied", func() bool {
		d, _ := e.client.GetDraft(t.Context(), "ratebox", "approved")
		return d != nil && len(d.Chunks) == autoApproveBurst
	})
	e.m.triageSandbox(t.Context(), e.boxOf("ratebox"))
	e.m.mu.Lock()
	seen := len(e.m.boxes["ratebox"].seenChunks)
	e.m.mu.Unlock()
	if seen != total-autoApproveBurst {
		t.Fatalf("seen chunks = %d, want the %d still pending", seen, total-autoApproveBurst)
	}

	e = liveEnv(t, "limitbox", nil)
	var ids []string
	for i := range rejectBurst + 5 {
		ids = append(ids, e.propose("limitbox", fmt.Sprintf("x%d.pastebin.com", i)))
	}
	e.draft("limitbox")
	for _, id := range ids {
		e.waitChunk("limitbox", id, "rejected")
	}
	notices := len(e.events("limitbox", sandboxapi.ActivityEgressBlocked, "rate_limited"))
	if blocked := len(e.events("limitbox", sandboxapi.ActivityEgressBlocked, "")) - notices; blocked != rejectBurst || notices != 1 {
		t.Fatalf("feed: %d blocked, %d notices; want %d and one", blocked, notices, rejectBurst)
	}
	e.m.mu.Lock()
	e.m.boxes["limitbox"].rulesAdded = maxRulesPerSession
	e.m.mu.Unlock()
	id := e.propose("limitbox", "more.example.org")
	e.draft("limitbox")
	e.waitChunk("limitbox", id, "rejected")
	if c, _ := e.fake.DraftChunk(openshell.DefaultWorkspace, "limitbox", id); !strings.Contains(c.RejectionReason, "rules this session") {
		t.Fatalf("rejection = %q", c.RejectionReason)
	}
	e.stopBox("limitbox")
	e.startBox("limitbox", sandboxapi.StartRequest{})
	e.m.mu.Lock()
	spent := e.m.boxes["limitbox"].rulesAdded
	e.m.mu.Unlock()
	if spent != 0 {
		t.Fatalf("rules after a restart = %d", spent)
	}
}

// At the pending-ask cap a new proposal of a rule already waiting collapses
// into its ask (on the newest chunk) instead of being rejected and taking the
// ask with it; a new rule at the cap is still rejected.
func TestPendingCapKeepsAReproposedAsk(t *testing.T) {
	e := newEnv(t, nil)
	e.create(sandboxapi.CreateRequest{Name: "capbox"})
	gw, err := e.m.gateway(t.Context())
	must(t, err)
	b := e.boxOf("capbox")
	ask := func(i int, chunkID string) {
		host := fmt.Sprintf("h%d.example.org", i)
		p := triage.Proposal{Sandbox: "capbox", ChunkID: chunkID, RuleName: ruleFor(host), RuleDigest: fmt.Sprintf("rule-%d", i),
			Endpoints: []triage.Endpoint{{Host: host, Port: 443}}}
		e.m.applyTriage(t.Context(), gw, b, b.rec.BindingID, p, triage.Decision{Verdict: triage.Ask, Reason: triage.ReasonManual,
			Kind: triage.KindNetworkRule, Host: host, Port: 443, Message: "approvals are manual"})
	}
	for i := range maxPendingApprovals {
		ask(i, fmt.Sprintf("chunk-%d", i))
	}
	ask(0, "chunk-0-again")
	e.m.mu.Lock()
	a := e.m.approvals[approvalID("capbox", "rule-0")]
	status, chunkID := a.status, a.chunkID
	e.m.mu.Unlock()
	if status != sandboxapi.ApprovalPending || chunkID != "chunk-0-again" {
		t.Fatalf("the re-proposed ask is %s on %s, want pending on the newest chunk", status, chunkID)
	}
	ask(maxPendingApprovals, "chunk-new")
	if asks, _ := e.m.Approvals(t.Context(), "capbox"); len(asks) != maxPendingApprovals {
		t.Fatalf("%d asks pending, want %d", len(asks), maxPendingApprovals)
	}
}

// An approval is judged again with a fresh DNS answer right before it is
// applied: a name that rebinds to this machine is never approved, by triage
// or by the operator.
func TestApprovalRecheckedAtApply(t *testing.T) {
	fastTriage(t)
	e := liveEnv(t, "rebindbox", nil)
	e.dns.rebindAfter("cdn.rebind.example.org", 1, "127.0.0.1")
	auto := e.propose("rebindbox", "cdn.rebind.example.org")
	e.draft("rebindbox")
	e.waitChunk("rebindbox", auto, "rejected")
	if c, _ := e.fake.DraftChunk(openshell.DefaultWorkspace, "rebindbox", auto); !strings.Contains(c.RejectionReason, "this machine") {
		t.Fatalf("rejection = %q", c.RejectionReason)
	}
	e.dns.set("db.rebind.example.org", "10.0.0.5")
	e.dns.rebindAfter("db.rebind.example.org", 2, "127.0.0.1")
	asked := e.propose("rebindbox", "db.rebind.example.org")
	e.draft("rebindbox")
	ask := e.waitAsks("rebindbox", 1)[0]
	if ask.Host != "db.rebind.example.org" || !ask.Risky {
		t.Fatalf("ask = %+v", ask)
	}
	must(t, e.decide(ask.ID, approve))
	e.waitChunk("rebindbox", asked, "rejected")
	for _, host := range []string{"cdn.rebind.example.org", "db.rebind.example.org"} {
		if e.hasRule("rebindbox", ruleFor(host)) {
			t.Fatalf("rule to %s reached the policy", host)
		}
	}
	if len(e.events("rebindbox", sandboxapi.ActivityApprovalResolved, "refused_at_apply")) == 0 {
		t.Fatal("no refused_at_apply feed event")
	}
}

// A resolver slower than the triage pass's budget leaves the proposal for
// the next poll instead of rejecting it as unresolvable.
func TestSlowDNSDefersTriage(t *testing.T) {
	savedDelay, savedBudget := triageDelay, triagePassBudget
	triageDelay, triagePassBudget = 20*time.Millisecond, 50*time.Millisecond
	t.Cleanup(func() { triageDelay, triagePassBudget = savedDelay, savedBudget })
	e := liveEnv(t, "slowbox", nil)
	e.dns.setHang("slow.example.org", true)
	id := e.propose("slowbox", "slow.example.org")
	e.draft("slowbox")
	time.Sleep(300 * time.Millisecond)
	if s := e.chunkStatus("slowbox", id); s != "pending" {
		t.Fatalf("proposal with a hanging lookup = %s, want it left pending", s)
	}
	e.dns.setHang("slow.example.org", false)
	e.waitChunk("slowbox", id, "approved")
}

// A lookup that fails temporarily (SERVFAIL, a timeout) never rejects: in
// triage the chunk waits for a later pass, and an approval the user gave is
// retried and then handed back to the user.
func TestFlakyDNSNeverRejects(t *testing.T) {
	savedDelay, savedRetry := triageDelay, applyRetryDelay
	triageDelay, applyRetryDelay = 10*time.Millisecond, 10*time.Millisecond
	t.Cleanup(func() { triageDelay, applyRetryDelay = savedDelay, savedRetry })
	servfail := &net.DNSError{Err: "server misbehaving", Name: "flaky", IsTemporary: true}
	e := liveEnv(t, "flakybox", nil)
	e.dns.setErr("cdn.flaky.example.org", servfail)
	auto := e.propose("flakybox", "cdn.flaky.example.org")
	e.m.triageSandbox(t.Context(), e.boxOf("flakybox"))
	e.dns.mu.Lock()
	looked := e.dns.calls["cdn.flaky.example.org."]
	e.dns.mu.Unlock()
	_ = e.m.batcher.Drain(t.Context())
	if looked == 0 || e.chunkStatus("flakybox", auto) != "pending" {
		t.Fatalf("proposal with a failing lookup (%d lookups) = %s, want it left pending", looked, e.chunkStatus("flakybox", auto))
	}
	e.dns.setErr("cdn.flaky.example.org", nil)
	e.draft("flakybox")
	e.waitChunk("flakybox", auto, "approved")

	e.dns.set("db.flaky.example.org", "10.0.0.5")
	asked := e.propose("flakybox", "db.flaky.example.org")
	e.draft("flakybox")
	ask := e.waitAsks("flakybox", 1)[0]
	e.dns.setErr("db.flaky.example.org", servfail)
	must(t, e.decide(ask.ID, approve))
	eventually(t, "the approval handed back", func() bool {
		return slices.ContainsFunc(e.events("flakybox", sandboxapi.ActivityApprovalRequested, "lookup_failed"), func(ev sandboxapi.ActivityEvent) bool {
			return ev.ApprovalID == ask.ID
		})
	})
	if s, again := e.chunkStatus("flakybox", asked), e.waitAsks("flakybox", 1); s != "pending" || again[0].ID != ask.ID {
		t.Fatalf("approved proposal with a failing lookup = %s, asks %+v; want the same ask back", s, again)
	}
	e.dns.setErr("db.flaky.example.org", nil)
	must(t, e.decide(ask.ID, approve))
	e.waitChunk("flakybox", asked, "approved")
}

// Enforcement removes the approved direct rules (which bypass the proxy)
// that resolve to this machine, that the user or the administrator now
// blocks, and all once no policy resolves, keeping DefenseClaw's own; each
// removal is a log.policy.updated record with a registered reason token.
func TestRemovedRulesAreAudited(t *testing.T) {
	e := liveEnv(t, "auditbox", nil)
	want := map[string]string{
		"org1.example.org": policyReasonAdmin, "org2.example.org": policyReasonAdmin, "drop.example.org": policyReasonBlocklist,
		"later1.example.org": policyReasonResolvesToHost, "later2.example.org": policyReasonResolvesToHost, "keep.example.org": "",
	}
	var ids []string
	for host := range want {
		ids = append(ids, e.propose("auditbox", host))
	}
	e.draft("auditbox")
	for _, id := range ids {
		e.waitChunk("auditbox", id, "approved")
	}
	e.dns.set("later1.example.org", "127.0.0.1")
	e.dns.set("later2.example.org", "169.254.169.254")
	e.m.enforceAll(t.Context())
	e.setConfig(func(c *config.Config) { c.OpenShell.Egress.Block = []string{"drop.example.org"} })
	e.m.enforceAll(t.Context())
	e.setConfig(func(c *config.Config) {
		c.OpenShell.Admin.EgressBlock = []string{"org1.example.org", "org2.example.org"}
	})
	e.m.enforceAll(t.Context())
	got := map[string]string{}
	for _, p := range where(&e.tel.mu, &e.tel.policy, func(p audit.SandboxPolicyEvent) bool { return p.Operation == audit.SandboxPolicyRuleRemove }) {
		if p.ChangeCount != 1 || p.PolicyHash == "" {
			t.Errorf("rule_remove record %+v, want one change and the policy hash", p)
		}
		got[p.Target] = p.Reason
	}
	for host, reason := range want {
		if got[ruleFor(host)] != reason || e.hasRule("auditbox", ruleFor(host)) != (reason == "") {
			t.Fatalf("rule to %s: removed for %q, want %q (records %v)", host, got[ruleFor(host)], reason, got)
		}
	}
	if len(got) != 5 || len(e.events("auditbox", sandboxapi.ActivityEgressBlocked, "resolves_to_host")) == 0 {
		t.Fatalf("rule_remove records = %v, or no feed event for a rule that resolves to this machine", got)
	}
	e.setConfig(func(c *config.Config) {
		c.OpenShell.Admin.RequiredPack = filepath.Join(t.TempDir(), "gone", "pack.yaml")
	})
	e.m.enforceAll(t.Context())
	if e.hasRule("auditbox", ruleFor("keep.example.org")) || !e.hasRule("auditbox", "defenseclaw_egress") ||
		!e.tel.removed(ruleFor("keep.example.org"), policyReasonUnresolved) {
		t.Fatal("without a policy: want the direct rule removed (and recorded) and DefenseClaw's own kept")
	}
}

// A rule DefenseClaw approved on its own goes once the policy would no longer
// approve it (a private answer now, a required strict pack); the user's rule
// stays, and the sandbox shows the posture it runs under now.
func TestTighterPolicyRemovesAutomaticApprovals(t *testing.T) {
	e := liveEnv(t, "stricter", nil)
	rebound, auto, own := e.approveRule("stricter", "cdn.rebind.example.org"), e.approveRule("stricter", "auto.example.org"), ruleFor("db.lan.example.org")
	e.dns.set("db.lan.example.org", "10.0.0.5")
	id := e.propose("stricter", "db.lan.example.org")
	e.draft("stricter")
	must(t, e.decide(e.waitAsks("stricter", 1)[0].ID, approve))
	e.waitChunk("stricter", id, "approved")
	eventually(t, "the approvers recorded", func() bool {
		a := e.approvedRules("stricter")
		return a[auto] == actorAutomatic && a[own] == actorOperator
	})
	kept := func(rules ...string) bool {
		for _, r := range []string{rebound, auto, own} {
			if e.hasRule("stricter", r) != slices.Contains(rules, r) {
				return false
			}
		}
		return true
	}
	e.m.enforceAll(t.Context())
	if !kept(rebound, auto, own) {
		t.Fatal("a pass under an unchanged policy removed an approved rule")
	}
	e.dns.set("cdn.rebind.example.org", "192.168.1.20")
	e.m.enforceAll(t.Context())
	if !kept(auto, own) || !e.tel.removed(rebound, policyReasonApprovalRequired) {
		t.Fatal("want the automatic rule that now resolves privately removed (and recorded), the others kept")
	}
	e.setConfig(func(c *config.Config) { c.OpenShell.Admin.RequiredPack = "strict" })
	e.m.refreshEgress()
	e.m.enforceAll(t.Context())
	if !kept(own) || !e.tel.removed(auto, policyReasonApprovalRequired) {
		t.Fatal("want the automatic rule removed (and recorded) under the required strict pack, the user's kept")
	}
	if a := e.approvedRules("stricter"); len(a) != 1 || a[own] != actorOperator {
		t.Fatalf("recorded approvers after the removals = %v", a)
	}
	if saved, errs := newRecordStore(e.dataDir).loadAll(); len(errs) > 0 || len(saved) != 1 || len(saved[0].ApprovedRules) != 1 {
		t.Fatalf("saved record = %+v, %v", saved, errs)
	}
	sb := e.get("stricter")
	if sb.Pack != "strict" || sb.Profile != "strict" || sb.NetworkMode != "deny" || sb.Approvals != "manual" {
		t.Fatalf("posture = pack %s profile %s network %s approvals %s, want the strict pack's", sb.Pack, sb.Profile, sb.NetworkMode, sb.Approvals)
	}
	joined := strings.Join(sb.Warnings, "\n")
	if !strings.Contains(joined, "the sandbox policy changed since this sandbox was created (pack open") ||
		!strings.Contains(joined, "works on a copy of this project, but this sandbox mounts it live") {
		t.Fatalf("warnings = %q, want the posture change and the live mount", sb.Warnings)
	}
}

// An automatic approval merged into a rule the user approved leaves the rule
// automatic, so its endpoints do not keep the user's approval once the
// policy tightens.
func TestAutomaticMergeTakesUserAuthority(t *testing.T) {
	e := liveEnv(t, "merged", nil)
	rule := ruleFor("wiki.corp")
	own := e.propose("merged", "wiki.corp")
	e.draft("merged")
	must(t, e.decide(e.waitAsks("merged", 1)[0].ID, approve))
	e.waitChunk("merged", own, "approved")
	approver := func() string { return e.approvedRules("merged")[rule] }
	eventually(t, "the user recorded as the approver", func() bool { return approver() == actorOperator })
	// The agent names the user's rule for a public destination, which the open pack approves on its own.
	auto := e.addChunk("merged", chunk(rule, "auto.example.org", 443))
	e.draft("merged")
	e.waitChunk("merged", auto, "approved")
	eventually(t, "the merged rule recorded and saved as automatic", func() bool {
		saved, errs := newRecordStore(e.dataDir).loadAll()
		return approver() == actorAutomatic && len(errs) == 0 && len(saved) == 1 && saved[0].ApprovedRules[rule] == actorAutomatic
	})
	e.m.mu.Lock()
	changed := noteApprovedRule(e.m.boxes["merged"], rule, actorOperator)
	e.m.mu.Unlock()
	if changed {
		t.Fatal("a user approval merged into an automatic rule made it the user's")
	}
	e.setConfig(func(c *config.Config) { c.OpenShell.Admin.RequiredPack = "strict" })
	e.m.refreshEgress()
	e.m.enforceAll(t.Context())
	if e.hasRule("merged", rule) {
		t.Fatal("the rule holding an automatic approval survived the required strict pack")
	}
}

// An administrator's tightening reaches approved rules even when a create or
// delete rebuilt the egress deciders from the new configuration before the
// config loop saw it.
func TestConfigChangeIsEnforcedAfterAnEgressRefresh(t *testing.T) {
	e := liveEnv(t, "cfgbox", nil)
	rule := e.approveRule("cfgbox", "gone.example.org")
	e.setConfig(func(c *config.Config) { c.OpenShell.Admin.EgressBlock = []string{"gone.example.org"} })
	e.m.refreshEgress()
	deadline := time.Now().Add(6 * time.Second)
	for e.hasRule("cfgbox", rule) {
		if time.Now().After(deadline) {
			t.Fatal("the admin-blocked rule survived the configuration change")
		}
		time.Sleep(20 * time.Millisecond)
	}
}

// The first denied connection to a declared --host-port becomes an ask
// (OpenShell drafts none for the host alias) whose approval opens the port;
// one the organization closes gets the refusal on the feed, and no ask.
func TestDeclaredHostPortAsks(t *testing.T) {
	e := newEnv(t, nil)
	e.live(sandboxapi.CreateRequest{Name: "hpbox", HostPorts: []int{38830}})
	push := func(line string) { e.ocsf("hpbox", line, time.Now()) }
	push("CONFIG:PUBLISHED [INFO] Policy DNS mapped host.openshell.internal resolved=127.0.0.1 synthetic=198.18.0.2 ports=18971,18972 mapping_id=m1")
	denied := "NET:OPEN [MED] DENIED /usr/bin/curl(0) -> 198.18.0.2:38830 [reason:transparent_tcp_mapping_denied]"
	push(denied)
	push(denied)
	asks, _ := e.m.Approvals(t.Context(), "hpbox")
	if len(asks) != 1 || asks[0].Kind != sandboxapi.ApprovalKindHostPort || asks[0].Host != openshellHostAlias || asks[0].Port != 38830 ||
		!asks[0].Risky || asks[0].ChunkID != "" || !strings.Contains(asks[0].Reason, "port 38830 on your machine") {
		t.Fatalf("asks = %+v; want one for the declared port", asks)
	}
	ask := asks[0]
	requested := slices.DeleteFunc(e.events("hpbox", sandboxapi.ActivityApprovalRequested, ""), func(ev sandboxapi.ActivityEvent) bool { return ev.ApprovalID != ask.ID })
	// An ask is no blocked destination, and the denials that raised it are
	// the ask's, not refused requests of the destinations.
	if eg := e.get("hpbox").Egress; len(requested) != 1 || eg.BlockedRequests != 0 || eg.Blocked != 0 {
		t.Fatalf("%d approval.requested events, egress %+v; want 1 and no blocked destination or request", len(requested), eg)
	}
	if res, err := e.m.DecideApproval(t.Context(), ask.ID, approve); err != nil || res.Approval.Status != sandboxapi.ApprovalQueued {
		t.Fatalf("approve = %+v, %v", res, err)
	}
	rule := hostPortRule(38830)
	eventually(t, "the host port rule and the resolved approval", func() bool {
		pol, _ := e.fake.SandboxPolicy(openshell.DefaultWorkspace, "hpbox")
		r, ok := pol.NetworkPolicies[rule]
		return ok && len(r.Endpoints) == 1 && r.Endpoints[0].Host == openshellHostAlias && r.Endpoints[0].Port == 38830 &&
			slices.ContainsFunc(e.events("hpbox", sandboxapi.ActivityApprovalResolved, ""), func(ev sandboxapi.ActivityEvent) bool {
				return ev.ApprovalID == ask.ID && strings.Contains(ev.Message, "approved port 38830")
			})
	})
	if e.approvedRules("hpbox")[rule] != actorOperator {
		t.Fatal("the operator is not the recorded approver")
	}
	if len(where(&e.tel.mu, &e.tel.approvals, func(a audit.SandboxApprovalEvent) bool {
		return a.ApprovalID == ask.ID && a.Stage == audit.SandboxApprovalResolved && a.Result == audit.SandboxApprovalApproved
	})) == 0 {
		t.Fatal("no resolved approval record")
	}
	e.m.enforceAll(t.Context())
	if !e.hasRule("hpbox", rule) {
		t.Fatal("enforcement removed the approved host port")
	}
	push(denied)
	if asks, _ := e.m.Approvals(t.Context(), "hpbox"); len(asks) != 0 {
		t.Fatalf("the next denial asked again: %+v", asks)
	}

	e.create(sandboxapi.CreateRequest{Name: "hpadmin", HostPorts: []int{38830}, Project: e.otherProject("admin")})
	e.setConfig(func(c *config.Config) { c.OpenShell.Admin.AllowHostPorts = boolPtr(false) })
	e.m.refreshEgress()
	e.ocsf("hpadmin", "NET:OPEN [MED] DENIED /usr/bin/curl(0) -> host.openshell.internal:38830 [reason:transparent_tcp_mapping_denied]", time.Now())
	got := e.events("hpadmin", sandboxapi.ActivityEgressBlocked, sandboxapi.ReasonHostPortClosed)
	if len(got) != 1 || !strings.Contains(got[0].Message, "does not open port 38830") {
		t.Fatalf("feed = %+v", got)
	}
	if asks, _ := e.m.Approvals(t.Context(), "hpadmin"); len(asks) != 0 {
		t.Fatalf("asks = %+v", asks)
	}
}

// esc is an inert terminal control marker, which a terminal must never
// receive from sandbox text.
const esc = "\x1b[0mDCMARK\x07"

// Text a sandbox controls (a directory it creates, a hook's tool name, a
// proposal's binary and notes) reaches the feed and the API without terminal
// control characters.
func TestSandboxTextIsSafeToPrint(t *testing.T) {
	e := liveEnv(t, "textbox", nil)
	opts := e.guard.waitActive(t, e.project, true)
	opts.OnDetect(nestguard.Detection{Kind: nestguard.KindRepository, Dir: "src/" + esc, Quarantined: "src/" + esc + "/.git.q", At: time.Now()})
	e.m.ObserveHookDecision(HookDecision{BindingID: e.binding("textbox").ID, SandboxName: "textbox", Event: "PreToolUse", Tool: "Bash" + esc,
		Action: "block", Reason: "blocked " + esc})
	c := chunk("allow_host_openshell_internal_5432", "host.openshell.internal", 5432)
	c.Binary, c.SecurityNotes, c.Rationale = "/usr/bin/"+esc, "notes "+esc, "why "+esc
	e.addChunk("textbox", c)
	e.draft("textbox")
	asks := e.waitAsks("textbox", 1)
	got := e.get("textbox")
	if len(got.NestedRepos) != 1 || !strings.Contains(got.NestedRepos[0].Path, "DCMARK") {
		t.Fatalf("nested repos = %+v", got.NestedRepos)
	}
	for what, v := range map[string]any{"the activity feed": e.m.ActivitySince(0, "textbox"), "the approvals": asks, "the sandbox view": got} {
		data, err := json.Marshal(v)
		must(t, err)
		// JSON escapes control characters; their escapes must not appear.
		if s := string(data); strings.Contains(s, `\u001b`) || strings.Contains(s, `\u0007`) {
			t.Fatalf("%s carries control characters: %s", what, s)
		}
	}
}

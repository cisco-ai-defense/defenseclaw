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
	"errors"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/audit"
	"github.com/defenseclaw/defenseclaw/internal/openshell/egress"
	"github.com/defenseclaw/defenseclaw/internal/openshell/sandboxapi"
)

// refusingTelemetry refuses egress records while refuse is set and keeps
// the health records it is given.
type refusingTelemetry struct {
	nopTelemetry
	mu     sync.Mutex
	refuse bool
	health []audit.SandboxHealthEvent
}

func (r *refusingTelemetry) RecordSandboxEgress(context.Context, audit.SandboxEgressEvent) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.refuse {
		return errors.New("runtime unavailable")
	}
	return nil
}

func (r *refusingTelemetry) RecordSandboxHealth(_ context.Context, e audit.SandboxHealthEvent) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.health = append(r.health, e)
	return nil
}

// A refused record is not swallowed where its caller ignores the error: the
// first of a streak is logged and recorded as degraded health, every one is
// counted for `sandbox status`, and an accepted record ends the streak.
func TestTelemetryGuardReportsRefusedRecords(t *testing.T) {
	next := &refusingTelemetry{refuse: true}
	var logs []string
	g := newTelemetryGuard(next, HostUser{UID: 1000, GID: 1000, Name: "dev"},
		func(format string, args ...any) { logs = append(logs, fmt.Sprintf(format, args...)) }, time.Now)
	ctx, ev := context.Background(), audit.SandboxEgressEvent{Sandbox: audit.SandboxIdentity{Name: "box"}}
	for range 3 {
		if err := g.RecordSandboxEgress(ctx, ev); err == nil {
			t.Fatal("a refused record was reported accepted")
		}
	}
	if n, last := g.failureStatus(); n != 3 || !strings.Contains(last, "egress record of sandbox box: runtime unavailable") {
		t.Fatalf("failures = %d %q", n, last)
	}
	if len(next.health) != 1 || next.health[0].State != audit.SandboxHealthDegraded || next.health[0].ErrorCode != "openshell_telemetry_failed" {
		t.Fatalf("health = %+v", next.health)
	}
	if len(logs) != 1 || !strings.Contains(logs[0], "OPENSHELL_TELEMETRY_FAILED") {
		t.Fatalf("logs = %q", logs)
	}
	next.refuse = false
	if err := g.RecordSandboxEgress(ctx, ev); err != nil {
		t.Fatal(err)
	}
	next.refuse = true
	_ = g.RecordSandboxEgress(ctx, ev)
	if len(next.health) != 2 || len(logs) != 3 {
		t.Fatalf("a new streak: health %d logs %q", len(next.health), logs)
	}
}

// Every record of a sandbox carries its binding, the host account that
// launched it and the session its hooks last named; the egress records of
// OpenShell's connections name the binary and its process.
func TestRecordsCarryTheSandboxsBindingUserAndSession(t *testing.T) {
	e := liveEnv(t, "idbox", nil)
	binding := e.binding("idbox").ID
	e.m.ObserveHookDecision(HookDecision{BindingID: binding, SandboxName: "idbox", Event: "PreToolUse", Tool: "Bash",
		ToolUseID: "toolu_1", SessionID: "session-7", Action: "allow"})
	e.ocsf("idbox", "NET:OPEN [INFO] ALLOWED /usr/bin/curl(77) -> files.example.org:443/tcp [policy:allow_files engine:opa]", time.Now())
	recs := where(&e.tel.mu, &e.tel.egress, func(r audit.SandboxEgressEvent) bool { return r.Host == "files.example.org" })
	if len(recs) != 1 {
		t.Fatalf("egress = %+v", recs)
	}
	if r := recs[0]; r.Sandbox.BindingID != binding || r.UserID != "1000" || r.UserName != "dev" || r.ConversationID != "session-7" ||
		r.PID != 77 || r.Executable != "/usr/bin/curl" {
		t.Fatalf("egress record = %+v", r)
	}
	// A new session's records do not carry the last one's.
	e.stopBox("idbox")
	e.startBox("idbox", sandboxapi.StartRequest{})
	e.ocsf("idbox", "NET:OPEN [INFO] ALLOWED /usr/bin/curl(78) -> files.example.org:443/tcp [policy:allow_files engine:opa]", time.Now())
	recs = where(&e.tel.mu, &e.tel.egress, func(r audit.SandboxEgressEvent) bool { return r.Host == "files.example.org" })
	if len(recs) != 2 || recs[1].ConversationID != "" {
		t.Fatalf("egress after a restart = %+v", recs)
	}
}

// The end of an allowed tunnel is recorded with its bytes and duration, an
// upstream failure as failed (timed out on a 504), and the proxy's refusals
// of invalid credentials as paced degraded health.
func TestEgressEndsAndCredentialRefusals(t *testing.T) {
	e := newEnv(t, nil)
	ctx, now := context.Background(), time.Now()
	// The clock is swapped before the sandbox's goroutines read it.
	now2, advance := e.fakeClock(now)
	e.live(sandboxapi.CreateRequest{Name: "endbox"})
	id := e.binding("endbox").ID
	e.m.egressEvent(ctx, egress.Event{Kind: egress.EventClosed, Time: now, BindingID: id, SandboxName: "endbox", Method: "CONNECT",
		Host: "registry.npmjs.org", Port: 443, BytesUp: 1200, BytesDown: 98000, Duration: 2 * time.Second, RemoteAddr: "104.16.0.1:443"}, 0)
	e.m.egressEvent(ctx, egress.Event{Kind: egress.EventFailed, Time: now, BindingID: id, SandboxName: "endbox", Method: "CONNECT",
		Host: "slow.example", Port: 443, Status: http.StatusGatewayTimeout, Error: "upstream timed out", Duration: 30 * time.Second}, 0)
	recs := where(&e.tel.mu, &e.tel.egress, func(r audit.SandboxEgressEvent) bool { return r.End != "" })
	if len(recs) != 2 {
		t.Fatalf("ended = %+v", recs)
	}
	if c := recs[0]; c.End != audit.SandboxEgressCompleted || c.BytesUp != 1200 || c.BytesDown != 98000 || c.Duration != 2*time.Second ||
		c.ResolvedIP != "104.16.0.1" || c.Blocked {
		t.Fatalf("completed = %+v", c)
	}
	if f := recs[1]; f.End != audit.SandboxEgressFailed || !f.TimedOut || f.Reason != "upstream timed out" || f.DecisionCode != "SANDBOX_EGRESS_UPSTREAM_FAILED" {
		t.Fatalf("failed = %+v", f)
	}

	authFailed := func() {
		e.m.egressEvent(ctx, egress.Event{Kind: egress.EventAuthFailed, Time: now2(), Method: "CONNECT", Host: "x.example", Port: 443}, 0)
	}
	authFailures := func() []audit.SandboxHealthEvent {
		return where(&e.tel.mu, &e.tel.health, func(h audit.SandboxHealthEvent) bool { return h.ErrorCode == "openshell_egress_auth_failed" })
	}
	authFailed()
	authFailed()
	authFailed()
	if got := authFailures(); len(got) != 1 || !strings.Contains(got[0].ErrorSummary, "refused 1 request(s)") || got[0].Sandbox.Name != "" {
		t.Fatalf("first report = %+v", got)
	}
	advance(authFailedEvery)
	e.m.reportAuthFailures(ctx, now2())
	if got := authFailures(); len(got) != 2 || !strings.Contains(got[1].ErrorSummary, "refused 2 request(s)") || !strings.Contains(got[1].ErrorSummary, "x.example") {
		t.Fatalf("paced report = %+v", got)
	}
	e.m.reportAuthFailures(ctx, now2().Add(time.Hour))
	if got := authFailures(); len(got) != 2 {
		t.Fatalf("a report with nothing new = %+v", got)
	}
}

// OpenShell's process, SSH and inference records become sandbox activity
// records; process records are paced per sandbox.
func TestOCSFActivityRecords(t *testing.T) {
	e := newEnv(t, nil)
	at := time.Now()
	// No refill while the records go in. The clock is swapped before the
	// sandbox's goroutines read it.
	e.fakeClock(at)
	e.live(sandboxapi.CreateRequest{Name: "actbox"})
	for _, line := range []string{
		"PROC:LAUNCH [INFO] python3(42) [cmd:python3 /work/app/main.py dccert-block-marker]",
		"PROC:TERMINATE [INFO] python3(42) [exit:3]",
		"SSH:OPEN [INFO] ALLOWED 10.42.0.1:48201 [auth:NSSH1]",
		"API:INFERENCE [INFO] Success claude-haiku via anthropic 812ms [messages:create]",
		"API:INFERENCE [INFO] Error claude-haiku via anthropic 90ms [messages:create]",
	} {
		e.ocsf("actbox", line, at)
	}
	acts := where(&e.tel.mu, &e.tel.activity, nil)
	if len(acts) != 5 {
		t.Fatalf("activity = %+v", acts)
	}
	if p := acts[0]; p.Kind != audit.SandboxActivityProcess || p.ProcessEvent != audit.SandboxProcessStart || p.PID != 42 ||
		p.Executable != "python3" || p.CommandLine != "python3 /work/app/main.py dccert-block-marker" || p.UserName != "dev" {
		t.Fatalf("launch = %+v", p)
	}
	if p := acts[1]; p.ProcessEvent != audit.SandboxProcessExit || p.ExitCode == nil || *p.ExitCode != 3 {
		t.Fatalf("terminate = %+v", p)
	}
	if s := acts[2]; s.Kind != audit.SandboxActivitySSH || s.SSHActivity != "OPEN" || !s.SSHAllowed || s.SSHAuth != "NSSH1" || s.Peer != "10.42.0.1:48201" {
		t.Fatalf("ssh = %+v", s)
	}
	if i := acts[3]; i.Kind != audit.SandboxActivityInference || i.Provider != "anthropic" || i.Model != "claude-haiku" ||
		i.Latency != 812*time.Millisecond || i.Operation != "messages:create" {
		t.Fatalf("inference = %+v", i)
	}
	d, err := e.m.Destinations(context.Background(), "actbox")
	if err != nil || len(d.Models) != 1 || d.Models[0].Calls != 2 || d.Models[0].Failed != 1 || d.Models[0].Model != "claude-haiku" {
		t.Fatalf("models = %+v, %v", d, err)
	}
	for i := range activityBurst + 50 {
		e.ocsf("actbox", fmt.Sprintf("PROC:LAUNCH [INFO] sh(%d)", 1000+i), at)
	}
	launches := where(&e.tel.mu, &e.tel.activity, func(a audit.SandboxActivityEvent) bool { return a.ProcessEvent == audit.SandboxProcessStart })
	// The burst, of which the first launch and the terminate took two.
	if n := len(launches); n != activityBurst-1 {
		t.Fatalf("paced launches = %d, want %d", n, activityBurst-1)
	}
}

// An allowed connection to a host port other than DefenseClaw's own is an
// allowed egress record and a destination.
func TestAllowedHostPortConnectionsAreRecorded(t *testing.T) {
	e := liveEnv(t, "portbox", nil)
	e.ocsf("portbox", "NET:OPEN [INFO] ALLOWED /usr/bin/node(9) -> host.openshell.internal:8080/tcp [policy:allow_host_openshell_internal_8080 engine:opa]", time.Now())
	recs := where(&e.tel.mu, &e.tel.egress, func(r audit.SandboxEgressEvent) bool { return r.Host == openshellHostAlias })
	if len(recs) != 1 || recs[0].Port != 8080 || recs[0].Blocked || recs[0].DecisionCode != "SANDBOX_EGRESS_ALLOWED" || recs[0].PID != 9 {
		t.Fatalf("host port = %+v", recs)
	}
	d, _ := e.m.Destinations(context.Background(), "portbox")
	if len(d.Destinations) != 1 || d.Destinations[0].Host != openshellHostAlias || d.Destinations[0].Ports[0] != 8080 {
		t.Fatalf("destinations = %+v", d.Destinations)
	}
}

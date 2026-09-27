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
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/audit"
	"github.com/defenseclaw/defenseclaw/internal/openshell/ocsf"
	"github.com/defenseclaw/defenseclaw/internal/openshell/sandboxapi"
	"github.com/defenseclaw/defenseclaw/internal/sandboxauth"
)

// reachEnv is a manager with one ready sandbox and a clock the test moves.
type reachEnv struct {
	*harnessEnv
	name    string
	binding sandboxauth.Binding
	mu      sync.Mutex
	now     time.Time
}

func newReachEnv(t *testing.T) *reachEnv {
	t.Helper()
	r := &reachEnv{harnessEnv: newEnv(t, nil), now: time.Now()}
	clock := func() time.Time { r.mu.Lock(); defer r.mu.Unlock(); return r.now }
	r.m.opts.Now, r.m.now = clock, clock
	sb := r.create(sandboxapi.CreateRequest{Name: "reachbox"})
	r.name = sb.Name
	r.binding, _ = r.store.Lookup(sb.Name)
	return r
}

func (r *reachEnv) advance(d time.Duration) {
	r.mu.Lock()
	r.now = r.now.Add(d)
	r.mu.Unlock()
}

func (r *reachEnv) clock() time.Time { return r.m.now() }

// ocsf feeds one OpenShell shorthand line to the sandbox, stamped now.
func (r *reachEnv) ocsf(line string) {
	r.t.Helper()
	rec, err := ocsf.Parse(line)
	if err != nil {
		r.t.Fatalf("parse %q: %v", line, err)
	}
	r.m.ocsfEvent(context.Background(), r.m.boxes[r.name], rec, r.clock())
}

func (r *reachEnv) hooks() sandboxapi.HookCoverage {
	r.t.Helper()
	sb, err := r.m.Get(context.Background(), r.name)
	if err != nil {
		r.t.Fatal(err)
	}
	return sb.Hooks
}

func (r *reachEnv) feed(reason string) []sandboxapi.ActivityEvent {
	var out []sandboxapi.ActivityEvent
	for _, ev := range r.m.ActivitySince(0, r.name) {
		if ev.Reason == reason {
			out = append(out, ev)
		}
	}
	return out
}

func (r *reachEnv) findings() []audit.SandboxFindingEvent {
	var out []audit.SandboxFindingEvent
	for _, f := range r.tel.findings {
		if f.Title == "Sandbox hooks are not reaching DefenseClaw" {
			out = append(out, f)
		}
	}
	return out
}

var ingressLine = func(action string) string {
	return "NET:OPEN [MED] " + action + " /usr/bin/curl(7) -> host.openshell.internal:" + strconv.Itoa(testIngressPort) + " [policy:defenseclaw_ingress engine:opa]"
}

// OpenShell refusing the hooks' connections is reported at once, even
// after hooks that got through; an authenticated hook clears the flag, and
// the session is warned only once.
func TestHookReachRefusedConnections(t *testing.T) {
	r := newReachEnv(t)
	r.ocsf(ingressLine("DENIED"))
	h := r.hooks()
	if !h.Unreachable || h.IngressRefused != 1 || h.LastIngressRefusedAt.IsZero() ||
		!strings.Contains(h.UnreachableReason, "OpenShell refused") || !strings.Contains(h.UnreachableReason, strconv.Itoa(testIngressPort)) {
		t.Fatalf("hooks = %+v", h)
	}
	warn := r.feed(sandboxapi.ReasonHooksUnreachable)
	if len(warn) != 1 || warn[0].Severity != "HIGH" || warn[0].Kind != sandboxapi.ActivityFinding ||
		!strings.HasPrefix(warn[0].Message, "⚠ "+sandboxapi.HooksUnreachableWarning+" (OpenShell refused") ||
		!strings.HasSuffix(warn[0].Message, sandboxapi.HooksDoctorHint) {
		t.Fatalf("feed = %+v", warn)
	}
	if f := r.findings(); len(f) != 1 || f[0].Kind != audit.SandboxFindingHookSilence || f[0].Severity != "HIGH" ||
		!strings.Contains(f[0].Remediation, "defenseclaw sandbox doctor") {
		t.Fatalf("findings = %+v", f)
	}

	r.advance(time.Second)
	r.m.ObserveIngress(r.binding, sandboxauth.RouteHook)
	if h := r.hooks(); h.Unreachable || h.UnreachableReason != "" {
		t.Fatalf("a hook did not clear the flag: %+v", h)
	}
	if n := len(r.feed(sandboxapi.ReasonHooksRestored)); n != 1 {
		t.Fatalf("restored events = %d", n)
	}
	// Hooks that break later in the session are flagged again, without a
	// second warning.
	r.advance(time.Second)
	r.ocsf(ingressLine("DENIED"))
	if h := r.hooks(); !h.Unreachable || h.IngressRefused != 2 {
		t.Fatalf("hooks after a later refusal = %+v", h)
	}
	if n := len(r.feed(sandboxapi.ReasonHooksUnreachable)); n != 1 {
		t.Fatalf("warnings = %d, want 1 per session", n)
	}
}

// A hook connection OpenShell let through that never became an
// authenticated request is flagged once the grace period ends.
func TestHookReachUnansweredConnections(t *testing.T) {
	r := newReachEnv(t)
	r.ocsf(ingressLine("ALLOWED"))
	r.advance(hookAttemptGrace - time.Second)
	r.m.checkHookReach(context.Background())
	if h := r.hooks(); h.Unreachable {
		t.Fatalf("flagged within the grace period: %+v", h)
	}
	r.advance(2 * time.Second)
	r.m.checkHookReach(context.Background())
	if h := r.hooks(); !h.Unreachable || !strings.Contains(h.UnreachableReason, "not one request authenticated") || h.IngressRefused != 0 {
		t.Fatalf("hooks = %+v", h)
	}
}

// A harness that works without a single hook is flagged after the window;
// one whose hooks arrived is not.
func TestHookReachSilentWork(t *testing.T) {
	for _, work := range []struct {
		name string
		do   func(*reachEnv)
	}{
		{"model call", func(r *reachEnv) {
			r.ocsf("HTTP:POST [INFO] ALLOWED POST https://api.anthropic.com/v1/messages [policy:anthropic engine:l7]")
		}},
		{"local model endpoint", func(r *reachEnv) {
			r.ocsf("NET:OPEN [INFO] ALLOWED /usr/bin/node(9) -> host.openshell.internal:28921 [policy:dc_cred_1 engine:opa]")
		}},
		{"otlp", func(r *reachEnv) { r.m.ObserveIngress(r.binding, sandboxauth.RouteOTLP) }},
	} {
		t.Run(work.name, func(t *testing.T) {
			r := newReachEnv(t)
			work.do(r)
			r.advance(DefaultHookReachWindow - time.Second)
			r.m.checkHookReach(context.Background())
			if h := r.hooks(); h.Unreachable {
				t.Fatalf("flagged within the window: %+v", h)
			}
			r.advance(2 * time.Second)
			r.m.checkHookReach(context.Background())
			if h := r.hooks(); !h.Unreachable || !strings.Contains(h.UnreachableReason, "the harness has been working for 31s") {
				t.Fatalf("hooks = %+v", h)
			}
		})
	}
	r := newReachEnv(t)
	r.m.ObserveIngress(r.binding, sandboxauth.RouteHook)
	r.ocsf("HTTP:POST [INFO] ALLOWED POST https://api.anthropic.com/v1/messages [policy:anthropic engine:l7]")
	r.advance(time.Hour)
	r.m.checkHookReach(context.Background())
	if h := r.hooks(); h.Unreachable {
		t.Fatalf("a session with hooks was flagged: %+v", h)
	}
}

// Nothing flags an idle sandbox, the egress proxy's own relay, or records
// replayed from before the session.
func TestHookReachQuietCases(t *testing.T) {
	r := newReachEnv(t)
	r.ocsf("NET:OPEN [INFO] ALLOWED /usr/bin/curl(3) -> host.openshell.internal:" + strconv.Itoa(testEgressPort) + " [policy:defenseclaw_egress engine:opa]")
	r.ocsf("PROC:LAUNCH [INFO] git(42) [cmd:git status]")
	rec, err := ocsf.Parse(ingressLine("DENIED"))
	if err != nil {
		t.Fatal(err)
	}
	b := r.m.boxes[r.name]
	r.m.ocsfEvent(context.Background(), b, rec, r.clock().Add(-time.Hour))
	r.advance(time.Hour)
	r.m.checkHookReach(context.Background())
	if h := r.hooks(); h.Unreachable || h.IngressRefused != 1 {
		t.Fatalf("hooks = %+v", h)
	}
	if n := len(r.feed(sandboxapi.ReasonHooksUnreachable)); n != 0 {
		t.Fatalf("warnings = %d", n)
	}
}

// A new session (the sandbox ready again) starts over: the flag clears and
// its first problem is warned about again.
func TestHookReachNewSessionStartsOver(t *testing.T) {
	r := newReachEnv(t)
	r.ocsf(ingressLine("DENIED"))
	if !r.hooks().Unreachable {
		t.Fatal("not flagged")
	}
	ctx := context.Background()
	b := r.m.boxes[r.name]
	r.m.lifecycle(ctx, b, audit.SandboxPhaseStopped, audit.SandboxTriggerStop, false, nil, nil)
	r.advance(time.Minute)
	r.m.lifecycle(ctx, b, audit.SandboxPhaseReady, audit.SandboxTriggerStart, false, nil, nil)
	if h := r.hooks(); h.Unreachable || h.IngressRefused != 1 {
		t.Fatalf("hooks of the new session = %+v", h)
	}
	r.advance(time.Second)
	r.ocsf(ingressLine("DENIED"))
	if n := len(r.feed(sandboxapi.ReasonHooksUnreachable)); n != 2 {
		t.Fatalf("warnings = %d, want one per session", n)
	}
}

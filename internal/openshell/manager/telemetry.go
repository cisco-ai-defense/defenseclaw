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
	"sync"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/audit"
	"github.com/defenseclaw/defenseclaw/internal/gatewaylog"
)

// telemetryGuard is the manager's sandbox telemetry: the recorder
// (Options.Telemetry) behind two things every record needs.
//
// It stamps each record with what the manager knows of the sandbox and the
// producer at the call site does not: the host account that launched it (the
// daemon's own user, which the sandbox's binding stores too) and the harness
// session its hooks last named (ObserveHookDecision), as
// gen_ai.conversation.id.
//
// And it reports every record the recorder refuses, so a call site that
// ignores the error swallows nothing: the first refusal of a streak is
// logged with its error and recorded as degraded sandbox health, the later
// ones are counted (Status.TelemetryFailures) and logged every
// telemetryLogEvery, and the next accepted record ends the streak.
type telemetryGuard struct {
	next             audit.SandboxTelemetry
	logf             func(string, ...any)
	now              func() time.Time
	userID, userName string

	// sessions maps a sandbox name to the session its hooks last named.
	// It has its own lock: producers record with or without Manager.mu.
	sessions sync.Map

	mu       sync.Mutex
	failures int64
	streak   int64
	lastErr  string
}

// telemetryLogEvery is how often a streak of refused records is logged
// again.
const telemetryLogEvery = 100

func newTelemetryGuard(next audit.SandboxTelemetry, host HostUser, logf func(string, ...any), now func() time.Time) *telemetryGuard {
	if next == nil {
		next = nopTelemetry{}
	}
	return &telemetryGuard{next: next, logf: logf, now: now, userID: strconv.Itoa(host.UID), userName: host.Name}
}

// noteSession records the session a sandbox's hooks named; a hook without
// one leaves the last.
func (g *telemetryGuard) noteSession(sandbox, session string) {
	if sandbox != "" && session != "" {
		g.sessions.Store(sandbox, truncate(session, 256))
	}
}

// forgetSandbox drops what the guard keeps of a deleted sandbox.
func (g *telemetryGuard) forgetSandbox(sandbox string) { g.sessions.Delete(sandbox) }

func (g *telemetryGuard) session(sandbox string) string {
	s, _ := g.sessions.Load(sandbox)
	session, _ := s.(string)
	return session
}

// failureStatus is what Status reports of refused records.
func (g *telemetryGuard) failureStatus() (int64, string) {
	g.mu.Lock()
	defer g.mu.Unlock()
	return g.failures, g.lastErr
}

// done reports the outcome of one record of kind about sandbox (empty for
// the integration as a whole) and returns err.
func (g *telemetryGuard) done(ctx context.Context, kind, sandbox string, err error) error {
	g.mu.Lock()
	if err == nil {
		ended := g.streak
		g.streak = 0
		g.mu.Unlock()
		if ended > 0 {
			g.logf("sandbox telemetry accepts records again (%d refused in a row before)", ended)
		}
		return nil
	}
	g.failures++
	g.streak++
	first, total := g.streak == 1, g.failures
	what := kind + " record"
	if sandbox != "" {
		what += " of sandbox " + sandbox
	}
	g.lastErr = truncate(what+": "+err.Error(), 512)
	g.mu.Unlock()
	if first || total%telemetryLogEvery == 0 {
		g.logf("%s: sandbox telemetry refused a %s: %v (%d refused since the daemon started; `defenseclaw sandbox status` counts them)",
			gatewaylog.ErrCodeOpenShellTelemetryFailed, what, err, total)
	}
	if first && kind != "health" {
		// Through the recorder that just refused one: a runtime that is
		// down refuses this too, which the count above still reports.
		_ = g.next.RecordSandboxHealth(context.WithoutCancel(ctx), audit.SandboxHealthEvent{
			State: audit.SandboxHealthDegraded, ErrorCode: errorToken(gatewaylog.ErrCodeOpenShellTelemetryFailed),
			ErrorSummary: truncate("sandbox telemetry refused a "+what+": "+err.Error(), 512), Timestamp: g.now(),
		})
	}
	return err
}

func (g *telemetryGuard) RecordSandboxLifecycle(ctx context.Context, e audit.SandboxLifecycleEvent) error {
	return g.done(ctx, "lifecycle", e.Sandbox.Name, g.next.RecordSandboxLifecycle(ctx, e))
}

func (g *telemetryGuard) RecordSandboxEgress(ctx context.Context, e audit.SandboxEgressEvent) error {
	if e.UserID == "" {
		e.UserID, e.UserName = g.userID, g.userName
	}
	if e.ConversationID == "" {
		e.ConversationID = g.session(e.Sandbox.Name)
	}
	return g.done(ctx, "egress", e.Sandbox.Name, g.next.RecordSandboxEgress(ctx, e))
}

func (g *telemetryGuard) RecordSandboxApproval(ctx context.Context, e audit.SandboxApprovalEvent) error {
	if e.UserID == "" {
		e.UserID, e.UserName = g.userID, g.userName
	}
	if e.ConversationID == "" {
		e.ConversationID = g.session(e.Sandbox.Name)
	}
	return g.done(ctx, "approval", e.Sandbox.Name, g.next.RecordSandboxApproval(ctx, e))
}

func (g *telemetryGuard) RecordSandboxPolicy(ctx context.Context, e audit.SandboxPolicyEvent) error {
	return g.done(ctx, "policy", e.Sandbox.Name, g.next.RecordSandboxPolicy(ctx, e))
}

func (g *telemetryGuard) RecordSandboxHealth(ctx context.Context, e audit.SandboxHealthEvent) error {
	return g.done(ctx, "health", e.Sandbox.Name, g.next.RecordSandboxHealth(ctx, e))
}

func (g *telemetryGuard) RecordSandboxFinding(ctx context.Context, e audit.SandboxFindingEvent) error {
	if e.UserID == "" {
		e.UserID, e.UserName = g.userID, g.userName
	}
	return g.done(ctx, "finding", e.Sandbox.Name, g.next.RecordSandboxFinding(ctx, e))
}

func (g *telemetryGuard) RecordSandboxWorkspace(ctx context.Context, e audit.SandboxWorkspaceEvent) error {
	return g.done(ctx, "workspace", e.Sandbox.Name, g.next.RecordSandboxWorkspace(ctx, e))
}

func (g *telemetryGuard) RecordSandboxActivity(ctx context.Context, e audit.SandboxActivityEvent) error {
	if e.UserID == "" {
		e.UserID, e.UserName = g.userID, g.userName
	}
	if e.ConversationID == "" {
		e.ConversationID = g.session(e.Sandbox.Name)
	}
	return g.done(ctx, string(e.Kind), e.Sandbox.Name, g.next.RecordSandboxActivity(ctx, e))
}

func (g *telemetryGuard) RecordSandboxProcess(ctx context.Context, e audit.SandboxProcessEvent) error {
	return g.done(ctx, "process tree", e.Sandbox.Name, g.next.RecordSandboxProcess(ctx, e))
}

type nopTelemetry struct{}

func (nopTelemetry) RecordSandboxLifecycle(context.Context, audit.SandboxLifecycleEvent) error {
	return nil
}
func (nopTelemetry) RecordSandboxEgress(context.Context, audit.SandboxEgressEvent) error { return nil }
func (nopTelemetry) RecordSandboxApproval(context.Context, audit.SandboxApprovalEvent) error {
	return nil
}
func (nopTelemetry) RecordSandboxPolicy(context.Context, audit.SandboxPolicyEvent) error { return nil }
func (nopTelemetry) RecordSandboxHealth(context.Context, audit.SandboxHealthEvent) error { return nil }
func (nopTelemetry) RecordSandboxFinding(context.Context, audit.SandboxFindingEvent) error {
	return nil
}
func (nopTelemetry) RecordSandboxWorkspace(context.Context, audit.SandboxWorkspaceEvent) error {
	return nil
}
func (nopTelemetry) RecordSandboxActivity(context.Context, audit.SandboxActivityEvent) error {
	return nil
}
func (nopTelemetry) RecordSandboxProcess(context.Context, audit.SandboxProcessEvent) error {
	return nil
}

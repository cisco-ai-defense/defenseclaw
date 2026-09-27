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
	"path"
	"strconv"
	"strings"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/audit"
	"github.com/defenseclaw/defenseclaw/internal/gatewaylog"
	"github.com/defenseclaw/defenseclaw/internal/openshell/harness"
	"github.com/defenseclaw/defenseclaw/internal/openshell/ocsf"
	"github.com/defenseclaw/defenseclaw/internal/openshell/sandboxapi"
	"github.com/defenseclaw/defenseclaw/internal/openshell/stream"
	"github.com/defenseclaw/defenseclaw/internal/openshell/triage"
)

// watchRetry paces restarting a watch that ended with an error.
const watchRetry = 10 * time.Second

// startWatch runs the sandbox's watcher unless one is running already or
// the manager is not running.
func (m *Manager) startWatch(b *box) {
	runCtx := m.running()
	if runCtx == nil {
		return
	}
	m.mu.Lock()
	if b.watchCancel != nil || b.deleted {
		m.mu.Unlock()
		return
	}
	ctx, cancel := context.WithCancel(runCtx)
	done := make(chan struct{})
	b.watchCancel, b.watchDone = cancel, done
	name := b.rec.Name
	m.mu.Unlock()
	go func() {
		defer close(done)
		defer func() {
			m.mu.Lock()
			if b.watchDone == done {
				b.watchCancel, b.watchDone = nil, nil
			}
			m.mu.Unlock()
			cancel()
		}()
		m.watchLoop(ctx, b, name)
	}()
}

func (m *Manager) stopWatch(b *box) {
	m.stopGuard(b)
	m.mu.Lock()
	cancel, done := b.watchCancel, b.watchDone
	b.watchCancel, b.watchDone = nil, nil
	m.mu.Unlock()
	if cancel != nil {
		cancel()
		<-done
	}
}

func (m *Manager) stopWatchers() {
	m.mu.Lock()
	boxes := make([]*box, 0, len(m.boxes))
	for _, b := range m.boxes {
		boxes = append(boxes, b)
	}
	m.mu.Unlock()
	for _, b := range boxes {
		m.stopWatch(b)
	}
}

func (m *Manager) watchLoop(ctx context.Context, b *box, name string) {
	for ctx.Err() == nil {
		gw, err := m.gateway(ctx)
		if err == nil {
			m.mu.Lock()
			cursor := b.rec.Cursor
			m.mu.Unlock()
			err = m.opts.Watch(ctx, gw, name, cursor, func(c string) error { return m.saveCursor(b, c) },
				func(ev stream.Event) { m.handleEvent(ctx, b, ev) })
		}
		if ctx.Err() != nil {
			return
		}
		if errors.Is(err, stream.ErrSandboxNotFound) {
			// Deleted outside DefenseClaw: reconcile releases what it held.
			go m.reconcileOne(context.WithoutCancel(ctx), name)
			return
		}
		if err != nil {
			m.logf("%s: watch %s: %v", gatewaylog.ErrCodeOpenShellWatchFailed, name, err)
		}
		t := time.NewTimer(watchRetry)
		select {
		case <-ctx.Done():
			t.Stop()
			return
		case <-t.C:
		}
	}
}

func (m *Manager) saveCursor(b *box, cursor string) error {
	m.mu.Lock()
	if b.deleted || b.rec.Cursor == cursor {
		m.mu.Unlock()
		return nil
	}
	b.rec.Cursor = cursor
	m.mu.Unlock()
	return m.saveRecord(b)
}

// handleEvent maps one WatchSandbox event onto telemetry, the feed and
// triage.
func (m *Manager) handleEvent(ctx context.Context, b *box, ev stream.Event) {
	switch ev.Kind {
	case stream.KindStatus:
		m.statusEvent(ctx, b, ev.Status)
	case stream.KindLog:
		if ev.Log != nil && ev.Log.OCSF != nil {
			m.ocsfEvent(ctx, b, *ev.Log.OCSF, ev.Time)
		}
	case stream.KindDraft:
		m.triageSandbox(ctx, b)
	case stream.KindGap:
		m.mu.Lock()
		id := b.identity()
		m.mu.Unlock()
		_ = m.tel.RecordSandboxHealth(ctx, audit.SandboxHealthEvent{Sandbox: id, State: audit.SandboxHealthDegraded,
			ErrorCode: errorToken(gatewaylog.ErrCodeOpenShellWatchFailed), ErrorSummary: "sandbox events were lost: " + ev.Gap.Reason, Timestamp: m.now()})
	case stream.KindConnected:
		// A reconnect may have missed a draft notification.
		m.triageSandbox(ctx, b)
	}
}

func (m *Manager) statusEvent(ctx context.Context, b *box, st *stream.Status) {
	if st == nil {
		return
	}
	m.mu.Lock()
	if b.sb != nil {
		b.sb.Status.Phase = st.Phase
		b.sb.Status.CurrentPolicyVersion = st.PolicyVersion
		b.sb.Status.ExitCode = st.ExitCode
	}
	if b.rec.ID == "" && st.ID != "" {
		b.rec.ID = st.ID
	}
	creating := b.creating
	m.mu.Unlock()
	if creating {
		return
	}
	// A failing condition explains the phase.
	var cond *audit.SandboxCondition
	for _, c := range st.Conditions {
		if !strings.EqualFold(c.Status, "true") {
			cond = &audit.SandboxCondition{Type: c.Type, Status: c.Status, Reason: c.Reason, Message: c.Message}
			break
		}
	}
	phase := auditPhase(st.Phase)
	if phase == audit.SandboxPhaseUnknown {
		return
	}
	m.lifecycle(ctx, b, phase, audit.SandboxTriggerWatch, false, cond, st.ExitCode)
}

// ocsfEvent handles one OpenShell OCSF record.
func (m *Manager) ocsfEvent(ctx context.Context, b *box, r ocsf.Record, at time.Time) {
	if at.IsZero() {
		at = m.now()
	}
	m.mu.Lock()
	id := b.identity()
	name, harnessName := b.rec.Name, b.rec.Harness
	m.mu.Unlock()
	switch r.Class {
	case ocsf.ClassNetwork, ocsf.ClassHTTP:
		host := triage.NormalizeHost(r.Host)
		if host == openshellHostAlias {
			m.hostAliasEvent(ctx, b, r, at, harnessName)
			return
		}
		if host == "" {
			return
		}
		// The harness's own background request around the proxy is refused
		// as expected and is none of the agent's doing: it is audited, but
		// neither counted as a blocked site nor shown on the feed, where
		// triage's rejection of its proposal explains it once, and it is no
		// sign of work (the Codex TUI makes it at start, before any prompt).
		fetch := r.Denied() && harnessFetchDenial(harnessName, r, host)
		ofHarness := harnessActivity(harnessName, r.Binary)
		if !fetch {
			m.markWork(b, at, ofHarness)
		} else if ofHarness {
			m.markActive(b, at)
		}
		if !r.Denied() && !r.Allowed() {
			return
		}
		ev := audit.SandboxEgressEvent{
			Sandbox: id, Source: audit.SandboxEgressSourceOpenShell, Host: host, Port: r.Port, Path: r.Path,
			Blocked: r.Denied(), Reason: truncate(firstNonEmpty(r.Reason, r.Message), 512), PolicyOutcome: truncate(r.Policy, 256),
			Timestamp: at,
		}
		if r.Denied() {
			ev.DecisionCode = "SANDBOX_EGRESS_OPENSHELL_DENIED"
			if !fetch {
				m.mu.Lock()
				b.blocked++
				m.mu.Unlock()
			}
			// OpenShell drafts a proposal for the denied destination a few
			// seconds later; OpenShell 0.1.1 does not always announce it
			// on the stream.
			m.scheduleTriage(b)
		} else {
			ev.DecisionCode = "SANDBOX_EGRESS_ALLOWED"
		}
		if r.Class == ocsf.ClassHTTP {
			ev.Scheme = schemeOf(r.URL)
		}
		_ = m.tel.RecordSandboxEgress(ctx, ev)
		if r.Denied() && !fetch {
			m.feed.Publish(sandboxapi.ActivityEvent{Time: at, Kind: sandboxapi.ActivityEgressBlocked, Sandbox: name, Host: host, Port: r.Port,
				Source: sandboxapi.SourceOpenShell, Reason: r.Reason, Message: "✗ " + host + " (direct connection denied by OpenShell)"})
		}
	case ocsf.ClassProcess:
		if harnessActivity(harnessName, r.Binary) {
			m.markActive(b, at)
		}
	case ocsf.ClassFinding:
		severity := ocsfSeverity(r.Severity)
		ev := audit.SandboxFindingEvent{
			Sandbox: id, Kind: audit.SandboxFindingOCSF, Severity: severity, Title: truncate(firstNonEmpty(r.Title, "OpenShell finding"), 256),
			Description: truncate(r.Message, 1024), Evidence: truncate(r.Raw, 1024), TargetRef: firstNonEmpty(r.Host, r.Binary),
			Timestamp: at,
		}
		if c, err := parseConfidence(r.Confidence); err == nil {
			ev.Confidence = c
		}
		_ = m.tel.RecordSandboxFinding(ctx, ev)
		m.feed.Publish(sandboxapi.ActivityEvent{Time: at, Kind: sandboxapi.ActivityFinding, Sandbox: name, Severity: severity,
			Host: r.Host, Message: firstNonEmpty(r.Title, r.Message)})
	}
}

const openshellHostAlias = "host.openshell.internal"

// hostAliasEvent handles OpenShell's record of a connection to the host.
// Relays to DefenseClaw's own listeners are reported by those listeners,
// except what only OpenShell sees of the hooks: a connection or request to
// the ingress it refused, or one that never became an authenticated
// request. Any other host port (a local model endpoint, a --host-port
// service) is harness work.
func (m *Manager) hostAliasEvent(ctx context.Context, b *box, r ocsf.Record, at time.Time, harnessName string) {
	switch r.Port {
	case m.opts.IngressPort:
		m.observeHookConnection(ctx, b, r.Denied() && !policyReloadCut(r), at)
	case m.opts.EgressPort, 0:
	default:
		m.markWork(b, at, harnessActivity(harnessName, r.Binary))
	}
}

// harnessFetchDenial reports an OpenShell denial of one of the sandbox
// harness's own background requests (harness.Spec.DirectFetches): the
// destination is the fetch's, and the actor is a binary under the harness's
// root-owned install root, or none (the DNS refusal before the connection
// names no binary). Binary is display text the workload could choose, which
// can at worst hide such a denial from the feed; the audit record stays.
func harnessFetchDenial(harnessName string, r ocsf.Record, host string) bool {
	for _, f := range harnessFetches(harnessName) {
		if host != triage.NormalizeHost(f.Host) || (r.Port != 0 && r.Port != f.Port) {
			continue
		}
		if r.Binary == "" || (strings.HasPrefix(r.Binary, f.BinaryRoot+"/") && !strings.Contains(r.Binary, "/../")) {
			return true
		}
	}
	return false
}

// policyReloadCut reports a connection OpenShell closed because the
// sandbox policy changed while it was open ("L7 tunnel closed before
// inspection because policy changed: policy generation is stale"): every
// policy reload closes the open connections, those the policy still allows
// included, so it is no refusal. The hooks retry once, and a session whose
// requests then never authenticate is still flagged after hookAttemptGrace.
func policyReloadCut(r ocsf.Record) bool {
	reason := strings.ToLower(r.Reason)
	return strings.Contains(reason, "policy changed") || strings.Contains(reason, "policy generation is stale")
}

// markWork records network activity of the sandbox's workload: it keeps
// the session's reachability check going and, when the harness's own
// binary made it (harnessActivity), the hooks' silence check too.
func (m *Manager) markWork(b *box, at time.Time, ofHarness bool) {
	if ofHarness {
		m.markActive(b, at)
	}
	m.mu.Lock()
	if !at.Before(b.started) {
		m.noteWorkLocked(b)
	}
	m.mu.Unlock()
}

// harnessActivity reports an OCSF event of the harness itself: its binary
// lies under the harness's install root in the overlay image. Only that
// counts toward hook silence: commands run through `sandbox exec` (the
// CLI's probe, a copy-mode upload or pull, the user's own) never pass the
// harness's hooks, and would raise hook_silence on a sandbox whose
// session is over. A harness whose hooks were disabled still reaches its
// model, so its own network events keep the check alive. The binary is
// what the workload reports; a process claiming the harness's path can
// only raise the alarm, never silence it.
func harnessActivity(harnessName, binary string) bool {
	spec, ok := harness.Get(harnessName)
	if !ok || binary == "" {
		return false
	}
	return strings.HasPrefix(path.Clean(binary), spec.InstallRoot()+"/")
}

func (m *Manager) markActive(b *box, at time.Time) {
	m.mu.Lock()
	if at.After(b.activeAt) {
		b.activeAt = at
	}
	m.mu.Unlock()
}

func ocsfSeverity(s ocsf.Severity) string {
	switch s {
	case ocsf.SeverityLow:
		return "LOW"
	case ocsf.SeverityMedium:
		return "MEDIUM"
	case ocsf.SeverityHigh:
		return "HIGH"
	case ocsf.SeverityCritical, ocsf.SeverityFatal:
		return "CRITICAL"
	default:
		return "INFO"
	}
}

func schemeOf(raw string) string {
	switch {
	case strings.HasPrefix(raw, "https://"):
		return "https"
	case strings.HasPrefix(raw, "http://"):
		return "http"
	default:
		return ""
	}
}

func firstNonEmpty(values ...string) string {
	for _, v := range values {
		if strings.TrimSpace(v) != "" {
			return v
		}
	}
	return ""
}

func parseConfidence(s string) (float64, error) {
	f, err := strconv.ParseFloat(strings.TrimSpace(s), 64)
	if err != nil || f <= 0 || f > 1 {
		return 0, errors.New("no confidence")
	}
	return f, nil
}

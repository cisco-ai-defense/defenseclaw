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
	"strconv"
	"strings"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/audit"
	"github.com/defenseclaw/defenseclaw/internal/gatewaylog"
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
	rec := b.rec
	m.mu.Unlock()
	return m.records.save(&rec)
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
			ErrorCode: string(gatewaylog.ErrCodeOpenShellWatchFailed), ErrorSummary: "sandbox events were lost: " + ev.Gap.Reason, Timestamp: m.now()})
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
	name := b.rec.Name
	m.mu.Unlock()
	switch r.Class {
	case ocsf.ClassNetwork, ocsf.ClassHTTP:
		host := triage.NormalizeHost(r.Host)
		// Relays to DefenseClaw's own listeners (hooks, the egress proxy)
		// are reported by those listeners.
		if host == "" || host == openshellHostAlias {
			return
		}
		m.markActive(b, at)
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
			m.mu.Lock()
			b.blocked++
			m.mu.Unlock()
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
		if r.Denied() {
			m.feed.Publish(sandboxapi.ActivityEvent{Time: at, Kind: sandboxapi.ActivityEgressBlocked, Sandbox: name, Host: host, Port: r.Port,
				Source: sandboxapi.SourceOpenShell, Reason: r.Reason, Message: "✗ " + host + " (direct connection denied by OpenShell)"})
		}
	case ocsf.ClassProcess:
		m.markActive(b, at)
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

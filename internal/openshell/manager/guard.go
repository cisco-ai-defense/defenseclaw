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
	"time"

	"github.com/defenseclaw/defenseclaw/internal/audit"
	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/openshell/nestguard"
	"github.com/defenseclaw/defenseclaw/internal/openshell/sandboxapi"
)

// maxGuardDetections bounds the detections a record keeps per session.
const maxGuardDetections = 64

// guardRestart paces restarting a guard that failed.
const guardRestart = 30 * time.Second

// guardRecord is the nested-repository guard state of a mounted sandbox's
// current session.
type guardRecord struct {
	// Baseline is what the project held when the session started; it is
	// taken before the sandbox runs, so nothing the agent creates is in it.
	Baseline   nestguard.Baseline    `json:"baseline"`
	TakenAt    time.Time             `json:"taken_at"`
	Detections []nestguard.Detection `json:"detections,omitempty"`
}

// GuardFunc runs the nested-repository guard of one project until ctx ends.
type GuardFunc func(ctx context.Context, opts nestguard.Options) error

// runNestGuard is the default GuardFunc.
func runNestGuard(ctx context.Context, opts nestguard.Options) error {
	g, err := nestguard.New(opts)
	if err != nil {
		return err
	}
	return g.Run(ctx)
}

// guarded reports whether a sandbox's project gets the guard.
func guarded(rec record) bool {
	return rec.WorkdirMode == config.OpenShellWorkdirMount && rec.Project != ""
}

// takeGuardBaseline records the session's starting point on rec. It runs
// before the sandbox starts, so the agent cannot plant a repository in it.
// A failed baseline only disables the guard's view of pre-existing
// repositories: every .git found later is quarantined, which errs on the
// safe side, so the error is logged rather than failing the start.
func (m *Manager) takeGuardBaseline(ctx context.Context, rec *record) {
	if !guarded(*rec) {
		rec.Guard = nil
		return
	}
	b, err := nestguard.TakeBaseline(ctx, rec.Project, 0, m.opts.GuardGitlinks)
	if err != nil {
		m.logf("nested-repository guard for %s: baseline: %v", rec.Name, err)
	}
	if b.Truncated {
		m.logf("nested-repository guard for %s: the project is too large to list every existing repository", rec.Name)
	}
	rec.Guard = &guardRecord{Baseline: b, TakenAt: m.now().UTC()}
}

// syncGuard runs the guard while a mounted sandbox is ready and stops it
// otherwise. Callers must not hold Manager.mu.
func (m *Manager) syncGuard(b *box, phase audit.SandboxPhase) {
	m.mu.Lock()
	want := guarded(b.rec) && !b.deleted && phase == audit.SandboxPhaseReady && m.opts.Guard != nil
	running := b.guardCancel != nil
	m.mu.Unlock()
	switch {
	case want && !running:
		m.startGuard(b)
	case !want && running:
		m.stopGuard(b)
	}
}

func (m *Manager) startGuard(b *box) {
	runCtx := m.running()
	if runCtx == nil {
		return
	}
	m.mu.Lock()
	if b.guardCancel != nil || b.deleted {
		m.mu.Unlock()
		return
	}
	ctx, cancel := context.WithCancel(runCtx)
	done := make(chan struct{})
	b.guardCancel, b.guardDone = cancel, done
	m.mu.Unlock()
	go func() {
		defer close(done)
		defer cancel()
		m.guardLoop(ctx, b)
	}()
}

func (m *Manager) stopGuard(b *box) {
	m.mu.Lock()
	cancel, done := b.guardCancel, b.guardDone
	b.guardCancel, b.guardDone = nil, nil
	m.mu.Unlock()
	if cancel != nil {
		cancel()
		<-done
	}
}

func (m *Manager) guardLoop(ctx context.Context, b *box) {
	for ctx.Err() == nil {
		m.mu.Lock()
		rec := b.rec
		m.mu.Unlock()
		if rec.Guard == nil {
			// A record from before the guard existed: the best baseline
			// left is now.
			m.takeGuardBaseline(ctx, &rec)
			m.mu.Lock()
			b.rec.Guard = rec.Guard
			saved := b.rec
			m.mu.Unlock()
			_ = m.records.save(&saved)
		}
		err := m.opts.Guard(ctx, nestguard.Options{
			Root: rec.Project, Baseline: rec.Guard.Baseline, Now: m.now, Gitlinks: m.opts.GuardGitlinks,
			OnDetect: func(d nestguard.Detection) { m.nestedRepo(ctx, b, d) },
			Logf: func(format string, args ...any) {
				m.logf("sandbox %s: "+format, append([]any{rec.Name}, args...)...)
			},
		})
		if ctx.Err() != nil {
			return
		}
		if errors.Is(err, nestguard.ErrUnsupported) {
			m.logf("sandbox %s: %v", rec.Name, err)
			return
		}
		if err != nil {
			m.logf("sandbox %s: nested-repository guard stopped: %v", rec.Name, err)
		}
		t := time.NewTimer(guardRestart)
		select {
		case <-ctx.Done():
			t.Stop()
			return
		case <-t.C:
		}
	}
}

// nestedRepo records one guard detection: on the sandbox record (the
// end-of-session review lists it), as workspace and finding telemetry, and
// on the activity feed (the run UI and the TUI show it).
func (m *Manager) nestedRepo(ctx context.Context, b *box, d nestguard.Detection) {
	m.mu.Lock()
	if b.rec.Guard == nil {
		b.rec.Guard = &guardRecord{TakenAt: m.now().UTC()}
	}
	if len(b.rec.Guard.Detections) < maxGuardDetections {
		b.rec.Guard.Detections = append(b.rec.Guard.Detections, d)
	}
	rec := b.rec
	id := b.identity()
	m.mu.Unlock()
	if err := m.records.save(&rec); err != nil {
		m.logf("sandbox %s: save the nested-repository detection: %v", rec.Name, err)
	}
	ctx = context.WithoutCancel(ctx)
	one := int64(1)
	label := d.Label()
	severity, title, description, remediation := "HIGH", "", "", ""
	switch {
	case d.Kind == nestguard.KindGitlink:
		title = "Gitlink added to the mounted project's index"
		description = "The sandbox added a submodule entry (" + d.Dir + ") to the project's index; `git submodule update` on this machine would fetch and check it out."
		remediation = "Review .gitmodules and the entry before running git submodule commands; `defenseclaw sandbox undo` restores the index."
	case d.Error != "":
		severity = "CRITICAL"
		title = "Nested repository created in the mounted project (quarantine failed)"
		description = "A new " + label + " appeared during the session and could not be quarantined: " + d.Error + ". Its configuration can run code when git runs in that folder on this machine."
		remediation = "Do not run git (or a git-aware shell prompt) in " + d.Dir + "; remove " + label + " or run `defenseclaw sandbox undo`."
	default:
		title = "Nested repository created in the mounted project"
		description = "A new " + label + " appeared during the session; DefenseClaw renamed it to " + d.Quarantined + " so git on this machine never reads its configuration."
		remediation = "Inspect " + d.Quarantined + " before renaming it back; `defenseclaw sandbox undo` removes it."
	}
	if d.Kind == nestguard.KindRepository {
		ev := audit.SandboxWorkspaceEvent{
			Sandbox: id, Operation: audit.SandboxWorkspaceQuarantine, Initiator: "defenseclaw", FileCount: &one,
			FlaggedCount: &one, Paths: []string{label}, Severity: severity, Timestamp: d.At,
		}
		if d.Error != "" {
			ev.Result, ev.FailureClass = audit.SandboxWorkspaceFailed, "rename_failed"
		}
		if err := m.tel.RecordSandboxWorkspace(ctx, ev); err != nil {
			m.logf("sandbox %s: quarantine telemetry: %v", rec.Name, err)
		}
	}
	if err := m.tel.RecordSandboxFinding(ctx, audit.SandboxFindingEvent{
		Sandbox: id, Kind: audit.SandboxFindingNestedRepo, Severity: severity, Title: title, Description: truncate(description, 1024),
		Evidence: truncate(label, 1024), Remediation: truncate(remediation, 1024), TargetRef: d.Dir, Confidence: 1, Timestamp: d.At,
	}); err != nil {
		m.logf("sandbox %s: nested-repository finding telemetry: %v", rec.Name, err)
	}
	msg := "⚠ quarantined a new git repository at " + label + " → " + d.Quarantined
	switch {
	case d.Kind == nestguard.KindGitlink:
		msg = "⚠ a gitlink (submodule) was added to the index: " + d.Dir
	case d.Error != "":
		msg = "⚠ a new git repository appeared at " + label + " and could not be quarantined: " + d.Error
	}
	m.feed.Publish(sandboxapi.ActivityEvent{
		Time: d.At, Kind: sandboxapi.ActivityFinding, Sandbox: rec.Name, Severity: severity,
		Reason: sandboxapi.ReasonNestedRepo, Message: msg,
	})
}

// nestedView renders a record's detections for the API.
func nestedView(g *guardRecord) []sandboxapi.NestedRepo {
	if g == nil {
		return nil
	}
	out := make([]sandboxapi.NestedRepo, 0, len(g.Detections))
	for _, d := range g.Detections {
		out = append(out, sandboxapi.NestedRepo{
			Kind: string(d.Kind), Path: d.Label(), Quarantined: d.Quarantined, Error: d.Error, At: d.At,
		})
	}
	return out
}

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
	"encoding/json"
	"errors"
	"slices"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/audit"
	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/openshell/nestguard"
	"github.com/defenseclaw/defenseclaw/internal/openshell/sandboxapi"
)

// maxGuardDetections bounds the detections a record keeps per session, and
// maxDetectionText each text field of one.
const (
	maxGuardDetections = 64
	maxDetectionText   = 1024
)

// guardBaselineBytes bounds what a baseline adds to its sandbox's record
// (JSON bytes of its paths), well under recordMaxBytes: the project decides
// how many repositories and gitlinks it lists, and a record too large to
// read back would lose the sandbox's policy on the next restart.
const guardBaselineBytes = 4 << 20

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
	b = boundBaseline(b, guardBaselineBytes)
	if b.Truncated {
		m.logf("nested-repository guard for %s: the project is too large to list every existing repository", rec.Name)
	}
	rec.Guard = &guardRecord{Baseline: b, TakenAt: m.now().UTC()}
}

// boundBaseline keeps the repositories and gitlinks of b that fit in limit
// JSON bytes, marking a cut baseline Truncated. What it leaves out errs on
// the safe side, as a failed baseline does: a repository missing from the
// baseline is quarantined when the guard sees it, a gitlink is reported.
// The project's own repository (".") is always kept.
func boundBaseline(b nestguard.Baseline, limit int) nestguard.Baseline {
	size := func(p string) int {
		n, _ := json.Marshal(p)
		return len(n) + 8 // separator and indent
	}
	total := 0
	for _, p := range append(slices.Clip(b.Repos), b.Gitlinks...) {
		total += size(p)
	}
	if total <= limit {
		return b
	}
	budget := limit
	keep := func(list []string) []string {
		for i, p := range list {
			if budget -= size(p); budget < 0 {
				b.Truncated = true
				return slices.Clip(list[:i])
			}
		}
		return list
	}
	own := slices.Contains(b.Repos, ".")
	repos := keep(slices.DeleteFunc(slices.Clone(b.Repos), func(r string) bool { return r == "." }))
	if own {
		repos = append([]string{"."}, repos...)
	}
	b.Repos = repos
	b.Gitlinks = keep(b.Gitlinks)
	return b
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
			m.mu.Unlock()
			_ = m.saveRecord(b)
		}
		baseline := rec.Guard.Baseline
		if baseline.At.IsZero() {
			// A baseline recorded before it carried its own time.
			baseline.At = rec.Guard.TakenAt
		}
		err := m.opts.Guard(ctx, nestguard.Options{
			Root: rec.Project, Baseline: baseline, Now: m.now, Gitlinks: m.opts.GuardGitlinks,
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
	if g := b.rec.Guard; g == nil || len(g.Detections) < maxGuardDetections {
		// Record copies taken under the lock share the guard record and
		// are saved after it is released, so a detection replaces the
		// guard record instead of writing through that shared pointer.
		next := guardRecord{TakenAt: m.now().UTC()}
		if g != nil {
			next = *g
		}
		kept := d
		kept.Dir, kept.Quarantined = truncate(d.Dir, maxDetectionText), truncate(d.Quarantined, maxDetectionText)
		kept.Error = truncate(d.Error, maxDetectionText)
		next.Detections = append(slices.Clip(next.Detections), kept)
		b.rec.Guard = &next
	}
	rec := b.rec
	id := b.identity()
	m.mu.Unlock()
	if err := m.saveRecord(b); err != nil {
		m.logf("sandbox %s: save the nested-repository detection: %v", rec.Name, err)
	}
	ctx = context.WithoutCancel(ctx)
	one := int64(1)
	// The names are the agent's: made safe to print before they reach
	// the finding, the feed and the terminal.
	label := sandboxapi.DisplayText(d.Label())
	d.Dir, d.Quarantined, d.Error = sandboxapi.DisplayText(d.Dir), sandboxapi.DisplayText(d.Quarantined), sandboxapi.DisplayText(d.Error)
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
			Kind: string(d.Kind), Path: sandboxapi.DisplayText(d.Label()), Quarantined: sandboxapi.DisplayText(d.Quarantined),
			Error: sandboxapi.DisplayText(d.Error), At: d.At,
		})
	}
	return out
}

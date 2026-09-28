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
	// Unswept marks a session whose final pass (finalSweep) has not run
	// yet: the workload may have left a repository after the guard's last
	// event or poll, and the next session's baseline would take it in.
	Unswept bool `json:"unswept,omitempty"`
}

// guardRun is one running guard of a box.
type guardRun struct {
	cancel context.CancelFunc
	done   chan struct{}
	// final, guarded by Manager.mu, asks for the final pass once the guard
	// ended (the workload stopped).
	final bool
}

// guardFinalTimeout bounds the final pass of a session's guard.
const guardFinalTimeout = 2 * time.Minute

// GuardFunc runs the nested-repository guard of one project until ctx ends,
// or once with opts.Once (the final pass).
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
	rec.Guard = &guardRecord{Baseline: b, TakenAt: m.now().UTC(), Unswept: true}
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

// syncGuard runs the guard while a mounted sandbox's workload may run
// (starting, ready, stopping or deleting: the grace period of a stop or a
// delete still runs it) and ends it once the workload stopped, with a
// final pass over the project that catches what the workload left after
// the guard's last event or poll. A session that ended without a final
// pass (it stopped while the daemon was down) gets it when the daemon sees
// it stopped. A delete runs the final pass itself (finishGuard). Callers
// must not hold Manager.mu.
func (m *Manager) syncGuard(b *box, phase audit.SandboxPhase) {
	m.mu.Lock()
	guardable := guarded(b.rec) && !b.deleted && m.opts.Guard != nil
	want := guardable && workloadPhase(phase)
	running := b.guard != nil
	final := guardable && stoppedWorkload(phase) && b.rec.Guard != nil && b.rec.Guard.Unswept
	m.mu.Unlock()
	switch {
	case want && !running:
		m.startGuard(b)
	case !want && (running || final):
		m.endGuard(b, final)
	}
}

// workloadPhase reports a phase in which the sandbox's workload may run.
func workloadPhase(p audit.SandboxPhase) bool {
	switch p {
	case audit.SandboxPhaseStarting, audit.SandboxPhaseReady, audit.SandboxPhaseStopping, audit.SandboxPhaseDeleting:
		return true
	}
	return false
}

// stoppedWorkload reports a phase in which the workload has stopped.
func stoppedWorkload(p audit.SandboxPhase) bool {
	switch p {
	case audit.SandboxPhaseStopped, audit.SandboxPhaseCompleted, audit.SandboxPhaseError:
		return true
	}
	return false
}

func (m *Manager) startGuard(b *box) {
	runCtx := m.running()
	if runCtx == nil {
		return
	}
	m.mu.Lock()
	if b.guard != nil || b.deleted {
		m.mu.Unlock()
		return
	}
	ctx, cancel := context.WithCancel(runCtx)
	run := &guardRun{cancel: cancel, done: make(chan struct{})}
	b.guard = run
	ending := b.guardEnding
	b.guardEnding = run.done
	m.mu.Unlock()
	go func() {
		defer close(run.done)
		defer cancel()
		if ending != nil {
			// The previous session's final pass first.
			<-ending
		}
		m.guardLoop(ctx, b)
		m.mu.Lock()
		final := run.final
		m.mu.Unlock()
		if final {
			m.finalSweep(runCtx, b)
		}
	}()
}

// endGuard ends the running guard without waiting for it; with final, a
// final pass follows (on the guard's goroutine, or on one of its own when
// no guard runs). waitGuard waits for both.
func (m *Manager) endGuard(b *box, final bool) {
	m.mu.Lock()
	run := b.guard
	b.guard = nil
	if run != nil {
		run.final = final
		m.mu.Unlock()
		run.cancel()
		return
	}
	runCtx := m.running()
	if !final || runCtx == nil {
		m.mu.Unlock()
		return
	}
	ending := b.guardEnding
	done := make(chan struct{})
	b.guardEnding = done
	m.mu.Unlock()
	go func() {
		defer close(done)
		if ending != nil {
			<-ending
		}
		m.finalSweep(runCtx, b)
	}()
}

// waitGuard waits until the box's last guard ended, its final pass
// included. Callers must not hold Manager.mu.
func (m *Manager) waitGuard(b *box) {
	m.mu.Lock()
	ending := b.guardEnding
	m.mu.Unlock()
	if ending != nil {
		<-ending
	}
}

// finishGuard ends the session's guard once its workload is gone (a start
// of a stopped sandbox, before the new baseline; a delete) and runs the
// final pass the session still lacks, waiting for both.
func (m *Manager) finishGuard(ctx context.Context, b *box) {
	m.mu.Lock()
	run := b.guard
	b.guard = nil
	if run != nil {
		run.final = true
	}
	m.mu.Unlock()
	if run != nil {
		run.cancel()
	}
	m.waitGuard(b)
	m.finalSweep(ctx, b)
}

// stopGuard stops the guard for good (the daemon stops, the sandbox is
// released) and waits for it; no final pass runs.
func (m *Manager) stopGuard(b *box) {
	m.mu.Lock()
	run := b.guard
	b.guard = nil
	if run != nil {
		run.final = false
	}
	m.mu.Unlock()
	if run != nil {
		run.cancel()
	}
	m.waitGuard(b)
}

// finalSweep runs the guard's final pass over a session whose workload
// stopped (guardRecord.Unswept): once, with the session's baseline, so
// the next session's baseline never takes in a repository the workload
// left at the end. It is recorded as done unless it failed (a later
// start runs it again).
func (m *Manager) finalSweep(ctx context.Context, b *box) {
	m.mu.Lock()
	rec := b.rec
	m.mu.Unlock()
	if !guarded(rec) || rec.Guard == nil || !rec.Guard.Unswept || m.opts.Guard == nil {
		return
	}
	ctx, cancel := context.WithTimeout(ctx, guardFinalTimeout)
	defer cancel()
	opts := m.guardOptions(ctx, b, rec)
	opts.Once = true
	if err := m.opts.Guard(ctx, opts); err != nil && !errors.Is(err, nestguard.ErrUnsupported) {
		m.logf("sandbox %s: nested-repository guard: the final pass failed: %v", rec.Name, err)
		return
	}
	if ctx.Err() != nil {
		return
	}
	m.mu.Lock()
	if g := b.rec.Guard; g != nil && g.Unswept && g.TakenAt.Equal(rec.Guard.TakenAt) {
		next := *g
		next.Unswept = false
		b.rec.Guard = &next
	}
	m.mu.Unlock()
	if err := m.saveRecord(b); err != nil {
		m.logf("sandbox %s: save the nested-repository guard state: %v", rec.Name, err)
	}
}

// guardOptions are the guard options of rec's session.
func (m *Manager) guardOptions(ctx context.Context, b *box, rec record) nestguard.Options {
	baseline := rec.Guard.Baseline
	if baseline.At.IsZero() {
		// A baseline recorded before it carried its own time.
		baseline.At = rec.Guard.TakenAt
	}
	return nestguard.Options{
		Root: rec.Project, Baseline: baseline, Now: m.now, Gitlinks: m.opts.GuardGitlinks,
		OnDetect: func(d nestguard.Detection) { m.nestedRepo(ctx, b, d) },
		Logf: func(format string, args ...any) {
			m.logf("sandbox %s: "+format, append([]any{rec.Name}, args...)...)
		},
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
		err := m.opts.Guard(ctx, m.guardOptions(ctx, b, rec))
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

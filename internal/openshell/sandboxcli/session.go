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

package sandboxcli

import (
	"bytes"
	"context"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/openshell"
	"github.com/defenseclaw/defenseclaw/internal/openshell/harness"
	"github.com/defenseclaw/defenseclaw/internal/openshell/sandboxapi"
	"github.com/defenseclaw/defenseclaw/internal/openshell/workspace"
)

// RunDir is where detached runs keep their output inside the sandbox.
const RunDir = "/sandbox/.defenseclaw/runs"

// session is one harness session in a sandbox.
type session struct {
	app  *App
	api  API
	cli  openshell.CLI
	spec *harness.Spec
	sb   *sandboxapi.Sandbox
	rm   bool
	yes  bool
	// started is set when the session created or started the sandbox; one
	// that was already running (a detached run, another session) is left
	// running when the session ends.
	started bool
	// liveRun is set at the end of a session in a sandbox whose detached
	// run is still going: nothing may stop the sandbox under it.
	liveRun bool
	// headless marks a one-prompt session (the resume hint says how to
	// run the next prompt).
	headless bool

	// before is the sandbox as it was when the session started, for the
	// end-of-session deltas.
	before *sandboxapi.Sandbox

	// hooksWarned is set once the live warning that the session's hooks do
	// not reach DefenseClaw went out (hooks.go); noHooks once the session
	// ended without one of them getting through.
	hooksMu     sync.Mutex
	hooksWarned bool
	noHooks     bool
}

// probe runs a trivial command in workdir until the sandbox answers; ""
// is the sandbox's default directory. The harness's workdir exists only
// once a copy-mode project is uploaded, so a probe there comes after the
// upload.
func (s *session) probe(ctx context.Context, workdir string) error {
	inv, err := s.cli.Exec(s.sb.Name, []string{"true"}, openshell.CLIExecOptions{WorkDir: workdir, Timeout: probeTimeout})
	if err != nil {
		return err
	}
	var last error
	for i := 0; i < probeAttempts; i++ {
		var out bytes.Buffer
		code, err := s.app.Streamer.Stream(ctx, inv, &out, &out)
		if err == nil && code == 0 {
			return nil
		}
		last = err
		if err == nil {
			last = fmt.Errorf("exit status %d: %s", code, truncate(out.String(), 200))
		}
		if ctx.Err() != nil {
			return ctx.Err()
		}
		if err := s.app.Sleep(ctx, 2*time.Second); err != nil {
			return err
		}
	}
	return fmt.Errorf("sandbox %s does not answer: %w", s.sb.Name, last)
}

// attach runs the harness in the foreground: with the terminal, or
// headless with its output streamed.
func (s *session) attach(ctx context.Context, opts harness.LaunchOptions, headless bool) (int, error) {
	argv, err := s.spec.LaunchArgv(opts)
	if err != nil {
		return -1, err
	}
	if before, err := s.api.Get(ctx, s.sb.Name); err == nil {
		s.before = before
	} else {
		s.before = s.sb
	}
	stop := s.watchNotices(ctx)
	defer stop()
	if headless || !s.app.IO.TTY {
		inv, err := s.cli.Exec(s.sb.Name, argv, openshell.CLIExecOptions{WorkDir: s.sb.Workdir})
		if err != nil {
			return -1, err
		}
		return s.app.Streamer.Stream(ctx, inv, s.app.IO.Out, s.app.IO.Err)
	}
	inv, err := s.cli.Exec(s.sb.Name, argv, openshell.CLIExecOptions{TTY: true, WorkDir: s.sb.Workdir})
	if err != nil {
		return -1, err
	}
	return s.app.Terminal.Run(ctx, inv)
}

// watchNotices follows the sandbox during the session and prints what must
// not wait until the end: a quarantined nested repository, and hooks that
// do not reach DefenseClaw (the daemon's verdict, or no hook by the end of
// the hook window).
func (s *session) watchNotices(ctx context.Context) func() {
	ctx, cancel := context.WithCancel(ctx)
	var since uint64
	_ = s.api.Activity(ctx, sandboxapi.ActivityQuery{Sandbox: s.sb.Name}, func(ev sandboxapi.ActivityEvent) error {
		since = max(since, ev.Seq)
		return nil
	})
	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		_ = s.api.Activity(ctx, sandboxapi.ActivityQuery{Sandbox: s.sb.Name, Since: since, Follow: true}, func(ev sandboxapi.ActivityEvent) error {
			if ev.Kind != sandboxapi.ActivityFinding {
				return nil
			}
			switch ev.Reason {
			case sandboxapi.ReasonNestedRepo:
				s.notice(strings.TrimPrefix(ev.Message, "⚠ "))
			case sandboxapi.ReasonHooksUnreachable:
				s.warnHooksOnce(ev.Message)
			}
			return nil
		})
	}()
	go func() {
		defer wg.Done()
		s.checkHooksAfter(ctx, s.app.hookWindow())
	}()
	return func() { cancel(); wg.Wait() }
}

// detach starts the harness in the background inside the sandbox; its
// output goes to RunDir/latest.log (see runs.go).
func (s *session) detach(ctx context.Context, opts harness.LaunchOptions) error {
	opts.Args = streamingArgs(s.spec, opts.Args)
	argv, err := s.spec.LaunchArgv(opts)
	if err != nil {
		return err
	}
	script := `set -eu
d=` + RunDir + `
mkdir -p "$d"
log="$d/$(date -u +%Y%m%dT%H%M%SZ).log"
ln -sfn "$log" "$d/latest.log"
rm -f "$d/latest.exit"
date +%s > "$d/latest.started"
runner='rc=0; "$@" || rc=$?; printf "%s\n" "$rc" > ` + RunDir + `/latest.exit'
if command -v setsid >/dev/null 2>&1; then
  setsid nohup sh -c "$runner" sh "$@" >"$log" 2>&1 </dev/null &
else
  nohup sh -c "$runner" sh "$@" >"$log" 2>&1 </dev/null &
fi
printf '%s\n' "$!" > "$d/latest.pid"
`
	inv, err := s.cli.Exec(s.sb.Name, append([]string{"sh", "-c", script, "sh"}, argv...), openshell.CLIExecOptions{WorkDir: s.sb.Workdir, Timeout: time.Minute})
	if err != nil {
		return err
	}
	var out bytes.Buffer
	code, err := s.app.Streamer.Stream(ctx, inv, &out, &out)
	if err != nil {
		return err
	}
	if code != 0 {
		return fmt.Errorf("start %s in the background: exit status %d: %s", s.spec.DisplayName, code, truncate(out.String(), 300))
	}
	a := s.app
	a.ok(s.spec.DisplayName + " is running in the background in " + s.sb.Name)
	a.line("follow:  " + CommandName + " logs " + s.sb.Name + " -f")
	a.line("watch:   " + CommandName + " activity -f --sandbox " + s.sb.Name)
	if s.sb.WorkdirMode == config.OpenShellWorkdirCopy {
		a.line("results: " + CommandName + " pull " + s.sb.Name + " --apply|--branch|--patch-out FILE")
	} else {
		a.line("review:  " + CommandName + " review " + s.sb.Name + "   undo: " + CommandName + " undo " + s.sb.Name)
	}
	a.line("stop:    " + CommandName + " stop " + s.sb.Name)
	return nil
}

// uploadCopy sends the staged copy and records its baseline. It runs
// before any exec in the workdir, which the upload creates.
func (s *session) uploadCopy(ctx context.Context, rec *workspace.CopyRecord) error {
	a := s.app
	t := a.transport(s.cli)
	report := func(result string, rec *workspace.CopyRecord, failure string) {
		r := sandboxapi.WorkspaceReport{Operation: sandboxapi.WorkspaceUpload, Result: result, FailureClass: failure}
		if rec != nil {
			files, bytes := int64(rec.Files), rec.Bytes
			r.FileCount, r.ByteCount = &files, &bytes
		}
		if err := s.api.ReportWorkspace(context.WithoutCancel(ctx), s.sb.Name, r); err != nil {
			a.warn("could not record the upload with the daemon: " + err.Error())
		}
	}
	a.note(fmt.Sprintf("Uploading the copy (%s, %s)…", plural(int64(rec.Files), "file", "files"), humanBytes(rec.Bytes)))
	up, err := a.Workspace.Upload(ctx, a.dataDir(), s.sb.Name, t)
	if err != nil {
		report("failed", rec, "upload_failed")
		return workspaceFailure("upload the project copy", err, "")
	}
	if _, err := a.Workspace.Baseline(ctx, a.dataDir(), s.sb.Name, t); err != nil {
		report("failed", up, "baseline_failed")
		return workspaceFailure("record the copy's baseline", err, "")
	}
	report("completed", up, "")
	for _, w := range up.Warnings {
		a.warn(w)
	}
	if len(up.HeldBack) > 0 {
		a.note("held back: " + strings.Join(firstN(up.HeldBack, 8), "  "))
	}
	return nil
}

func firstN(list []string, n int) []string {
	if len(list) <= n {
		return list
	}
	return append(append([]string(nil), list[:n]...), fmt.Sprintf("(+%d more)", len(list)-n))
}

// end runs the end-of-session summary, review and keep/undo decision.
func (s *session) end(ctx context.Context) error {
	ctx = context.WithoutCancel(ctx)
	a := s.app
	after, err := s.api.Get(ctx, s.sb.Name)
	if err != nil {
		return apiError(err)
	}
	a.println()
	if !s.started {
		// The sandbox was running before the session: a detached run may
		// still be going in it.
		if run, err := a.detachedRun(ctx, s.cli, after); err == nil && run.State == runRunning {
			s.liveRun = true
		}
	}
	if after.WorkdirMode == config.OpenShellWorkdirCopy {
		return s.endCopy(ctx, after)
	}
	rev, err := s.api.Review(ctx, s.sb.Name, sandboxapi.ReviewRequest{})
	if err != nil {
		a.warn("could not review the session's changes: " + apiError(err).Error())
	}
	a.println(s.summaryLine(after, rev))
	s.printHookReach(after)
	changed := rev != nil && rev.Report != nil && (rev.Report.FilesChanged > 0 || len(rev.Report.Flags) > 0 ||
		rev.Report.HeadBefore != rev.Report.HeadAfter || rev.Report.BranchBefore != rev.Report.BranchAfter)
	if rev != nil && rev.Report != nil {
		if line := riskLine(rev.Report); line != "" {
			a.println(a.style(line, ansiYellow))
		}
	} else if rev != nil && rev.RiskLine != "" {
		a.println(a.style(rev.RiskLine, ansiYellow))
	}
	s.printNested(after)
	if s.liveRun && changed {
		// Undo stops the sandbox, which would end the run.
		a.note("the detached run in " + s.sb.Name + " is still going; review or undo once it ends: `" + CommandName + " review " + s.sb.Name +
			"`, `" + CommandName + " undo " + s.sb.Name + "`")
		return s.finish(ctx, false)
	}
	decision, accepted := s.onExit(changed)
	for decision == "d" {
		diff, err := s.api.Review(ctx, s.sb.Name, sandboxapi.ReviewRequest{Diff: true})
		if err != nil {
			a.warn("diff: " + apiError(err).Error())
		} else {
			a.println(strings.TrimRight(diff.Diff, "\n"))
		}
		decision, accepted = s.onExit(changed)
	}
	if decision == "u" {
		res, err := s.api.Undo(ctx, s.sb.Name, sandboxapi.UndoRequest{Stop: true})
		if err != nil {
			return fmt.Errorf("undo: %w", apiError(err))
		}
		a.ok("undone: " + undoDone(res, "see below"))
		if res.Result != nil {
			for _, w := range res.Result.Warnings {
				a.warn(w)
			}
			a.printUnrestored(res.Result.Unrestored())
		}
		return s.finish(ctx, true)
	}
	if accepted {
		// The next session starts from here: its snapshot replaces this
		// undo point.
		a.acceptUndoPoint(after)
	}
	return s.finish(ctx, false)
}

// onExit returns k (keep), u (undo) or d (diff), and whether keeping was
// the user's choice (an answer, --yes, or on_exit: keep) rather than the
// default without a terminal.
func (s *session) onExit(changed bool) (string, bool) {
	a := s.app
	if !changed {
		return "k", false
	}
	policy := config.OpenShellOnExitAsk
	if a.Cfg != nil && a.Cfg.OpenShell.Workdir.OnExit != "" {
		policy = a.Cfg.OpenShell.Workdir.OnExit
	}
	switch policy {
	case config.OpenShellOnExitKeep:
		return "k", true
	case config.OpenShellOnExitUndo:
		return "u", false
	}
	if s.sb.Snapshot == nil {
		return "k", false
	}
	if !a.IO.TTY || s.yes {
		return "k", s.yes
	}
	ans, err := a.choose("Keep changes?", []choice{{"y", "keep"}, {"u", "undo everything"}, {"d", "show diff"}}, "y")
	if err != nil {
		return "k", false
	}
	if ans == "y" {
		return "k", true
	}
	return ans, false
}

// finish stops (or with --rm deletes) the sandbox after a session. A
// sandbox the session did not start, or whose detached run is still going,
// keeps running.
func (s *session) finish(ctx context.Context, stopped bool) error {
	a := s.app
	name := s.sb.Name
	if s.rm && s.liveRun {
		a.warn(name + " is not deleted (--rm): its detached run is still going; delete it once the run ends: `" + CommandName + " delete " + name + "`")
		s.rm = false
	}
	if s.rm {
		if _, err := s.api.Delete(ctx, name, sandboxapi.DeleteRequest{}); err != nil {
			return fmt.Errorf("delete %s: %w", name, apiError(err))
		}
		a.forgetCLIState(name)
		a.ok("sandbox " + name + " deleted (--rm)")
		return nil
	}
	if !stopped {
		switch {
		case s.liveRun:
			a.note("Sandbox " + name + " keeps running: its detached run is still going → follow: " + CommandName + " logs " + name + " -f   stop: " +
				CommandName + " stop " + name)
			return nil
		case !s.started:
			a.note("Sandbox " + name + " keeps running (it was running when you connected) → stop: " + CommandName + " stop " + name)
			return nil
		}
		if _, err := s.api.Stop(ctx, name); err != nil {
			a.warn("could not stop " + name + ": " + apiError(err).Error())
			return nil
		}
	}
	next := "resume: " + CommandName + " connect " + name
	if s.headless {
		next += " --prompt TEXT"
	}
	a.note("Sandbox kept (stopped) → " + next + "   delete: " + CommandName + " delete " + name)
	return nil
}

// summaryLine is "Session ended · 57 tool calls (1 blocked: …) · 23 sites
// contacted (1 request blocked) · 8 files changed (+212 −37)". Sites count
// distinct destinations and blocks count refused requests, so the blocked
// number is labelled as requests.
func (s *session) summaryLine(after *sandboxapi.Sandbox, rev *sandboxapi.ReviewResponse) string {
	before := s.before
	if before == nil {
		before = &sandboxapi.Sandbox{}
	}
	calls := after.Hooks.ToolCalls - before.Hooks.ToolCalls
	blocked := after.Hooks.ToolBlocked - before.Hooks.ToolBlocked
	parts := []string{"Session ended"}
	tools := plural(max(calls, 0), "tool call", "tool calls")
	if blocked > 0 {
		tools += fmt.Sprintf(" (%d blocked", blocked)
		if after.Hooks.LastBlocked != "" {
			tools += ": " + truncate(after.Hooks.LastBlocked, 48)
		}
		tools += ")"
	}
	parts = append(parts, tools)
	sites := after.Egress.Destinations - before.Egress.Destinations
	requestsBlocked := after.Egress.Blocked - before.Egress.Blocked
	siteText := plural(int64(max(sites, 0)), "site contacted", "sites contacted")
	if requestsBlocked > 0 {
		siteText += " (" + plural(int64(requestsBlocked), "request blocked", "requests blocked") + ")"
	}
	parts = append(parts, siteText)
	switch {
	case rev != nil && rev.Summary != "":
		parts = append(parts, rev.Summary)
	case rev != nil && rev.Report != nil:
		parts = append(parts, rev.Report.SummaryLine())
	}
	if rev != nil && rev.Report != nil {
		if moved := headMoved(rev.Report.BranchBefore, rev.Report.BranchAfter, rev.Report.HeadBefore, rev.Report.HeadAfter); moved != "" {
			parts = append(parts, moved)
		}
	}
	return strings.Join(parts, " · ")
}

// headMoved describes what a session did to HEAD: "switched main → fix",
// "HEAD moved on main (1a2b3c4 → 5d6e7f8)", or "" when it stayed.
func headMoved(branchBefore, branchAfter, headBefore, headAfter string) string {
	switch {
	case branchBefore != branchAfter:
		return "switched " + firstNonEmpty(branchBefore, "a detached HEAD") + " → " + firstNonEmpty(branchAfter, "a detached HEAD")
	case headBefore != headAfter:
		on := ""
		if branchAfter != "" {
			on = " on " + branchAfter
		}
		return "HEAD moved" + on + " (" + firstNonEmpty(shortCommit(headBefore), "none") + " → " + firstNonEmpty(shortCommit(headAfter), "none") + ")"
	}
	return ""
}

func shortCommit(oid string) string {
	if len(oid) > 7 {
		return oid[:7]
	}
	return oid
}

// printNested lists what the nested-repository guard found.
func (s *session) printNested(sb *sandboxapi.Sandbox) {
	a := s.app
	for _, n := range sb.NestedRepos {
		switch {
		case n.Kind == "gitlink":
			a.println(a.style("⚠ A submodule entry was added to the index: "+n.Path+"  → check .gitmodules before `git submodule update`", ansiYellow))
		case n.Error != "":
			a.println(a.style("✗ A new git repository at "+n.Path+" could not be quarantined ("+n.Error+"); do not run git there", ansiRed))
		default:
			a.println(a.style("⚠ A new git repository at "+n.Path+" was quarantined as "+n.Quarantined+"  → inspect it before renaming it back", ansiYellow))
		}
	}
}

// endCopy pulls a copy-mode sandbox's work and asks where it goes.
func (s *session) endCopy(ctx context.Context, after *sandboxapi.Sandbox) error {
	a := s.app
	pull, err := a.pull(ctx, s.api, s.cli, after)
	if err != nil {
		a.println(s.summaryLine(after, nil))
		s.printHookReach(after)
		a.warn("could not pull the sandbox's changes: " + err.Error())
		a.note("retry with `" + CommandName + " pull " + after.Name + "`; the sandbox is kept")
		s.rm = false
		return s.finish(ctx, false)
	}
	rev := &sandboxapi.ReviewResponse{Summary: pull.Review.SummaryLine(), RiskLine: riskLine(&pull.Review)}
	a.println(s.summaryLine(after, rev))
	s.printHookReach(after)
	if rev.RiskLine != "" {
		a.println(a.style(rev.RiskLine, ansiYellow))
	}
	for _, b := range pull.Blocking {
		a.warn(b)
	}
	if pull.Empty() {
		a.note("the sandbox changed nothing")
		return s.finish(ctx, false)
	}
	mode := ""
	if a.IO.TTY && !s.yes {
		choices := []choice{{"a", "apply (3-way)"}}
		if pull.Kind != workspace.CopyPlain {
			// A plain folder has no branches to put the work on.
			choices = append(choices, choice{"b", "branch dc/" + after.Name})
		}
		choices = append(choices, choice{"p", "patch file"}, choice{"s", "skip"})
		ans, err := a.choose("Bring the changes back?", choices, "a")
		if err != nil {
			return err
		}
		mode = map[string]string{"a": "apply", "b": "branch", "p": "patch"}[ans]
	}
	if mode == "" {
		a.note("changes are kept in the sandbox: `" + CommandName + " pull " + after.Name + " --apply|--branch|--patch-out FILE`")
		s.rm = false
		return s.finish(ctx, false)
	}
	opts := PullOptions{Name: after.Name, AcceptSensitive: rev.RiskLine == "" || !a.IO.TTY}
	switch mode {
	case "apply":
		opts.Apply = true
	case "branch":
		opts.Branch = true
	case "patch":
		opts.PatchOut = after.Name + ".patch"
	}
	if rev.RiskLine != "" && a.IO.TTY {
		yes, err := a.ask("Some changes can run code on this machine. Bring them back anyway?", false, false)
		if err != nil {
			return err
		}
		opts.AcceptSensitive = yes
		if !yes {
			s.rm = false
			return s.finish(ctx, false)
		}
	}
	if _, err := a.applyPull(ctx, s.api, after, pull, opts); err != nil {
		a.warn(err.Error())
		s.rm = false
	}
	return s.finish(ctx, false)
}

// transport is copy mode's openshell CLI transport.
func (a *App) transport(cli openshell.CLI) *workspace.CLI {
	return &workspace.CLI{Binary: cli.Binary, Gateway: cli.Gateway, Workspace: cli.Workspace}
}

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

package sandboxcli

import (
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/openshell"
	"github.com/defenseclaw/defenseclaw/internal/openshell/harness"
	"github.com/defenseclaw/defenseclaw/internal/openshell/profiles"
	"github.com/defenseclaw/defenseclaw/internal/openshell/sandboxapi"
	"github.com/defenseclaw/defenseclaw/internal/openshell/workspace"
)

// unaccepted stops the test if the changes of name's session were accepted
// as the next session's base.
func unaccepted(t *testing.T, ta *testApp, name string) {
	t.Helper()
	dir, _ := ta.cliStateDir(name)
	if _, err := os.Stat(filepath.Join(dir, "accepted.json")); err == nil {
		t.Fatal("changes nobody may accept yet were accepted as the next session's base")
	}
}

// deleted checks the one delete of the run's sandbox: whether it kept the
// undo snapshot.
func deleted(keepSnapshot bool) func(*testing.T, *testApp) {
	return func(t *testing.T, ta *testApp) {
		t.Helper()
		if del := ta.bodies("DELETE", sbName); len(del) != 1 || strings.Contains(del[0], `"keep_snapshot":true`) != keepSnapshot {
			t.Fatalf("delete calls = %q, want the snapshot kept: %t", del, keepSnapshot)
		}
	}
}

// The end of a session: the sandbox it started stops before the review; an
// unreviewed or unaccepted (no terminal, no --yes) change keeps the undo
// snapshot through --rm; a secret the agent wrote in a copy is brought back
// only on a yes; a headless answer cannot drive the terminal.
func TestSessionEnd(t *testing.T) {
	failedReview := func(ta *testApp) {
		ta.daemon.errors["POST "+sbPath+"/review"] = sandboxapi.Errorf(sandboxapi.CodeInternal, "the snapshot is unreadable")
	}
	headless := func(ta *testApp) { ta.IO.TTY = false }
	secret := func(ta *testApp) {
		ta.copy.pull = &workspace.PullResult{Name: "fix-tests", Kind: workspace.CopyGit,
			Changes: []workspace.TreeChange{{Path: "config/keys.txt", Status: "A", Added: 1}},
			Review: workspace.ReviewReport{FilesChanged: 1, Insertions: 1, Findings: []workspace.ScanFinding{
				{Path: "config/keys.txt", Scanner: "clawshield-secrets", RuleID: "CS-SEC-MARKER", Severity: "CRITICAL", Title: "marker secret"}}}}
	}
	applied := func(accepted bool) func(*testing.T, *testApp) {
		return func(t *testing.T, ta *testApp) {
			if a := ta.copy.apply; (len(a) == 1 && a[0].AcceptSensitive) != accepted || (!accepted && len(a) != 0) {
				t.Fatalf("apply = %+v, want the secret brought back: %t", a, accepted)
			}
		}
	}
	const answer = "done \x1b]0;DCMARK\x07 \x1b[32mok\x1b[0m\n"
	answers := func(tty bool) func(*testApp) {
		return func(ta *testApp) {
			ta.IO.TTY, ta.IO.OutTTY = false, tty
			ta.stream.answer = func(argv []string) (int, string) {
				if runsHarness(argv) {
					return 0, answer
				}
				return 0, ""
			}
		}
	}
	stopped := func(t *testing.T, ta *testApp) { ta.wantCalls(t, 1, "POST", sbName+"/stop") }
	copyRun := RunOptions{Harness: "claude", Copy: true, Name: "fix-tests"}
	runCases(t, []runCase{
		{name: "the sandbox stops before the review", input: "y\n", opts: RunOptions{Harness: "claude"}, want: []string{"Sandbox kept (stopped)"},
			check: func(t *testing.T, ta *testApp) {
				paths := ta.daemon.paths()
				if stop, review := slices.Index(paths, "POST "+sbPath+"/stop"), slices.Index(paths, "POST "+sbPath+"/review"); stop < 0 || stop > review {
					t.Fatalf("stop at %d, review at %d; want the stop first:\n%s", stop, review, strings.Join(paths, "\n"))
				}
				stopped(t, ta)
			}},
		{name: "a failed review, kept", input: "\n", setup: failedReview, opts: RunOptions{Harness: "claude", Rm: true},
			want: []string{"could not review the session's changes", "Keep changes?", "its undo point is kept because the changes were not reviewed",
				"undo: defenseclaw sandbox undo " + sbName},
			check: func(t *testing.T, ta *testApp) {
				deleted(true)(t, ta)
				unaccepted(t, ta, sbName)
			}},
		{name: "a failed review, undone", input: "u\n", setup: failedReview, opts: RunOptions{Harness: "claude", Rm: true},
			check: func(t *testing.T, ta *testApp) {
				ta.wantCalls(t, 1, "POST", sbName+"/undo")
				deleted(false)(t, ta)
			}},
		{name: "headless --rm", setup: headless, opts: RunOptions{Harness: "claude", Prompt: "fix it", Rm: true}, check: deleted(true),
			want: []string{"its undo point is kept because nobody accepted the changes", "undo: defenseclaw sandbox undo " + sbName,
				"drop it: defenseclaw sandbox delete " + sbName}},
		{name: "headless --rm --yes", setup: headless, opts: RunOptions{Harness: "claude", Prompt: "fix it", Rm: true, Yes: true}, check: deleted(false)},
		{name: "a secret from a copy, declined", input: "a\n\n", setup: secret, opts: copyRun, check: applied(false),
			want: []string{"the sandbox wrote what looks like a secret: config/keys.txt", "Some changes hold what looks like a secret. Bring them back anyway?"}},
		{name: "a secret from a copy, accepted", input: "a\ny\n", setup: secret, opts: copyRun, check: applied(true)},
		{name: "a headless answer on a terminal", setup: answers(true), opts: RunOptions{Harness: "claude", Prompt: "fix it"}, check: stopped,
			want: []string{"done �]0;DCMARK� \x1b[32mok\x1b[0m\n"}, not: []string{"\x1b]"}},
		{name: "a headless answer piped", setup: answers(false), opts: RunOptions{Harness: "claude", Prompt: "fix it"}, check: stopped,
			want: []string{answer}},
		{name: "the harness's print flag runs headless", setup: answers(false), opts: RunOptions{Harness: "claude", Args: []string{"-p", "hello"}},
			check: stopped, want: []string{answer}},
	})
}

// A copy-mode session whose changes nobody brings back (no terminal to ask
// on, --yes, a skip, a declined secret) ends saying how many files changed
// and that nothing was applied, with the pull that brings them back; its
// sandbox is stopped and kept, and a --rm dropped for that is said. On the
// MicroVM driver, where every run works on a copy, this is how an
// unattended run ends: nothing is applied without a review.
func TestCopySessionLeavesUnpulledWorkInTheSandbox(t *testing.T) {
	const name = "copybox"
	left := "1 file changed; nothing was applied: the changes are kept in the sandbox for `defenseclaw sandbox pull " + name +
		" --apply` (or --branch or --patch-out FILE)"
	kept := name + " is not deleted (--rm): its work was not brought back; delete it once it is: `defenseclaw sandbox delete " + name + "`"
	keptStopped := func(t *testing.T, ta *testApp) {
		t.Helper()
		if stops, deletes, applies := ta.calls("POST", name+"/stop"), ta.calls("DELETE", name), len(ta.copy.apply); stops != 1 || deletes != 0 || applies != 0 {
			t.Fatalf("stop %d, delete %d, apply %d calls; want the sandbox stopped and kept with its work", stops, deletes, applies)
		}
	}
	headless := func(ta *testApp) { ta.IO.TTY = false }
	vm := func(ta *testApp) {
		ta.IO.TTY = false
		ta.daemon.status.Gateway.Driver = "vm"
	}
	secret := func(ta *testApp) {
		ta.copy.pull = &workspace.PullResult{Name: name, Kind: workspace.CopyGit,
			Changes: []workspace.TreeChange{{Path: "config/keys.txt", Status: "A", Added: 1}},
			Review: workspace.ReviewReport{FilesChanged: 1, Insertions: 1, Findings: []workspace.ScanFinding{
				{Path: "config/keys.txt", Scanner: "clawshield-secrets", RuleID: "CS-SEC-MARKER", Severity: "CRITICAL", Title: "marker secret"}}}}
	}
	copyRun := RunOptions{Harness: "claude", Copy: true, Name: name}
	with := func(f func(*RunOptions)) RunOptions {
		o := copyRun
		f(&o)
		return o
	}
	runCases(t, []runCase{
		{name: "no terminal, --rm", setup: headless, opts: with(func(o *RunOptions) { o.Prompt, o.Rm = "fix it", true }),
			want: []string{left, kept}, check: keptStopped},
		{name: "--yes on a terminal", opts: with(func(o *RunOptions) { o.Yes = true }), want: []string{left},
			not: []string{kept, "Bring the changes back?"}, check: keptStopped},
		{name: "a skip, --rm", input: "s\n", opts: with(func(o *RunOptions) { o.Rm = true }), want: []string{"Bring the changes back?", left, kept},
			check: keptStopped},
		{name: "a declined secret, --rm", input: "a\n\n", setup: secret, opts: with(func(o *RunOptions) { o.Rm = true }), want: []string{kept},
			check: keptStopped},
		{name: "the MicroVM driver without a terminal", setup: vm, opts: RunOptions{Harness: "claude", Name: name, Prompt: "fix it"},
			want: []string{left}, not: []string{kept}, check: keptStopped},
	})
}

// A headless session (--prompt) on a terminal still asks "Keep changes?"
// at its end, and keeping them makes them the next session's base; only a
// session with no terminal to ask on leaves its changes unaccepted, so the
// next start keeps the undo point.
func TestHeadlessSessionOnATerminalAsksToKeepChanges(t *testing.T) {
	for _, tty := range []bool{true, false} {
		t.Run(fmt.Sprintf("tty=%t", tty), func(t *testing.T) {
			ta := newTestApp(t, "y\n")
			ta.IO.TTY = tty
			sb := sampleSandbox("m1-a")
			sb.Phase = "stopped"
			sb.Snapshot = &sandboxapi.SnapshotInfo{Kind: "git", CreatedAt: time.Date(2026, 9, 27, 9, 30, 0, 0, time.UTC)}
			ta.daemon.add(sb)
			ta.ok(t, ta.Connect(bg, ConnectOptions{Name: "m1-a", Prompt: "add the tests"}))
			if asked := strings.Contains(ta.output(), "Keep changes?"); asked != tty || len(ta.term.runs) != 0 {
				t.Fatalf("asked = %v, terminal runs %d:\n%s", asked, len(ta.term.runs), ta.output())
			}
			ta.ok(t, ta.Start(bg, "m1-a", StartOptions{}))
			if starts := ta.bodies("POST", "m1-a/start"); len(starts) != 2 || strings.Contains(starts[1], `"new_snapshot":true`) != tty {
				t.Fatalf("starts = %q; the second must ask for a new snapshot: %t", starts, tty)
			}
		})
	}
}

// Manual R2-51 and R2-98: an ask is announced in the terminal's title and a
// desktop notification, not written over the harness's screen, with the
// destination, the binary, why it is an ask, the command and the TUI's Asks
// view; the banner says where asks are answered, and the end of the session
// repeats the ask and names those left.
func TestSessionAnnouncesAsks(t *testing.T) {
	ta := newTestApp(t, "")
	stderr := liveErr(ta)
	noChanges(ta)
	ta.daemon.approvals = []sandboxapi.Approval{{ID: "ap-1", Sandbox: sbName, Host: "www.example.com", Port: 443, Binary: "/usr/bin/curl"}}
	ta.daemon.live = []sandboxapi.ActivityEvent{{Seq: 5, Kind: sandboxapi.ActivityApprovalRequested, Sandbox: sbName, ApprovalID: "ap-1",
		Host: "www.example.com", Port: 443, Message: "approvals are manual for the strict profile"}}
	notice := "? ask ap-1: www.example.com:443 (curl) is waiting for you (approvals are manual for the strict profile) → in another terminal: " +
		"defenseclaw sandbox approve " + sbName + " ap-1 (or reject), or in `defenseclaw tui`: 7 Sandboxes, then t for Asks"
	ta.term.during = func() {
		waitFor(t, "the ask notice", func() bool { return strings.Contains(stderr.String(), "\x1b]9;DefenseClaw: "+notice+"\a") })
		ta.daemon.edit(sbName, func(sb *sandboxapi.Sandbox) { sb.PendingApprovals = 1 })
	}
	ta.ok(t, ta.Run(bg, RunOptions{Harness: "claude"}))
	live := stderr.String()
	if !strings.Contains(live, "\x1b[22;0t\x1b]2;[defenseclaw] ? ask ap-1: www.example.com:443 (curl)") || strings.Contains(live, "\r\n[defenseclaw]") ||
		!strings.HasSuffix(live, "\x1b[23;0t") || !strings.Contains(live, "\a\a") {
		t.Fatalf("live output = %q", live)
	}
	has(t, ta.output(), "? asked to reach www.example.com:443 (curl)",
		"Asks      announced in this terminal's title as they come; answer them in another terminal: defenseclaw sandbox approvals --sandbox "+sbName,
		"? 1 ask is still waiting for you → defenseclaw sandbox approvals --sandbox "+sbName)
	// A headless session has no screen to protect: its notices are lines.
	ta = newTestApp(t, "")
	stderr = liveErr(ta)
	s := &session{app: ta.App, headless: true, sb: &sandboxapi.Sandbox{Name: "box"}}
	s.notice("", "✓ the DefenseClaw daemon is reachable again", "")
	s.restoreTitle()
	if got := stderr.String(); got != "\r\n[defenseclaw] ✓ the DefenseClaw daemon is reachable again\r\n" {
		t.Fatalf("headless notice = %q; it does not touch the title", got)
	}
}

// Manual R2-84 and R2-68: a blocked destination and a finding (an alert,
// hook tamper) are announced while the harness runs, and the summary
// repeats them, the block with the command that lifts it. What the harness
// fetches on its own and does without, and INFO findings, are not.
func TestBlocksAndFindingsAreAnnouncedAndSummarised(t *testing.T) {
	ta := newTestApp(t, "")
	stderr := liveErr(ta)
	noChanges(ta)
	ta.daemon.live = []sandboxapi.ActivityEvent{
		{Seq: 1, Kind: sandboxapi.ActivityEgressBlocked, Sandbox: sbName, Host: "webhook.site", Port: 443, Category: "webhook_catcher", Unblockable: true},
		{Seq: 2, Kind: sandboxapi.ActivityEgressBlocked, Sandbox: sbName, Host: "webhook.site", Port: 443, Category: "webhook_catcher", Unblockable: true},
		{Seq: 3, Kind: sandboxapi.ActivityEgressBlocked, Sandbox: sbName, Host: "raw.githubusercontent.com", Reason: harnessFetchReason},
		{Seq: 4, Kind: sandboxapi.ActivityFinding, Sandbox: sbName, Severity: "HIGH", Reason: "tool_alert", Host: "webhook.site",
			Message: "⚠ alert on Bash: known exfil destination (C2-WEBHOOK-SITE)"},
		{Seq: 5, Kind: sandboxapi.ActivityFinding, Sandbox: sbName, Severity: "HIGH", Reason: reasonHookTamper,
			Message: "⚠ hook tamper: Bash ran without a DefenseClaw verdict; the sandbox keeps running (hooks.on_tamper: alert)"},
		{Seq: 6, Kind: sandboxapi.ActivityFinding, Sandbox: sbName, Severity: "INFO", Reason: "note", Message: "nothing to see"},
	}
	block := "✗ DefenseClaw blocked webhook.site (webhook catcher) → unblock: defenseclaw sandbox unblock webhook.site --sandbox " + sbName
	ta.term.during = func() {
		waitFor(t, "the tamper notice", func() bool { return strings.Contains(stderr.String(), "hook tamper") })
	}
	ta.ok(t, ta.Run(bg, RunOptions{Harness: "claude"}))
	live := stderr.String()
	if strings.Count(live, "\x1b]9;DefenseClaw: "+block+"\a") != 1 || strings.Contains(live, "raw.githubusercontent.com") || strings.Contains(live, "nothing to see") {
		t.Fatalf("live output = %q", live)
	}
	has(t, ta.output(), block, "⚠ webhook.site: alert on Bash: known exfil destination (C2-WEBHOOK-SITE)", "⚠ hook tamper: Bash ran without a DefenseClaw verdict")
	if out := ta.output(); strings.Index(out, "Session ended") > strings.Index(out, block) {
		t.Errorf("the notices come before the summary line:\n%s", out)
	}
}

// Manual R2-2: while the daemon does not answer, the run says so (the hooks
// fail closed meanwhile), then, as soon as it answers, that it is back, and
// the summary keeps the outage.
func TestDaemonOutageIsAnnouncedLive(t *testing.T) {
	old := reconnectDelay
	reconnectDelay = 5 * time.Millisecond
	t.Cleanup(func() { reconnectDelay = old })
	ta := newTestApp(t, "")
	stderr := liveErr(ta)
	noChanges(ta)
	// Like the daemon's, the followed stream stays open until the daemon
	// goes away.
	ta.daemon.hold = make(chan struct{})
	following := func() bool {
		return slices.ContainsFunc(ta.daemon.callsTo("GET", sandboxapi.PathActivity), func(c call) bool { return strings.Contains(c.Query, "follow=true") })
	}
	said := func(what string) func() bool { return func() bool { return strings.Contains(stderr.String(), what) } }
	ta.term.during = func() {
		waitFor(t, "the session to follow the feed", following)
		ta.daemon.mu.Lock()
		ta.daemon.errors["GET "+sandboxapi.PathStatus] = &sandboxapi.Error{Code: sandboxapi.CodeUnavailable, Message: "stopped"}
		close(ta.daemon.hold)
		ta.daemon.hold = make(chan struct{})
		ta.daemon.mu.Unlock()
		waitFor(t, "the outage notice",
			said("⚠ the DefenseClaw daemon is not reachable, so the hooks fail closed: Claude Code can't use its tools until it is back"))
		ta.daemon.mu.Lock()
		delete(ta.daemon.errors, "GET "+sandboxapi.PathStatus)
		ta.daemon.mu.Unlock()
		// Back, it holds the new stream open: the return is said without
		// waiting for that stream to end.
		waitFor(t, "the return notice", said("✓ the DefenseClaw daemon is reachable again"))
	}
	ta.ok(t, ta.Run(bg, RunOptions{Harness: "claude"}))
	has(t, ta.output(), "⚠ the DefenseClaw daemon was not reachable from ", "the hooks failed closed meanwhile")
}

// What the end of a session says, and its exit status (manual R2-2, R2-6,
// R2-66, R2-78, L3): late denials count, a harness that failed early is not
// blamed on the hooks, the continue hint follows a conversation only, and
// the agent's names cannot drive the terminal.
func TestSessionSummary(t *testing.T) {
	claude := RunOptions{Harness: "claude"}
	elsewhere := func(undone bool) func(*testApp) {
		return func(ta *testApp) {
			noChanges(ta)
			ta.term.code = 255
			ta.term.during = func() {
				ta.daemon.edit(sbName, func(sb *sandboxapi.Sandbox) {
					sb.Phase = "stopped"
					if undone {
						sb.Snapshot = &sandboxapi.SnapshotInfo{Kind: "git", UndoneAt: ta.Now().Add(time.Minute)}
					}
				})
			}
		}
	}
	noStop := func(t *testing.T, ta *testApp) { ta.wantCalls(t, 0, "POST", sbName+"/stop") }
	continueHint := func(env string, wrapped bool) func(*testApp) {
		return func(ta *testApp) {
			noChanges(ta)
			ta.env["OPENAI_API_KEY"] = env
			if wrapped {
				ta.Cfg.OpenShell.Wrappers = []string{"claudecode"}
			}
		}
	}
	const cont = "continue this conversation: defenseclaw sandbox connect " + sbName
	evil := "notes\x1b[2J\x1b]0;DCMARKER\x07\rx\u202etxt.sh"
	runCases(t, []runCase{
		{name: "late denials count", opts: claude, want: []string{"0 new sites contacted (2 requests blocked)"}, setup: func(ta *testApp) {
			noChanges(ta)
			var armed atomic.Bool
			var late atomic.Int32
			late.Store(2)
			ta.daemon.onGet = func(sb *sandboxapi.Sandbox) {
				if armed.Load() && late.Add(-1) >= 0 {
					sb.Egress.Blocked++
				}
			}
			ta.term.during = func() { armed.Store(true) }
		}},
		{name: "after a daemon restart", do: func(ta *testApp) error { return ta.Connect(bg, ConnectOptions{Name: "box"}) }, setup: func(ta *testApp) {
			noChanges(ta)
			ta.term.hooks = nil
			sb := sampleSandbox("box")
			sb.Hooks = sandboxapi.HookCoverage{HookRequests: 107, ToolCalls: 13, LastHookAt: time.Now().Add(-time.Hour)}
			sb.Egress = sandboxapi.EgressStats{Destinations: 20, Blocked: 3}
			ta.daemon.add(sb)
			ta.term.during = func() {
				ta.daemon.edit("box", func(sb *sandboxapi.Sandbox) {
					sb.Hooks = sandboxapi.HookCoverage{HookRequests: 15, ToolCalls: 1, LastHookAt: time.Now()}
					sb.Egress = sandboxapi.EgressStats{Destinations: 2}
				})
			}
		}, want: []string{"Session ended · 1 tool call since the daemon restarted · 2 new sites contacted"}, not: []string{"hooks are not reaching"}},
		{name: "the harness failed before its hooks", opts: claude, exit: 1, setup: func(ta *testApp) {
			noChanges(ta)
			ta.term.hooks, ta.term.code = nil, 1
		}, want: []string{"✗ Claude Code exited with status 1 before any of its hooks reached DefenseClaw: the harness itself failed (its output is above)"},
			not: []string{"hooks are not reaching", "continue this conversation"}},
		{name: "stopped from elsewhere", opts: claude, exit: 255, setup: elsewhere(false), check: noStop,
			want: []string{sbName + " was stopped from outside this session (`defenseclaw sandbox stop` or the TUI), which ended Claude Code", "Sandbox kept (stopped)"},
			not:  []string{"the harness itself failed"}},
		{name: "undone from elsewhere", opts: claude, exit: 255, setup: elsewhere(true), check: noStop,
			want: []string{sbName + " was undone from outside this session (`defenseclaw sandbox undo` or the TUI): the folder is back at its undo point, " +
				"and that stopped Claude Code", "Sandbox kept (stopped)"}, not: []string{"the harness itself failed"}},
		{name: "continue claude", opts: claude, setup: continueHint("", false), want: []string{cont +
			" -- --continue (the `claude --resume …` Claude Code printed would run it on this machine, outside the sandbox)"}},
		{name: "continue claude with the wrapper", opts: claude, setup: continueHint("", true), want: []string{cont +
			" -- --continue (the `claude --resume …` Claude Code printed resumes it in this sandbox too: the shell wrapper is on)"}},
		{name: "continue codex", opts: RunOptions{Harness: "codex"}, setup: continueHint("sk-mock", false),
			want: []string{"-- resume --last (the `codex resume …` Codex printed would run it on this machine, outside the sandbox)"}},
		// OmniGent prints `Resume: omnigent run <agent> --model <m> --resume
		// <id>` at /quit, and a plain connect started a new conversation
		// (OG-U2).
		{name: "continue omnigent", opts: RunOptions{Harness: "omnigent", Args: []string{"--model", "gpt-5-mini"}}, setup: continueHint("sk-mock", false),
			want: []string{cont + " -- --continue (the `omnigent run …` OmniGent printed would run it on this machine, outside the sandbox)"}},
		{name: "no continue after one prompt", opts: RunOptions{Harness: "claude", Prompt: "fix it"}, setup: func(ta *testApp) {
			ta.IO.TTY = false
			noChanges(ta)
		}, not: []string{"continue this conversation"}},
		{name: "commits", input: "y\n", opts: claude, setup: func(ta *testApp) {
			ta.daemon.review = sandboxapi.ReviewResponse{Summary: "0 files changed (+0 −0)", Report: &workspace.ReviewReport{
				HeadBefore: strings.Repeat("a", 40), HeadAfter: strings.Repeat("b", 40), BranchBefore: "main", BranchAfter: "main"}}
		}, want: []string{"0 files changed (+0 −0) · HEAD moved on main (aaaaaaa → bbbbbbb)", "Keep changes?"}},
		{name: "the harness's exit status", opts: claude, exit: 3, setup: func(ta *testApp) {
			noChanges(ta)
			ta.term.code = 3
		}},
		{name: "the review cannot drive the terminal", input: "d\ny\n", opts: claude, setup: func(ta *testApp) {
			ta.daemon.review = sandboxapi.ReviewResponse{Report: &workspace.ReviewReport{FilesChanged: 1, Insertions: 1, BranchBefore: "main", BranchAfter: "main",
				Flags: []workspace.Flag{{Path: evil, Label: evil, Kind: workspace.RiskExecutable, Severity: workspace.SeverityHigh, Detail: "new executable"}}}}
			ta.term.during = func() {
				ta.daemon.edit(sbName, func(sb *sandboxapi.Sandbox) {
					sb.Hooks = sandboxapi.HookCoverage{ToolCalls: 2, ToolBlocked: 1, LastBlocked: "rm\x1b[1A marker"}
				})
			}
		}, want: []string{"notes\ufffd[2J", "+changed"}, not: []string{"\x1b", "\x07", "\r", "\u202e"}},
		{name: "keeping is confirmed and the diff paged", input: "d\ny\n", opts: claude, setup: func(ta *testApp) {
			ta.App.pager = func(text string) bool {
				ta.err.WriteString(text)
				return true
			}
		}, want: []string{"✓ kept: the changes stay in the folder, and the next session takes a new undo point"}, not: []string{"+changed"},
			check: func(t *testing.T, ta *testApp) { has(t, ta.err.String(), "+changed") }},
		{name: "connect --shell", input: "y\n", do: func(ta *testApp) error { return ta.Connect(bg, ConnectOptions{Name: "r2c1-cp", Shell: true}) },
			setup: func(ta *testApp) {
				ta.term.hooks = nil
				sb := sampleSandbox("r2c1-cp")
				sb.Phase, sb.Snapshot = "stopped", &sandboxapi.SnapshotInfo{Kind: "git"}
				ta.daemon.add(sb)
			}, want: []string{"Sandbox r2c1-cp · Claude Code", "Session ended ·", "Keep changes?"},
			not: []string{"hooks are not reaching", "continue this conversation"}, check: func(t *testing.T, ta *testApp) {
				if len(ta.term.runs) != 1 {
					t.Fatalf("terminal runs = %q", ta.term.runs)
				}
				has(t, strings.Join(ta.term.runs[0], " "), "--workdir /work/proj", "exec bash -l")
			}},
	})
}

// Hooks that never reach DefenseClaw (the hooks fail closed) are warned
// about live and in the summary, with ExitHooksUnreachable unless the
// harness failed itself; the daemon's verdict wins. Idle harnesses whose
// first hook comes with the first prompt (Codex with telemetry, Kiro:
// manual R2-66) are not warned about.
func TestSessionHookWarnings(t *testing.T) {
	quiet := func(window time.Duration) func(*testApp) {
		return func(ta *testApp) {
			noChanges(ta)
			ta.term.hooks, ta.HookWindow = nil, window
		}
	}
	unreachable := func(name, why string) func(*testing.T, *testApp) {
		return func(_ *testing.T, ta *testApp) {
			ta.daemon.edit(name, func(sb *sandboxapi.Sandbox) {
				sb.Hooks.LastOTLPAt = time.Now()
				sb.Hooks.Unreachable, sb.Hooks.UnreachableReason = true, why
			})
		}
	}
	idle := func(_ *testing.T, ta *testApp) {
		ta.daemon.edit(sbName, func(sb *sandboxapi.Sandbox) { sb.Hooks.LastOTLPAt = time.Now() })
		time.Sleep(50 * time.Millisecond) // past the window
	}
	reason := "OpenShell refused the hooks' connections to the DefenseClaw ingress (host.openshell.internal:18971)"
	kiro := RunOptions{Harness: "kiro", Name: "r2c1-kiro"}
	runCases(t, []runCase{
		{name: "hooks never reach DefenseClaw", setup: quiet(10 * time.Millisecond), opts: RunOptions{Harness: "claude"}, exit: ExitHooksUnreachable,
			during: func(t *testing.T, ta *testApp) {
				waitFor(t, "the live warning", func() bool { return strings.Contains(ta.live.String(), "[defenseclaw] ⚠ DefenseClaw hooks") })
			},
			live: []string{"[defenseclaw] ⚠ DefenseClaw hooks are not reaching the daemon; every tool call is being blocked",
				"not one hook request reached DefenseClaw in the session's first", "Run: defenseclaw sandbox doctor"},
			want: []string{"Session ended · 0 tool calls", "✗ DefenseClaw hooks are not reaching the daemon; every tool call is being blocked " +
				"(not one hook request of this session reached DefenseClaw). Run: defenseclaw sandbox doctor"},
			check: func(t *testing.T, ta *testApp) {
				if n := strings.Count(ta.live.String(), "\x1b]9;DefenseClaw: ⚠ DefenseClaw hooks are not reaching"); n != 1 {
					t.Errorf("live warnings = %d, want 1", n)
				}
			}},
		{name: "the daemon's verdict", opts: RunOptions{Harness: "claude"}, exit: 3, setup: func(ta *testApp) {
			noChanges(ta)
			ta.term.hooks, ta.term.code = nil, 3
			ta.daemon.live = []sandboxapi.ActivityEvent{
				{Seq: 1, Kind: sandboxapi.ActivityFinding, Sandbox: "other", Reason: sandboxapi.ReasonHooksUnreachable, Message: "⚠ not this sandbox"},
				{Seq: 2, Kind: sandboxapi.ActivityFinding, Sandbox: sbName, Reason: sandboxapi.ReasonHooksUnreachable, Message: "⚠ " + hooksWarningText(reason)},
			}
		}, during: func(t *testing.T, ta *testApp) {
			waitFor(t, "the daemon's warning", func() bool { return strings.Contains(ta.live.String(), "OpenShell refused") })
			unreachable(sbName, reason)(t, ta)
		}, want: []string{"✗ " + hooksWarningText(reason)}, notLive: []string{"not this sandbox"}, check: func(t *testing.T, ta *testApp) {
			if n := strings.Count(ta.live.String(), "[defenseclaw]"); n != 1 {
				t.Fatalf("live notices = %d:\n%s", n, ta.live.String())
			}
		}},
		{name: "hooks reach DefenseClaw", opts: RunOptions{Harness: "claude"}, setup: func(ta *testApp) {
			noChanges(ta)
			ta.HookWindow = 10 * time.Millisecond
		}, during: func(_ *testing.T, ta *testApp) {
			ta.daemon.hookTraffic([]string{"--name", sbName})
			time.Sleep(50 * time.Millisecond) // past the window
		}, not: []string{"not reaching"}, notLive: []string{"not reaching"}},
		{name: "an idle codex with telemetry", opts: RunOptions{Harness: "codex"}, setup: quiet(10 * time.Millisecond), during: idle,
			not: []string{"not reaching"}, notLive: []string{"not reaching"}},
		{name: "telemetry does not hide the daemon's verdict", opts: RunOptions{Harness: "codex"}, setup: quiet(time.Hour), exit: ExitHooksUnreachable,
			during: unreachable(sbName, "the hook token was refused"), want: []string{"✗ " + hooksWarningText("the hook token was refused")}},
		{name: "a copy-mode session", input: "s\n", opts: RunOptions{Harness: "claude", Copy: true, Name: "copybox"}, exit: ExitHooksUnreachable,
			setup: func(ta *testApp) { ta.term.hooks = nil }, want: []string{"✗ DefenseClaw hooks are not reaching the daemon"}},
		{name: "an idle kiro", opts: kiro, setup: quiet(time.Millisecond), during: func(*testing.T, *testApp) { time.Sleep(30 * time.Millisecond) },
			want: []string{"no hook of this session reached DefenseClaw: Kiro CLI sends its first one with your first prompt"},
			not:  []string{"hooks are not reaching"}, notLive: []string{"hooks are not reaching"}},
		{name: "kiro the daemon found unreachable", opts: kiro, setup: quiet(0), exit: ExitHooksUnreachable,
			during: unreachable("r2c1-kiro", "no hook request")},
	})
}

// Manual R2-11: Ctrl-C at the keep/undo question does not end the process
// silently: it says the changes stay and undo still reverts them, stops
// and keeps the sandbox, and exits 130.
func TestKeepQuestionCtrlCSaysWhatIsLeft(t *testing.T) {
	ta := newTestApp(t, "")
	pr, pw := io.Pipe() // a terminal nobody types into
	t.Cleanup(func() { _ = pw.Close() })
	ta.IO.In = pr
	sig := make(chan os.Signal, 1)
	ta.App.interrupts = func() (<-chan os.Signal, func()) {
		sig <- os.Interrupt
		return sig, func() {}
	}
	wantExit(t, ta.Run(bg, RunOptions{Harness: "claude"}), exitInterrupted)
	has(t, ta.output(), "Keep changes? [Y] keep  [u] undo everything  [d] show diff (then Enter)",
		"⚠ interrupted: nothing was decided, so the changes stay in the folder and the undo point is kept (`defenseclaw sandbox undo "+sbName+"` still reverts them",
		"Sandbox kept (stopped)")
	ta.wantCalls(t, 0, "POST", sbName+"/undo")
	ta.wantCalls(t, 1, "POST", sbName+"/stop")
}

func TestLogsChecksTheRunsHooks(t *testing.T) {
	started := time.Now().Add(-time.Minute)
	exited := fmt.Sprintf("started=%d\nstate=exited\nexit=0\n", started.Unix())
	for _, c := range []struct {
		name    string
		status  string // the run-state script's answer
		hooks   sandboxapi.HookCoverage
		code    int
		warning string
	}{
		{"hooks during the run", exited, sandboxapi.HookCoverage{HookRequests: 3, LastHookAt: time.Now()}, 0, ""},
		{"no hook since the run started", exited, sandboxapi.HookCoverage{HookRequests: 3, LastHookAt: started.Add(-time.Hour)}, ExitHooksUnreachable,
			"not one hook request of this run reached DefenseClaw"},
		{"never a hook, the daemon knows why", exited,
			sandboxapi.HookCoverage{Unreachable: true, UnreachableReason: "OpenShell refused the hooks' connections"}, ExitHooksUnreachable,
			"(OpenShell refused the hooks' connections). Run: defenseclaw sandbox doctor"},
		{"run of an older version, no start", "started=\nstate=exited\nexit=0\n", sandboxapi.HookCoverage{}, ExitHooksUnreachable,
			"every tool call is being blocked"},
		{"run of an older version with hooks", "state=exited\nexit=0\n", sandboxapi.HookCoverage{HookRequests: 1, LastHookAt: time.Now()}, 0, ""},
		{"still going, unreachable", "started=1\nstate=running\n", sandboxapi.HookCoverage{Unreachable: true, UnreachableReason: "no hook request"}, 0,
			"every tool call is being blocked (no hook request)"},
	} {
		t.Run(c.name, func(t *testing.T) {
			ta := newTestApp(t, "")
			ta.IO.TTY = false
			sb := sampleSandbox("box")
			sb.Hooks = c.hooks
			ta.daemon.add(sb)
			ta.stream.answer = func(argv []string) (int, string) {
				if isRunStatus(sandboxCommand(argv)) {
					return 0, c.status
				}
				return 0, "log line\n"
			}
			if err := ta.Logs(bg, LogsOptions{Name: "box"}); c.code != 0 {
				wantExit(t, err, c.code)
			} else {
				ta.ok(t, err)
			}
			if c.warning == "" {
				lacks(t, ta.output(), "not reaching")
			} else {
				has(t, ta.output(), "DefenseClaw hooks are not reaching the daemon", c.warning)
			}
		})
	}
}

func TestParseDetachedRun(t *testing.T) {
	for in, want := range map[string]detachedRun{
		"state=none\n":                          {State: runNone},
		"started=1790000000\nstate=running\n":   {State: runRunning, Started: 1790000000},
		"started=\nstate=exited\nexit=3\n":      {State: runExited, Exit: "3"},
		"started=17\nstate=interrupted\n":       {State: runInterrupted, Started: 17},
		" state=exited \n exit=0 \n garbage \n": {State: runExited, Exit: "0"},
		"state=bogus\n":                         {State: runNone},
		"":                                      {State: runNone},
	} {
		if got := parseDetachedRun(in); got != want {
			t.Errorf("parseDetachedRun(%q) = %+v, want %+v", in, got, want)
		}
	}
}

func TestDoctorReportsSandboxHooks(t *testing.T) {
	check := func(ta *testApp) openshell.Check {
		t.Helper()
		ta.HostDoctor = func(context.Context, *openshell.Doctor) *openshell.DoctorReport { return &openshell.DoctorReport{} }
		for _, c := range ta.runDoctor(bg).Checks {
			if c.ID == CheckIDHooks {
				return c
			}
		}
		t.Fatal("no sandbox-hooks check")
		return openshell.Check{}
	}
	ta := newTestApp(t, "")
	if c := check(ta); c.Status != openshell.StatusPass || c.Detail != "no sandbox is running" {
		t.Fatalf("no sandboxes: %+v", c)
	}
	ta.daemon.add(sampleSandbox("good"))
	if c := check(ta); c.Status != openshell.StatusPass || !strings.Contains(c.Detail, "1 running sandbox reach") {
		t.Fatalf("healthy: %+v", c)
	}
	bad := sampleSandbox("bad")
	bad.Hooks.Unreachable, bad.Hooks.UnreachableReason = true, "OpenShell refused the hooks' connections"
	ta.daemon.add(bad)
	c := check(ta)
	if c.Status != openshell.StatusFail || !strings.Contains(c.Detail, "bad: OpenShell refused the hooks' connections") ||
		strings.Contains(c.Detail, "good") || !strings.Contains(c.Detail, "127.0.0.1:18971") || c.Fix == nil {
		t.Fatalf("unreachable: %+v", c)
	}
}

// A session in a sandbox that was running leaves it running (stopping it
// killed a detached run: manual test H9), says the review may miss what
// comes later, and keeps the undo point; one it started is stopped.
func TestConnectLeavesARunningSandboxRunning(t *testing.T) {
	for _, c := range []struct {
		name, phase, state string
		rm                 bool
		stops              int
		want               []string
		detached           bool // no undo and no keep question under the run
	}{
		{name: "detached run going", phase: "ready", state: "started=1790000000\nstate=running\n", detached: true,
			want: []string{"Sandbox m1-b keeps running: its detached run is still going", "logs m1-b -f",
				"the detached run in m1-b is still going; review or undo once it ends"}},
		{name: "detached run going, --rm", phase: "ready", state: "state=running\n", rm: true, detached: true,
			want: []string{"m1-b is not deleted (--rm): its detached run is still going"}},
		{name: "running, no run", phase: "ready", state: "state=none\n", want: []string{"Sandbox m1-b keeps running (it was running when you connected)",
			"m1-b is still running (it was running when you connected); changes it makes after this point are not in this review",
			"Keep changes?", "the undo point stays, since m1-b keeps running"}},
		{name: "stopped before the session", phase: "stopped", state: "state=none\n", stops: 1,
			want: []string{"Sandbox kept (stopped) → resume: defenseclaw sandbox connect m1-b"}},
	} {
		t.Run(c.name, func(t *testing.T) {
			ta := newTestApp(t, "y\n")
			sb := sampleSandbox("m1-b")
			sb.Phase, sb.Snapshot = c.phase, &sandboxapi.SnapshotInfo{Kind: "git", CreatedAt: time.Now().Add(-time.Hour)}
			ta.daemon.add(sb)
			runAnswers(ta, c.state, "")
			ta.ok(t, ta.Connect(bg, ConnectOptions{Name: "m1-b", Rm: c.rm}))
			ta.wantCalls(t, c.stops, "POST", "m1-b/stop")
			ta.wantCalls(t, 0, "DELETE", "m1-b")
			has(t, ta.output(), c.want...)
			if c.detached && (ta.calls("POST", "m1-b/undo") != 0 || strings.Contains(ta.output(), "Keep changes?")) {
				t.Fatalf("undo was offered with a detached run going (an undo stops the sandbox under it):\n%s", ta.output())
			}
			if c.stops == 0 {
				unaccepted(t, ta, "m1-b")
			}
		})
	}
}

// `sandbox stop` on a sandbox whose detached run is still going asks first
// on a terminal, marks the run interrupted and keeps its log on this
// machine, where `sandbox logs` reads it once the sandbox is stopped (manual
// test M1). Deleting the sandbox drops what the CLI kept of it.
func TestStopWithALiveDetachedRun(t *testing.T) {
	const log = "working on it\nstill working\n"
	going := "started=1790000000\nstate=running\n"
	t.Run("declined", func(t *testing.T) {
		ta := newTestApp(t, "n\n", sampleSandbox("box"))
		runAnswers(ta, going, log)
		ta.ok(t, ta.Stop(bg, StopOptions{Name: "box"}))
		if ta.calls("POST", "box/stop") != 0 || ranScript(ta, runMarkScript) {
			t.Fatal("the sandbox was stopped, or its run marked, although the user kept the run going")
		}
		has(t, ta.output(), "box's detached run (started ", "Stop anyway? [y/N]", "box keeps running")
	})
	for _, c := range []struct {
		name string
		tty  bool
		yes  bool
		in   string
		asks bool
	}{{"confirmed", true, false, "y\n", true}, {"--yes", true, true, "", false}, {"no terminal", false, false, "", false}} {
		t.Run(c.name, func(t *testing.T) {
			ta := newTestApp(t, c.in)
			ta.IO.TTY = c.tty
			ta.daemon.add(sampleSandbox("box"))
			runAnswers(ta, going, log)
			ta.ok(t, ta.Stop(bg, StopOptions{Name: "box", Yes: c.yes}))
			if ta.calls("POST", "box/stop") != 1 || !ranScript(ta, runMarkScript) {
				t.Fatal("the run was not marked interrupted and the sandbox stopped")
			}
			has(t, ta.output(), "is still going; stopping the sandbox ends it")
			if strings.Contains(ta.output(), "Stop anyway?") != c.asks {
				t.Fatalf("asked = %t:\n%s", !c.asks, ta.output())
			}
			// Stopped, the kept log is what `logs` shows.
			ta.out.Reset()
			ta.stream.runs = nil
			ta.ok(t, ta.Logs(bg, LogsOptions{Name: "box", Lines: 1}))
			has(t, ta.output(), "still working", "the log kept when it stopped", "the run did not finish")
			lacks(t, ta.output(), "working on it")
			if len(ta.stream.runs) != 0 {
				t.Fatalf("logs of a stopped sandbox ran %q in it", ta.stream.commands())
			}
			dir, _ := ta.cliStateDir("box")
			if _, err := os.Stat(filepath.Join(dir, "run.log")); err != nil {
				t.Fatalf("kept log: %v", err)
			}
			ta.ok(t, ta.Delete(bg, DeleteOptions{Names: []string{"box"}, Yes: true}))
			if _, err := os.Stat(dir); !os.IsNotExist(err) {
				t.Fatalf("the kept state outlived the sandbox: %v", err)
			}
		})
	}
}

// A kept log belongs to one sandbox: a later sandbox of the same name does
// not show it, and a stopped sandbox without one says how to read its log.
// Without the kept marker, a run whose process is gone reads "did not
// finish", not "still going".
func TestLogsOfAStoppedSandbox(t *testing.T) {
	ta := newTestApp(t, "")
	sb := sampleSandbox("box")
	ta.daemon.add(sb)
	ta.ok(t, ta.saveRunLog(&sb, detachedRun{State: runExited, Exit: "0"}, []byte("done\n")))
	sb.Phase, sb.ID = "stopped", "sb-another-box"
	ta.daemon.add(sb)
	wantErr(t, ta.Logs(bg, LogsOptions{Name: "box"}), "no log of a detached run was kept", "defenseclaw sandbox start box")

	ta = newTestApp(t, "")
	ta.IO.TTY = false
	ta.daemon.add(sampleSandbox("box"))
	runAnswers(ta, "started=1790000000\nstate=interrupted\n", "partial\n")
	ta.ok(t, ta.Logs(bg, LogsOptions{Name: "box"}))
	has(t, ta.output(), "the run did not finish")
	lacks(t, ta.output(), "still going")
	// The pid check is the run-state script's; -f stops once the run is gone.
	has(t, runStateScript, `kill -0 "$pid"`, "/proc/$pid/cmdline", "grep -q latest.exit", "state=interrupted")
	has(t, runFollowScript, `while alive && [ ! -s "$d/latest.exit" ]`, `kill "$t"`)
}

// A detached Claude Code run streams its events, which `logs` renders; a
// user's own --output-format wins.
func TestDetachedClaudeStreamsAndLogsRenderIt(t *testing.T) {
	for _, c := range []struct {
		spec       *harness.Spec
		args, want []string
	}{
		{harness.ClaudeCode, []string{"--model", "sonnet"}, []string{"--model", "sonnet", "--output-format", "stream-json", "--verbose"}},
		{harness.ClaudeCode, []string{"--output-format=json"}, []string{"--output-format=json"}},
		{harness.Codex, []string{"exec", "x"}, []string{"exec", "x"}},
	} {
		if got := streamingArgs(c.spec, c.args); !slices.Equal(got, c.want) {
			t.Fatalf("streamingArgs(%q) = %q", c.args, got)
		}
	}
	events := strings.Join([]string{
		`{"type":"system","subtype":"init","model":"claude-sonnet-4-5","tools":["Bash"]}`,
		`{"type":"assistant","message":{"content":[{"type":"text","text":"Looking at the tests."},{"type":"tool_use","name":"Bash","input":{"command":"go test ./..."}}]}}`,
		`{"type":"user","message":{"content":[{"type":"tool_result","is_error":true,"content":"blocked by DefenseClaw: DCBLOCK"}]}}`,
		`{"type":"user","message":{"content":[{"type":"tool_result","content":"ok"}]}}`,
		`{"type":"stream_event","event":{}}`,
		`plain launcher line`,
		`{"type":"result","subtype":"success","is_error":false,"num_turns":3,"duration_ms":65000,"result":"Fixed."}`,
		`{"type":"unknown_kind"}`,
	}, "\n") + "\n"
	ta := newTestApp(t, "")
	r := &streamRenderer{w: ta.out}
	// Split mid-line: the renderer waits for whole lines.
	_, _ = r.Write([]byte(events[:37]))
	_, _ = r.Write([]byte(events[37:]))
	_ = r.Flush()
	want := strings.Join([]string{
		"● session started (claude-sonnet-4-5)",
		"Looking at the tests.",
		"→ Bash: go test ./...",
		"  ✗ blocked by DefenseClaw: DCBLOCK",
		"plain launcher line",
		"● finished after 3 turns, 1m",
		`{"type":"unknown_kind"}`,
	}, "\n") + "\n"
	if got := ta.output(); got != want {
		t.Fatalf("rendered:\n%s\nwant:\n%s", got, want)
	}
}

// Resuming after a session whose changes nobody kept (a detached run, a
// terminal-less end) keeps its undo point, so `undo` still reverts them:
// the daemon decides, and the banner says what it did. Once the user keeps
// the changes at the end of a session, the next connect asks for a new
// snapshot (manual test M2).
func TestResumeKeepsAnUnacceptedUndoPoint(t *testing.T) {
	ta := newTestApp(t, "y\ny\n")
	sb := sampleSandbox("m1-a")
	sb.Phase = "stopped"
	earlier := time.Date(2026, 9, 27, 9, 30, 0, 0, time.UTC)
	sb.Snapshot = &sandboxapi.SnapshotInfo{Kind: "git", CreatedAt: earlier}
	sb.Workspace = &sandboxapi.WorkspaceSummary{Project: "~/proj → /work/proj (live)"}
	ta.daemon.add(sb)
	ta.daemon.pendingChanges = true
	ta.ok(t, ta.Connect(bg, ConnectOptions{Name: "m1-a"}))
	if starts := ta.bodies("POST", "m1-a/start"); len(starts) != 1 || strings.Contains(starts[0], "snapshot") {
		t.Fatalf("start = %q; the daemon decides about an unaccepted undo point", starts)
	}
	has(t, ta.output(), "kept the undo point from "+ta.clock(earlier),
		"undo point from "+ta.clock(earlier)+" kept → `defenseclaw sandbox undo m1-a` reverts every session since")
	lacks(t, ta.output(), "undo point taken")
	// The user kept the changes: the next connect asks for a new snapshot.
	ta.out.Reset()
	ta.daemon.edit("m1-a", func(sb *sandboxapi.Sandbox) { sb.Phase = "stopped" })
	ta.ok(t, ta.Connect(bg, ConnectOptions{Name: "m1-a"}))
	if starts := ta.bodies("POST", "m1-a/start"); len(starts) != 2 || !strings.Contains(starts[1], `"new_snapshot":true`) {
		t.Fatalf("start after keeping = %q", starts)
	}
	has(t, ta.output(), "undo point taken → `defenseclaw sandbox undo m1-a` restores it")
	lacks(t, ta.output(), "kept the undo point")
}

// `start` takes a fresh snapshot when nothing is on top of the last one;
// over changes nobody kept, the daemon keeps the undo point, and the start
// says so once and names --new-snapshot (manual R2-13), which accepts them.
func TestStartTakesAFreshSnapshotWhenNothingIsOnTop(t *testing.T) {
	ta := newTestApp(t, "")
	ta.IO.TTY = false
	sb := sampleSandbox("box")
	sb.Phase = "stopped"
	sb.Snapshot = &sandboxapi.SnapshotInfo{Kind: "git", CreatedAt: time.Now().Add(-time.Hour)}
	for i, c := range []struct {
		pending bool
		opts    StartOptions
		fresh   bool
		want    []string
		not     string
	}{
		{false, StartOptions{}, false, []string{"undo point taken → `defenseclaw sandbox undo box` restores it"}, "kept the undo point"},
		{true, StartOptions{}, false, []string{"kept the undo point from ", "`defenseclaw sandbox undo box` still reverts them",
			"`defenseclaw sandbox start box --new-snapshot`"}, "reverts every session since"},
		{true, StartOptions{NewSnapshot: true}, true, []string{"undo point taken"}, "kept the undo point"},
	} {
		ta.out.Reset()
		ta.daemon.add(sb)
		ta.daemon.pendingChanges = c.pending
		ta.ok(t, ta.Start(bg, "box", c.opts))
		starts := ta.bodies("POST", "box/start")
		if len(starts) != i+1 || strings.Contains(starts[i], `"new_snapshot":true`) != c.fresh || (!c.fresh && strings.Contains(starts[i], "snapshot")) {
			t.Fatalf("start %d = %q", i, starts)
		}
		has(t, ta.output(), c.want...)
		lacks(t, ta.output(), c.not)
	}
}

// A headless session in an existing sandbox runs without a terminal:
// `connect NAME --prompt TEXT` or the harness's own print flag (manual
// test M6).
func TestConnectRunsOnePromptHeadless(t *testing.T) {
	for _, c := range []struct {
		name string
		opts ConnectOptions
	}{
		{"--prompt", ConnectOptions{Name: "m1-a", Prompt: "add the tests"}},
		{"print flag", ConnectOptions{Name: "m1-a", Args: []string{"-p", "add the tests"}}},
	} {
		t.Run(c.name, func(t *testing.T) {
			ta := newTestApp(t, "")
			ta.IO.TTY = false
			sb := sampleSandbox("m1-a")
			sb.Phase = "stopped"
			ta.daemon.add(sb)
			ta.ok(t, ta.Connect(bg, c.opts))
			if len(ta.term.runs) != 0 {
				t.Fatal("a headless connect took the terminal")
			}
			if !slices.ContainsFunc(ta.stream.runs, func(argv []string) bool {
				cmd := sandboxCommand(argv)
				return len(cmd) >= 2 && cmd[0] == harness.ClaudeCodeLauncherPath && slices.Equal(cmd[len(cmd)-2:], []string{"-p", "add the tests"})
			}) {
				t.Fatalf("stream runs = %q", ta.stream.commands())
			}
			ta.wantCalls(t, 1, "POST", "m1-a/stop")
			has(t, ta.output(), "resume: defenseclaw sandbox connect m1-a --prompt TEXT")
		})
	}
	ta := newTestApp(t, "")
	ta.IO.TTY = false
	ta.daemon.add(sampleSandbox("m1-a"))
	wantErr(t, ta.Connect(bg, ConnectOptions{Name: "m1-a"}), "pass --prompt TEXT")
	wantErr(t, ta.Connect(bg, ConnectOptions{Name: "m1-a", Shell: true}), "defenseclaw sandbox exec m1-a -- COMMAND")
}

// A connect that started the sandbox for a session that never began (the
// probe failed) stops it again.
func TestConnectStopsWhatItStartedWhenTheSessionFails(t *testing.T) {
	ta := newTestApp(t, "")
	sb := sampleSandbox("m1-a")
	sb.Phase = "stopped"
	ta.daemon.add(sb)
	ta.stream.answer = func(argv []string) (int, string) {
		if cmd := sandboxCommand(argv); len(cmd) == 1 && cmd[0] == "true" {
			return 1, "no answer"
		}
		return 0, ""
	}
	wantErr(t, ta.Connect(bg, ConnectOptions{Name: "m1-a"}), "does not answer")
	ta.wantCalls(t, 1, "POST", "m1-a/stop")
}

// A resumed sandbox keeps the credential bindings and host ports it was
// created with. The offer names those this run did not ask for and
// defaults to a new sandbox; the banner and the status show the sandbox's
// own, whatever this invocation passed.
func TestResumeNamesTheGrantsItKeeps(t *testing.T) {
	existing := func(ta *testApp) {
		sb := folderSandbox(ta, "stopped")
		sb.HostPorts = []int{5432}
		sb.Credentials = []sandboxapi.CredentialGrant{{Name: "STRIPE_API_KEY", Host: "api.stripe.com", Port: 443},
			{Name: "GH_TOKEN", Host: "api.github.com", Port: 443}, {Name: "GITHUB_TOKEN", Host: "api.github.com", Port: 443}}
		ta.daemon.add(sb)
		noChanges(ta)
	}
	// No to the resume (the default), a copy for the folder the old sandbox
	// still mounts live, and skip bringing the copy's changes back.
	ta := newTestApp(t, "\n\ns\n")
	existing(ta)
	ta.ok(t, ta.Run(bg, RunOptions{Harness: "claude"}))
	has(t, ta.output(), "It keeps grants this run did not ask for: --credential STRIPE_API_KEY → api.stripe.com, --github-write "+
		"(the GitHub token for api.github.com), --host-port 5432. Resume it anyway? [y/N]")
	if n := ta.calls("POST", "proj-0a1b/start"); n != 0 {
		t.Fatal("the default resumed the sandbox")
	}
	// Asked for, a grant is not named; resumed, the banner shows the
	// sandbox's own grants.
	ta = newTestApp(t, "y\ny\n")
	ta.env["STRIPE_API_KEY"] = "stripe-test-value"
	existing(ta)
	ta.ok(t, ta.Run(bg, RunOptions{Harness: "claude", GitHubWrite: true, HostPorts: []int{5432}}))
	has(t, ta.output(), "It keeps grants this run did not ask for: --credential STRIPE_API_KEY → api.stripe.com. Resume it anyway?",
		"Secret    STRIPE_API_KEY → api.stripe.com only", "Secret    GH_TOKEN/GITHUB_TOKEN → api.github.com only", "Host      localhost:5432")
	lacks(t, ta.output(), "--github-write", "ignores")
	ta.ok(t, ta.fresh().Status(bg, "proj-0a1b", OutputText))
	has(t, ta.output(), "Secret        STRIPE_API_KEY → api.stripe.com only", "Host ports    localhost:5432")
}

// The offer to resume names the flags a resume would ignore and defaults to
// a new sandbox; resuming anyway says what was left out. A headless run is
// offered the folder's sandbox too (`claude -p` created one every time).
func TestRunResumeNamesTheFlagsItIgnores(t *testing.T) {
	opts := RunOptions{Harness: "claude", Safe: true, Pack: "open", Credentials: []string{"STRIPE_API_KEY=api.stripe.com"}}
	existing := func(input string) *testApp {
		ta := newTestApp(t, input)
		ta.env["STRIPE_API_KEY"] = "stripe-test-value"
		ta.daemon.add(folderSandbox(ta, "stopped"))
		noChanges(ta)
		return ta
	}
	// No to the resume, the default (a copy) for the folder the old sandbox
	// still mounts live, and skip bringing the copy's changes back.
	ta := existing("\n\ns\n")
	ta.ok(t, ta.Run(bg, opts))
	has(t, ta.output(), "Resuming it keeps its own settings and ignores --safe, --credential. Resume it anyway? [y/N]")
	if req := createRequest(t, ta.daemon); !req.Safe || len(req.Credentials) != 1 || ta.calls("POST", "proj-0a1b/start") != 0 {
		t.Fatalf("the default must start a new sandbox with the flags: %+v", req)
	}
	ta = existing("y\ny\n")
	ta.ok(t, ta.Run(bg, opts))
	if n := ta.creates(); n != 0 {
		t.Fatal("resuming anyway created a sandbox")
	}
	has(t, ta.output(), "resuming proj-0a1b without --safe, --credential (they apply to a new sandbox: run with --new --copy, "+
		"or delete proj-0a1b first (`defenseclaw sandbox delete proj-0a1b`))")
	// Flags the sandbox already matches ask nothing new.
	if got := resumeIgnores(RunOptions{Pack: "open", Profile: "open", LLM: LLMAuto}, &sandboxapi.Sandbox{Pack: "open", Profile: "open"}, nil); len(got) != 0 {
		t.Fatalf("resumeIgnores = %v", got)
	}
	ta = existing("y\n")
	ta.ok(t, ta.Run(bg, RunOptions{Harness: "claude", Prompt: "next step"}))
	if n := ta.creates(); n != 0 || !slices.ContainsFunc(ta.stream.runs, func(argv []string) bool {
		cmd := sandboxCommand(argv)
		return len(cmd) > 1 && cmd[0] == harness.ClaudeCodeLauncherPath && slices.Contains(cmd, "next step")
	}) {
		t.Fatalf("a headless run did not resume (creates %d): %q", n, ta.stream.commands())
	}
}

// Manual R2-110: the run's command typed again in the folder its kept
// sandbox holds is a resume with nothing ignored, so the default answer
// (Enter) resumes it; different values are still named.
func TestRunAgainResumesWithTheSameFlags(t *testing.T) {
	ta := newTestApp(t, "\n")
	ta.env["ANTHROPIC_API_KEY"] = "sk-mock"
	noChanges(ta)
	run := RunOptions{Harness: "claude", LLM: "none", Credentials: []string{"ANTHROPIC_API_KEY=host.openshell.internal:38121"},
		Env: []string{"ANTHROPIC_BASE_URL=http://host.openshell.internal:38121"}, Args: []string{"--model", "mock"}}
	ta.ok(t, ta.Run(bg, run))
	ta.ok(t, ta.fresh().Run(bg, run))
	has(t, ta.output(), "already holds this folder. Resume it? [Y/n]")
	lacks(t, ta.output(), "ignores")
	if creates, starts := ta.creates(), ta.calls("POST", sbName+"/start"); creates != 1 || starts != 1 {
		t.Fatalf("creates = %d, starts = %d; want the second run to resume", creates, starts)
	}
	rec := ta.runLaunchOf(ta.mustGet(t, sbName))
	if rec == nil {
		t.Fatal("the run was not remembered")
	}
	other := run
	other.Env, other.Credentials = []string{"ANTHROPIC_BASE_URL=http://elsewhere"}, []string{"ANTHROPIC_API_KEY=api.anthropic.com"}
	if got := resumeIgnores(other, ta.mustGet(t, sbName), rec); !slices.Equal(got, []string{"--credential", "--env"}) {
		t.Fatalf("resumeIgnores = %q", got)
	}
}

// Manual R2-101: a stopped sandbox the policy would not start is not
// offered for resume; status and connect say to delete it and run again.
func TestOutOfPolicySandboxIsNotOfferedForResume(t *testing.T) {
	ta := newTestApp(t, "s\n")
	ta.daemon.explain.Settings[0] = sandboxapi.Setting{Key: "workdir.mode", Value: "copy", Source: "admin", Origin: "openshell.admin.required_pack"}
	old := sampleSandbox("r2f-b")
	old.Phase, old.Project, old.CreatedAt = "stopped", ta.project, time.Now()
	ta.daemon.add(old)
	ta.ok(t, ta.Run(bg, RunOptions{Harness: "claude"}))
	has(t, ta.output(), "Sandbox r2f-b (stopped, mount) holds this folder but cannot start under the current policy (it mounts the folder live, "+
		"and your organization now runs it on a copy (openshell.admin.required_pack)); `defenseclaw sandbox delete r2f-b` removes it.")
	lacks(t, ta.output(), "Resume it")
	ta.ok(t, ta.fresh().Status(bg, "r2f-b", OutputText))
	has(t, ta.output(), "r2f-b cannot start under the current policy", "`defenseclaw sandbox delete r2f-b`")
	ta.daemon.errors["POST /api/v1/sandbox/sandboxes/r2f-b/start"] = &sandboxapi.Error{Code: sandboxapi.CodeAdminViolation, Message: sandboxapi.AdminMessage,
		Violation: &sandboxapi.Violation{Key: "workdir.mode", Admin: true, Fatal: true, Constraint: "openshell.admin.required_pack",
			Detail: "the required strict sandbox pack works on a copy of the project; host folders are not mounted"}}
	err := ta.Connect(bg, ConnectOptions{Name: "r2f-b"})
	if err == nil || !strings.HasSuffix(err.Error(), "; delete it (`defenseclaw sandbox delete r2f-b`) and run it again") {
		t.Fatalf("Connect = %v", err)
	}
}

// The run's harness options are the ones a later session passes again: a
// prompt is not, nor anything after one, nor a one-prompt run's arguments.
// A later session passes them first, then its own; the run's command typed
// again is not doubled.
func TestLaunchOptionsKeepOptionsNotPrompts(t *testing.T) {
	claude, codex := harnessSpec(t, "claudecode"), harnessSpec(t, "codex")
	for _, c := range []struct {
		name string
		spec *harness.Spec
		args []string
		want []string
	}{
		{"codex overrides", codex, []string{"-c", "openai_base_url=http://host.openshell.internal:38221/v1", "-m", "mock-model"},
			[]string{"-c", "openai_base_url=http://host.openshell.internal:38221/v1", "-m", "mock-model"}},
		{"a trailing prompt", claude, []string{"--model", "sonnet", "fix the failing tests"}, []string{"--model", "sonnet"}},
		{"a prompt after a switch", claude, []string{"--verbose", "fix the failing tests"}, []string{"--verbose"}},
		{"an option with its value", claude, []string{"--model=sonnet", "--verbose"}, []string{"--model=sonnet", "--verbose"}},
		{"a prompt first", claude, []string{"fix it", "--model", "sonnet"}, nil},
		{"a subcommand", codex, []string{"resume", "--last"}, nil},
		{"print mode", claude, []string{"-p", "fix it", "--model", "sonnet"}, nil},
		{"after --", claude, []string{"--model", "sonnet", "--", "-x"}, []string{"--model", "sonnet"}},
	} {
		if got := launchOptions(c.spec, c.args); !slices.Equal(got, c.want) {
			t.Errorf("%s: launchOptions(%q) = %q, want %q", c.name, c.args, got, c.want)
		}
	}
	stored := []string{"-m", "mock-model"}
	for _, c := range []struct{ stored, given, want []string }{
		{stored, nil, stored},
		{stored, []string{"resume", "01a0e644"}, []string{"-m", "mock-model", "resume", "01a0e644"}},
		{stored, []string{"-m", "mock-model", "resume", "01a0e644"}, []string{"-m", "mock-model", "resume", "01a0e644"}},
		{nil, []string{"--continue"}, []string{"--continue"}},
	} {
		if got := sessionArgs(c.stored, c.given); !slices.Equal(got, c.want) {
			t.Errorf("sessionArgs(%q, %q) = %q, want %q", c.stored, c.given, got, c.want)
		}
	}
}

// Manual R2-21 and R2-7: `connect` after a run gives the harness the run's
// options again (a Codex endpoint override), before the ones given now,
// and its banner has the run's Model and Secret lines.
func TestConnectPassesTheRunsOptionsAndBanner(t *testing.T) {
	ta := newTestApp(t, "")
	ta.env["OPENAI_API_KEY"] = "sk-mock"
	noChanges(ta)
	ta.ok(t, ta.Run(bg, RunOptions{Harness: "codex", Name: "r2b-y", LLM: "none", Credentials: []string{"OPENAI_API_KEY=host.openshell.internal:38221"},
		Args: []string{"-c", "openai_base_url=http://host.openshell.internal:38221/v1", "-m", "mock-model"}}))
	ta.out.Reset()
	ta.term.runs = nil
	ta.ok(t, ta.Connect(bg, ConnectOptions{Name: "r2b-y", Args: []string{"resume", "01a0e644"}}))
	if len(ta.term.runs) != 1 {
		t.Fatalf("terminal runs = %q", ta.term.runs)
	}
	has(t, strings.Join(ta.term.runs[0], " "), "-c openai_base_url=http://host.openshell.internal:38221/v1 -m mock-model resume 01a0e644")
	has(t, ta.output(), "Model     mock-model", "OPENAI_API_KEY comes from --credential", "Secret    OPENAI_API_KEY → host.openshell.internal:38221 only")
}

// The connect banner of a sandbox the CLI remembers nothing of keeps its
// Model line, named by the variable its credential came from, not the
// provider profile's id (manual R2-7, L10).
func TestConnectBannerNamesTheModelVariable(t *testing.T) {
	for _, c := range []struct {
		profile, region, want string
	}{
		{profiles.AnthropicID, "", "Model     ANTHROPIC_API_KEY → api.anthropic.com only (the sandbox sees a placeholder)"},
		{profiles.ClaudeBedrockMantleID, "us-east-1",
			"Model     anthropic.claude-sonnet-5 (the default; -- --model MODEL picks another) · AWS_BEARER_TOKEN_BEDROCK → "},
	} {
		ta := newTestApp(t, "")
		sb := sampleSandbox("box")
		sb.Launch.CredentialProfile, sb.Launch.BedrockRegion = c.profile, c.region
		ta.daemon.add(sb)
		ta.ok(t, ta.Connect(bg, ConnectOptions{Name: "box"}))
		has(t, ta.output(), c.want)
		lacks(t, ta.output(), strings.TrimPrefix(c.profile, "defenseclaw-")+" credential")
	}
}

// The record belongs to the sandbox that was created: a later sandbox of
// the same name does not inherit it, and it keeps no secret value.
func TestRunLaunchIsTiedToTheSandbox(t *testing.T) {
	ta := newTestApp(t, "")
	sb := sampleSandbox("box")
	ta.saveRunLaunch(&sb, newRunLaunch(&sb, harnessSpec(t, "claudecode"), RunOptions{Env: []string{"DB_URL=postgres://u:hunter2@db"},
		Credentials: []string{"K=api.x.com"}}, llmChoice{Note: "K comes from --credential"}))
	if got := ta.runLaunchOf(&sb); got == nil || !slices.Equal(got.EnvNames, []string{"DB_URL"}) || got.ModelNote != "K comes from --credential" {
		t.Fatalf("record = %+v", got)
	}
	dir, _ := ta.cliStateDir("box")
	if data, err := os.ReadFile(filepath.Join(dir, runLaunchFile)); err != nil || strings.Contains(string(data), "hunter2") {
		t.Fatalf("record on disk = %s, %v", data, err)
	}
	other := sb
	other.ID = "sb-another"
	if ta.runLaunchOf(&other) != nil {
		t.Fatal("a later sandbox of the name inherited the record")
	}
}

// Manual R2-43: a copy-mode session that found nothing to bring back lets
// `delete` of the stopped sandbox go without the "may hold work" warning,
// until the sandbox runs again.
func TestDeleteKnowsTheSessionChangedNothing(t *testing.T) {
	ta := newTestApp(t, "y\n")
	ta.env["ANTHROPIC_API_KEY"] = "sk-mock"
	ta.copy.pull = &workspace.PullResult{Name: "copybox"}
	ta.copy.pendingStopped = map[string]workspace.CopyWork{"copybox": workspace.CopyWorkUnknown}
	ta.ok(t, ta.Run(bg, RunOptions{Harness: "claude", Copy: true, Name: "copybox"}))
	has(t, ta.output(), "the sandbox changed nothing")
	ta.ok(t, ta.fresh().Delete(bg, DeleteOptions{Names: []string{"copybox"}}))
	has(t, ta.output(), "Delete sandbox copybox (its providers, credentials and, unless --keep-snapshot, its undo point)?")
	lacks(t, ta.output(), "may hold work")
	// Once it ran again, it is not known to be clean.
	ta = newTestApp(t, "n\n")
	sb := copySandbox("copybox")
	ta.daemon.add(sb)
	ta.copy.pendingStopped = map[string]workspace.CopyWork{"copybox": workspace.CopyWorkUnknown}
	ta.markCleanCopy(&sb)
	sb.StartedAt = ta.Now().Add(time.Minute)
	ta.daemon.add(sb)
	ta.ok(t, ta.Delete(bg, DeleteOptions{Names: []string{"copybox"}}))
	has(t, ta.output(), "may hold work that was never pulled back")
}

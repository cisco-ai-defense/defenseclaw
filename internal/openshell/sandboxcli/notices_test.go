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
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/openshell/harness"
	"github.com/defenseclaw/defenseclaw/internal/openshell/sandboxapi"
	"github.com/defenseclaw/defenseclaw/internal/openshell/workspace"
)

const sbName = "dc-claude-proj-1a2b"

// noChanges makes the fake review report an unchanged folder.
func noChanges(ta *testApp) {
	ta.daemon.review = sandboxapi.ReviewResponse{Report: &workspace.ReviewReport{}}
}

// Manual R2-51 and R2-98: an ask is announced in the terminal's title and
// a desktop notification, not written over the harness's screen; it names
// the destination and the binary, why it is an ask and the TUI's Asks view,
// and the summary repeats it.
func TestAskNoticeNamesTheDestinationOffScreen(t *testing.T) {
	ta := newTestApp(t, "")
	stderr := liveErr(ta)
	noChanges(ta)
	ta.daemon.approvals = []sandboxapi.Approval{{ID: "ap-1", Sandbox: sbName, Host: "www.example.com", Port: 443, Binary: "/usr/bin/curl"}}
	ta.daemon.live = []sandboxapi.ActivityEvent{{Seq: 5, Kind: sandboxapi.ActivityApprovalRequested, Sandbox: sbName, ApprovalID: "ap-1",
		Host: "www.example.com", Port: 443, Message: "approvals are manual for the strict profile"}}
	want := "? ask ap-1: www.example.com:443 (curl) is waiting for you (approvals are manual for the strict profile) → in another terminal: " +
		"defenseclaw sandbox approve " + sbName + " ap-1 (or reject), or in `defenseclaw tui`: 7 Sandboxes, then t for Asks"
	ta.term.during = func() {
		waitFor(t, "the ask notice", func() bool { return strings.Contains(stderr.String(), "\x1b]9;DefenseClaw: "+want+"\a") })
	}
	if err := ta.Run(context.Background(), RunOptions{Harness: "claude"}); err != nil {
		t.Fatalf("Run: %v\n%s", err, ta.output())
	}
	live := stderr.String()
	if !strings.Contains(live, "\x1b[22;0t\x1b]2;[defenseclaw] ? ask ap-1: www.example.com:443 (curl)") || strings.Contains(live, "\r\n[defenseclaw]") ||
		!strings.HasSuffix(live, "\x1b[23;0t") || !strings.Contains(live, "\a\a") {
		t.Fatalf("live output = %q", live)
	}
	if out := ta.output(); !strings.Contains(out, "? asked to reach www.example.com:443 (curl)") {
		t.Fatalf("summary does not repeat the ask:\n%s", out)
	}
}

// The feed line of an ask shows the destination with the daemon's reason.
func TestFeedAskShowsTheDestination(t *testing.T) {
	ta := newTestApp(t, "")
	ev := sandboxapi.ActivityEvent{Time: time.Date(2026, 9, 27, 12, 1, 2, 0, time.Local), Kind: sandboxapi.ActivityApprovalRequested, Sandbox: "r2f-c",
		ApprovalID: "ap_6d04", Host: "www.example.com", Port: 443, Message: "approvals are manual for the strict profile"}
	want := "12:01:02 r2f-c ? ask ap_6d04: www.example.com:443 (approvals are manual for the strict profile)  → defenseclaw sandbox approve r2f-c ap_6d04"
	if got := ta.activityLine(ev, true); got != want {
		t.Fatalf("feed line = %q\nwant        %q", got, want)
	}
}

// A headless session has no screen to protect: its notices are lines.
func TestHeadlessNoticesAreLines(t *testing.T) {
	ta := newTestApp(t, "")
	stderr := liveErr(ta)
	s := &session{app: ta.App, headless: true, sb: &sandboxapi.Sandbox{Name: "box"}}
	s.notice("", "✓ the DefenseClaw daemon is reachable again", "")
	if got := stderr.String(); got != "\r\n[defenseclaw] ✓ the DefenseClaw daemon is reachable again\r\n" {
		t.Fatalf("notice = %q", got)
	}
	s.restoreTitle()
	if strings.Contains(stderr.String(), "\x1b[") {
		t.Fatal("a headless session touched the title")
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
	if err := ta.Run(context.Background(), RunOptions{Harness: "claude"}); err != nil {
		t.Fatalf("Run: %v\n%s", err, ta.output())
	}
	live := stderr.String()
	if strings.Count(live, "\x1b]9;DefenseClaw: "+block+"\a") != 1 || strings.Contains(live, "raw.githubusercontent.com") || strings.Contains(live, "nothing to see") {
		t.Fatalf("live output = %q", live)
	}
	out := ta.output()
	for _, want := range []string{block, "⚠ webhook.site: alert on Bash: known exfil destination (C2-WEBHOOK-SITE)",
		"⚠ hook tamper: Bash ran without a DefenseClaw verdict"} {
		if !strings.Contains(out, want) {
			t.Errorf("summary lacks %q:\n%s", want, out)
		}
	}
	if strings.Index(out, "Session ended") > strings.Index(out, block) {
		t.Errorf("the notices come before the summary line:\n%s", out)
	}
}

// Manual R2-2: while the daemon does not answer, the run says so (the hooks
// fail closed meanwhile), then that it is back, and the summary keeps the
// outage.
func TestDaemonOutageIsAnnouncedLive(t *testing.T) {
	old := reconnectDelay
	reconnectDelay = 5 * time.Millisecond
	t.Cleanup(func() { reconnectDelay = old })
	ta := newTestApp(t, "")
	stderr := liveErr(ta)
	noChanges(ta)
	ta.term.during = func() {
		ta.daemon.mu.Lock()
		ta.daemon.errors["GET "+sandboxapi.PathStatus] = &sandboxapi.Error{Code: sandboxapi.CodeUnavailable, Message: "stopped"}
		ta.daemon.mu.Unlock()
		waitFor(t, "the outage notice", func() bool {
			return strings.Contains(stderr.String(), "⚠ the DefenseClaw daemon is not reachable, so the hooks fail closed: Claude Code can't use its tools until it is back")
		})
		ta.daemon.mu.Lock()
		delete(ta.daemon.errors, "GET "+sandboxapi.PathStatus)
		ta.daemon.mu.Unlock()
		waitFor(t, "the return notice", func() bool { return strings.Contains(stderr.String(), "✓ the DefenseClaw daemon is reachable again") })
	}
	if err := ta.Run(context.Background(), RunOptions{Harness: "claude"}); err != nil {
		t.Fatalf("Run: %v\n%s", err, ta.output())
	}
	if out := ta.output(); !strings.Contains(out, "⚠ the DefenseClaw daemon was not reachable from ") || !strings.Contains(out, "the hooks failed closed meanwhile") {
		t.Fatalf("summary lacks the outage:\n%s", out)
	}
}

// Manual R2-2: a daemon restart during the session resets its hook
// counters. Hooks that reached the new daemon count, the summary counts
// from zero, and there is no false alarm or exit 69.
func TestHooksAfterADaemonRestartStillCount(t *testing.T) {
	ta := newTestApp(t, "")
	noChanges(ta)
	ta.term.hooks = nil
	sb := sampleSandbox("box")
	sb.Hooks = sandboxapi.HookCoverage{HookRequests: 107, ToolCalls: 13, LastHookAt: time.Now().Add(-time.Hour)}
	sb.Egress = sandboxapi.EgressStats{Destinations: 20, Blocked: 3}
	ta.daemon.add(sb)
	ta.term.during = func() {
		ta.daemon.mu.Lock()
		ta.daemon.sandboxes["box"].Hooks = sandboxapi.HookCoverage{HookRequests: 15, ToolCalls: 1, LastHookAt: time.Now()}
		ta.daemon.sandboxes["box"].Egress = sandboxapi.EgressStats{Destinations: 2}
		ta.daemon.mu.Unlock()
	}
	if err := ta.Connect(context.Background(), ConnectOptions{Name: "box"}); err != nil {
		t.Fatalf("Connect = %v\n%s", err, ta.output())
	}
	out := ta.output()
	if strings.Contains(out, "hooks are not reaching") || !strings.Contains(out, "Session ended · 1 tool call · 2 new sites contacted") {
		t.Fatalf("summary:\n%s", out)
	}
}

// Manual R2-66: a harness that fires its first hook only with the first
// prompt (Kiro) gets no timed warning while it idles, and a session nobody
// prompted is not reported as failing closed.
func TestPromptFirstHarnessIsNotOverdueWhileIdle(t *testing.T) {
	ta := newTestApp(t, "")
	stderr := liveErr(ta)
	noChanges(ta)
	ta.HookWindow = time.Millisecond
	ta.term.hooks = nil
	ta.term.during = func() { time.Sleep(30 * time.Millisecond) }
	if err := ta.Run(context.Background(), RunOptions{Harness: "kiro", Name: "r2c1-kiro"}); err != nil {
		t.Fatalf("Run = %v\n%s", err, ta.output())
	}
	if live := stderr.String(); strings.Contains(live, "hooks are not reaching") {
		t.Fatalf("live warning on an idle Kiro session: %q", live)
	}
	out := ta.output()
	if strings.Contains(out, "hooks are not reaching") || !strings.Contains(out, "no hook of this session reached DefenseClaw: Kiro CLI sends its first one with your first prompt") {
		t.Fatalf("summary:\n%s", out)
	}
	// The daemon's verdict (the harness worked without hooks) still counts.
	ta = newTestApp(t, "")
	noChanges(ta)
	ta.term.hooks = nil
	ta.term.during = func() {
		ta.daemon.mu.Lock()
		ta.daemon.sandboxes["r2c1-kiro"].Hooks.Unreachable = true
		ta.daemon.mu.Unlock()
	}
	wantExit(t, ta.Run(context.Background(), RunOptions{Harness: "kiro", Name: "r2c1-kiro"}), ExitHooksUnreachable)
}

// Manual R2-66: a harness that exited with an error before any of its
// hooks fired failed; the hooks are not blamed.
func TestHarnessThatFailedBeforeItsHooksIsNamed(t *testing.T) {
	ta := newTestApp(t, "")
	noChanges(ta)
	ta.term.hooks = nil
	ta.term.code = 1
	wantExit(t, ta.Run(context.Background(), RunOptions{Harness: "claude"}), 1)
	out := ta.output()
	if strings.Contains(out, "hooks are not reaching") ||
		!strings.Contains(out, "✗ Claude Code exited with status 1 before any of its hooks reached DefenseClaw: the harness itself failed (its output is above)") {
		t.Fatalf("summary:\n%s", out)
	}
}

// A session that ended because the sandbox was stopped or undone from
// elsewhere says so plainly.
func TestSessionEndedFromElsewhereSaysSo(t *testing.T) {
	for _, c := range []struct {
		name, want string
		undone     bool
	}{
		{"stopped", sbName + " was stopped from outside this session (`defenseclaw sandbox stop` or the TUI), which ended Claude Code", false},
		{"undone", sbName + " was undone from outside this session (`defenseclaw sandbox undo` or the TUI): the folder is back at its undo point, " +
			"and that stopped Claude Code", true},
	} {
		t.Run(c.name, func(t *testing.T) {
			ta := newTestApp(t, "")
			noChanges(ta)
			ta.term.code = 255
			ta.term.during = func() {
				ta.daemon.mu.Lock()
				sb := ta.daemon.sandboxes[sbName]
				sb.Phase = "stopped"
				if c.undone {
					sb.Snapshot = &sandboxapi.SnapshotInfo{Kind: "git", UndoneAt: ta.Now().Add(time.Minute)}
				}
				ta.daemon.mu.Unlock()
			}
			wantExit(t, ta.Run(context.Background(), RunOptions{Harness: "claude"}), 255)
			out := ta.output()
			if !strings.Contains(out, c.want) || strings.Contains(out, "the harness itself failed") || !strings.Contains(out, "Sandbox kept (stopped)") {
				t.Fatalf("output:\n%s", out)
			}
			if n := len(ta.daemon.callsTo("POST", sbPath+"/stop")); n != 0 {
				t.Fatalf("stop calls = %d; it was stopped already", n)
			}
		})
	}
}

// blockPipe is a terminal input nobody types into: a prompt waits.
func blockPipe(t *testing.T, ta *testApp) {
	pr, pw := io.Pipe()
	t.Cleanup(func() { _ = pw.Close() })
	ta.IO.In = pr
}

// Manual R2-11: Ctrl-C at the keep/undo question does not end the process
// silently: it says the changes stay and undo still reverts them, stops
// and keeps the sandbox, and exits 130.
func TestKeepQuestionCtrlCSaysWhatIsLeft(t *testing.T) {
	ta := newTestApp(t, "")
	blockPipe(t, ta)
	sig := make(chan os.Signal, 1)
	ta.App.interrupts = func() (<-chan os.Signal, func()) {
		sig <- os.Interrupt
		return sig, func() {}
	}
	wantExit(t, ta.Run(context.Background(), RunOptions{Harness: "claude"}), exitInterrupted)
	out := ta.output()
	for _, want := range []string{"Keep changes? [Y] keep  [u] undo everything  [d] show diff (then Enter)",
		"⚠ interrupted: nothing was decided, so the changes stay in the folder and the undo point is kept (`defenseclaw sandbox undo " + sbName + "` still reverts them",
		"Sandbox kept (stopped)"} {
		if !strings.Contains(out, want) {
			t.Errorf("output lacks %q:\n%s", want, out)
		}
	}
	if n := len(ta.daemon.callsTo("POST", sbPath+"/undo")); n != 0 {
		t.Fatalf("undo calls = %d", n)
	}
	if n := len(ta.daemon.callsTo("POST", sbPath+"/stop")); n != 1 {
		t.Fatalf("stop calls = %d", n)
	}
}

// Keeping is confirmed, and a long diff goes through the pager.
func TestKeepIsConfirmedAndTheDiffIsPaged(t *testing.T) {
	ta := newTestApp(t, "d\ny\n")
	var paged string
	ta.App.pager = func(text string) bool {
		paged = text
		return true
	}
	if err := ta.Run(context.Background(), RunOptions{Harness: "claude"}); err != nil {
		t.Fatalf("Run: %v\n%s", err, ta.output())
	}
	out := ta.output()
	if !strings.Contains(paged, "+changed") || strings.Contains(out, "+changed") ||
		!strings.Contains(out, "✓ kept: the changes stay in the folder, and the next session takes a new undo point") {
		t.Fatalf("paged %q, output:\n%s", paged, out)
	}
	// Without a pager the diff is printed.
	ta = newTestApp(t, "d\ny\n")
	if err := ta.Run(context.Background(), RunOptions{Harness: "claude"}); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(ta.output(), "+changed") {
		t.Fatalf("output:\n%s", ta.output())
	}
}

// Manual R2-6: the end of a session names the command that continues the
// conversation inside the sandbox, and says what the harness's own resume
// hint does on this machine.
func TestSessionEndNamesTheInSandboxContinue(t *testing.T) {
	for _, c := range []struct {
		name, harness string
		wrapped       bool
		want          string
	}{
		{"claude", "claude", false, "continue this conversation: defenseclaw sandbox connect " + sbName +
			" -- --continue (the `claude --resume …` Claude Code printed would run it on this machine, outside the sandbox)"},
		{"claude with the wrapper", "claude", true, "continue this conversation: defenseclaw sandbox connect " + sbName +
			" -- --continue (the `claude --resume …` Claude Code printed resumes it in this sandbox too: the shell wrapper is on)"},
		{"codex", "codex", false, "-- resume --last (the `codex resume …` Codex printed would run it on this machine, outside the sandbox)"},
	} {
		t.Run(c.name, func(t *testing.T) {
			ta := newTestApp(t, "")
			noChanges(ta)
			ta.env["OPENAI_API_KEY"] = "sk-mock"
			if c.wrapped {
				ta.Cfg.OpenShell.Wrappers = []string{"claudecode"}
			}
			if err := ta.Run(context.Background(), RunOptions{Harness: c.harness}); err != nil {
				t.Fatalf("Run: %v\n%s", err, ta.output())
			}
			if out := ta.output(); !strings.Contains(out, c.want) {
				t.Fatalf("output lacks %q:\n%s", c.want, out)
			}
		})
	}
	ta := newTestApp(t, "")
	ta.IO.TTY = false
	noChanges(ta)
	if err := ta.Run(context.Background(), RunOptions{Harness: "claude", Prompt: "fix it"}); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(ta.output(), "continue this conversation") {
		t.Fatalf("a one-prompt run got the continue hint:\n%s", ta.output())
	}
}

// Manual R2-5: hook tamper shows in status and in the list's HOOKS column.
func TestTamperShowsInStatusAndList(t *testing.T) {
	ta := newTestApp(t, "")
	sb := sampleSandbox("r2a-bed")
	sb.Hooks.Tampered, sb.Hooks.LastTamperAt = 1, time.Date(2026, 9, 28, 4, 57, 1, 0, time.Local)
	ta.daemon.add(sb)
	if err := ta.List(context.Background(), OutputText); err != nil {
		t.Fatal(err)
	}
	if out := ta.output(); !strings.Contains(out, "tamper!") {
		t.Fatalf("list:\n%s", out)
	}
	ta.out.Reset()
	if err := ta.Status(context.Background(), "r2a-bed", OutputText); err != nil {
		t.Fatal(err)
	}
	if out := ta.output(); !strings.Contains(out, "Tamper        1 tool call ran without a DefenseClaw verdict, last 04:57:01") {
		t.Fatalf("status:\n%s", out)
	}
}

// Manual R2-13: a start that keeps the undo point names --new-snapshot.
func TestStartNoticeNamesNewSnapshot(t *testing.T) {
	ta := newTestApp(t, "")
	ta.daemon.pendingChanges = true
	sb := sampleSandbox("r2a-safe")
	sb.Phase = "stopped"
	sb.Snapshot = &sandboxapi.SnapshotInfo{Kind: "git", CreatedAt: ta.Now().Add(-time.Hour)}
	ta.daemon.add(sb)
	if err := ta.Start(context.Background(), "r2a-safe", StartOptions{}); err != nil {
		t.Fatal(err)
	}
	if out := ta.output(); !strings.Contains(out, "`defenseclaw sandbox start r2a-safe --new-snapshot`") {
		t.Fatalf("start:\n%s", out)
	}
}

// Manual R2-17: the summary names a blocked call's rule by its title and
// ID, not the cut-off start of the reason.
func TestBlockedReasonNamesTheRule(t *testing.T) {
	for _, c := range []struct{ in, want string }{
		{"Blocked by DefenseClaw rule E2E-SANDBOX-MARKER: E2E sandbox marker command. Try another approach that does not need this action, or ask the user to review the DefenseClaw policy.",
			"E2E sandbox marker command (E2E-SANDBOX-MARKER)"},
		{"Blocked by DefenseClaw rule CMD-1: Destructive command (also CMD-2). Do not.", "Destructive command (CMD-1)"},
		{"Blocked by DefenseClaw rule CMD-1. Do not.", "CMD-1"},
		{"Blocked by DefenseClaw policy. Try another approach.", "DefenseClaw policy"},
		{"marker", "marker"},
	} {
		if got := blockedReason(c.in); got != c.want {
			t.Errorf("blockedReason(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}

// Manual R2-78: `connect --shell` opens the shell in the project folder and
// ends with the summary and review of any other session.
func TestConnectShellStartsInTheProjectAndSummarises(t *testing.T) {
	ta := newTestApp(t, "y\n")
	ta.term.hooks = nil
	sb := sampleSandbox("r2c1-cp")
	sb.Phase, sb.Snapshot = "stopped", &sandboxapi.SnapshotInfo{Kind: "git"}
	ta.daemon.add(sb)
	if err := ta.Connect(context.Background(), ConnectOptions{Name: "r2c1-cp", Shell: true}); err != nil {
		t.Fatalf("Connect: %v\n%s", err, ta.output())
	}
	if len(ta.term.runs) != 1 {
		t.Fatalf("terminal runs = %q", ta.term.runs)
	}
	argv := strings.Join(ta.term.runs[0], " ")
	if !strings.Contains(argv, "--workdir /work/proj") || !strings.Contains(argv, "exec bash -l") {
		t.Fatalf("shell argv = %s", argv)
	}
	out := ta.output()
	if !strings.Contains(out, "Sandbox r2c1-cp · Claude Code") || !strings.Contains(out, "Session ended ·") || !strings.Contains(out, "Keep changes?") ||
		strings.Contains(out, "hooks are not reaching") || strings.Contains(out, "continue this conversation") {
		t.Fatalf("output:\n%s", out)
	}
}

// Manual R2-28: the worktree fallback is one sentence, with the daemon's
// reason unwrapped and without advice the run already follows.
func TestNeedsCopyTextIsOneSentence(t *testing.T) {
	ta := newTestApp(t, "")
	project := ta.home + "/proj/r2b-wt"
	e := &sandboxapi.Error{Code: sandboxapi.CodeNeedsCopy, Message: "this project cannot be mounted live; run it with --copy",
		Detail: "workspace: " + project + " cannot be mounted live: its git directory lives at " + ta.home +
			"/proj/r2b-proj/.git/worktrees/r2b-wt, outside the folder (a git worktree or submodule checkout); run with --copy to work on a copy"}
	want := "~/proj/r2b-wt can't be mounted live (its git directory lives at ~/proj/r2b-proj/.git/worktrees/r2b-wt, outside the folder " +
		"(a git worktree or submodule checkout)), so it runs on a copy: `defenseclaw sandbox pull r2b-w` brings the changes back"
	if got := ta.needsCopyText(project, e, "r2b-w"); got != want {
		t.Fatalf("needsCopyText =\n%s\nwant\n%s", got, want)
	}
}

// Manual R2-89 and the OmniGent banner.
func TestBannerWording(t *testing.T) {
	for name, want := range map[string]string{"OpenHands": "an OpenHands", "Antigravity": "an Antigravity", "OmniGent": "an OmniGent", "Codex": "a Codex"} {
		if got := withArticle(name); got != want {
			t.Errorf("withArticle(%s) = %q", name, got)
		}
	}
	ta := newTestApp(t, "")
	sb := sampleSandbox("og")
	sb.Harness, sb.HarnessName = "omnigent", "OmniGent"
	ta.banner(&sb, bannerInfo{})
	if out := ta.output(); !strings.Contains(out, "OmniGent · approvals from OmniGent's policies, DefenseClaw's included") || strings.Contains(out, "skip-permissions") {
		t.Fatalf("banner:\n%s", out)
	}
}

// Manual R2-42: the setup-token hint only where Claude Code is installed,
// with the wrapper bypass when the wrapper is on.
func TestSetupTokenHintFollowsTheHost(t *testing.T) {
	claude, _ := harness.Get("claudecode")
	ta := newTestApp(t, "")
	ta.LookPath = func(string) (string, error) { return "", errors.New("not found") }
	got, err := ta.detectLLM(claude, "", "", nil)
	if err != nil || strings.Contains(got.Note, "setup-token") || !strings.Contains(got.Note, "set ANTHROPIC_API_KEY, or use /login in the sandbox") {
		t.Fatalf("without claude: %+v, %v", got, err)
	}
	ta = newTestApp(t, "")
	ta.Cfg.OpenShell.Wrappers = []string{"claudecode"}
	if got, _ := ta.detectLLM(claude, "", "", nil); !strings.Contains(got.Note, "CLAUDE_CODE_OAUTH_TOKEN from `DEFENSECLAW_NO_SANDBOX=1 claude setup-token`") {
		t.Fatalf("with the wrapper: %q", got.Note)
	}
}

// Manual R2-87: a --credential binding of Hermes's managed-provider key is
// the run's model credential.
func TestHermesProviderKeyIsTheModelCredential(t *testing.T) {
	hermes, _ := harness.Get("hermes")
	ta := newTestApp(t, "")
	got, err := ta.detectLLM(hermes, "", "", map[string]bool{"HERMES_DEFENSECLAW_API_KEY": true})
	if err != nil || got.Note != "HERMES_DEFENSECLAW_API_KEY comes from --credential" {
		t.Fatalf("detectLLM = %+v, %v", got, err)
	}
}

// Manual R2-102: an organization's limit on --cpu reads as a limit and is
// confirmed like any other overridden flag; declining creates nothing.
func TestCPUClampIsSaidAndConfirmed(t *testing.T) {
	limit := sandboxapi.Setting{Key: "resources.cpu", Value: "1", Source: "admin", Origin: "openshell.admin.max_resources", Requested: "(unlimited)"}
	want := "⚠ limited by your organization's DefenseClaw policy: resources.cpu — your organization caps sandbox cpu at 1 " +
		"(openshell.admin.max_resources); running with resources.cpu 1 instead of 4"
	ta := newTestApp(t, "n\n")
	ta.daemon.explain.Settings = append(ta.daemon.explain.Settings, limit)
	var silent *Silent
	if err := ta.Run(context.Background(), RunOptions{Harness: "claude", CPU: "4"}); !errors.As(err, &silent) {
		t.Fatalf("Run = %v", err)
	}
	out := ta.output()
	if !strings.Contains(out, want) || !strings.Contains(out, "overrides a flag you passed. Run with its setting? [Y/n]") ||
		!strings.Contains(out, "cancelled; no sandbox was created") || len(ta.daemon.callsTo("POST", sandboxapi.PathSandboxes)) != 0 {
		t.Fatalf("output:\n%s", out)
	}
	// Accepted, the banner does not repeat the daemon's own clamp.
	ta = newTestApp(t, "y\ny\n")
	ta.daemon.explain.Settings = append(ta.daemon.explain.Settings, limit)
	ta.daemon.createViolations = []sandboxapi.Violation{{Key: "resources.cpu", Source: "flag", Attempted: "4", Enforced: "1", Admin: true,
		Constraint: "openshell.admin.max_resources", Message: sandboxapi.AdminMessage + ": resources.cpu", Detail: "your organization caps sandbox cpu at 1"}}
	if err := ta.Run(context.Background(), RunOptions{Harness: "claude", CPU: "4"}); err != nil {
		t.Fatalf("Run: %v\n%s", err, ta.output())
	}
	if n := strings.Count(ta.output(), "running with resources.cpu 1 instead of 4"); n != 1 {
		t.Fatalf("the clamp is said %d times:\n%s", n, ta.output())
	}
	// Within the limit, nothing is said.
	if got := resourceClamps(RunOptions{CPU: "500m"}, &sandboxapi.Explain{Settings: []sandboxapi.Setting{limit}}); len(got) != 0 {
		t.Fatalf("resourceClamps = %+v", got)
	}
}

// Manual R2-102: a dropped skip-permissions flag names the organization
// when it is the organization's doing.
func TestFilterBypassNamesTheOrganization(t *testing.T) {
	ta := newTestApp(t, "")
	off := false
	ta.Cfg.OpenShell.Admin.AllowYolo = &off
	claude, _ := harness.Get("claudecode")
	sb := sampleSandbox("box")
	sb.Launch.Yolo = false
	ta.filterBypass(claude, &sb, []string{"--dangerously-skip-permissions"})
	if out := ta.output(); !strings.Contains(out, "--dangerously-skip-permissions is ignored: this sandbox keeps Claude Code's permission prompts "+
		"(your organization disables skip-permissions)") {
		t.Fatalf("output:\n%s", out)
	}
}

// Manual R2-103: a run the organization puts on a copy says why.
func TestRequireCopyForIsSaid(t *testing.T) {
	ta := newTestApp(t, "s\n")
	ta.daemon.explain.Settings[0] = sandboxapi.Setting{Key: "workdir.mode", Value: "copy", Source: "admin", Origin: "openshell.admin.require_copy_for",
		Requested: "mount"}
	if err := ta.Run(context.Background(), RunOptions{Harness: "claude", Name: "r2f-acme"}); err != nil {
		t.Fatalf("Run: %v\n%s", err, ta.output())
	}
	out := ta.output()
	want := "copy mode: your organization requires copy mode for this folder (openshell.admin.require_copy_for); the agent works on a copy"
	if !strings.Contains(out, want) || strings.Index(out, want) > strings.Index(out, "Copying") {
		t.Fatalf("output:\n%s", out)
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
	if err := ta.Run(context.Background(), RunOptions{Harness: "claude"}); err != nil {
		t.Fatalf("Run: %v\n%s", err, ta.output())
	}
	out := ta.output()
	if strings.Contains(out, "Resume it") || !strings.Contains(out, "Sandbox r2f-b (stopped, mount) holds this folder but cannot start under the current policy "+
		"(it mounts the folder live, and your organization now runs it on a copy (openshell.admin.required_pack)); `defenseclaw sandbox delete r2f-b` removes it.") {
		t.Fatalf("output:\n%s", out)
	}
	ta.out.Reset()
	if err := ta.Status(context.Background(), "r2f-b", OutputText); err != nil {
		t.Fatal(err)
	}
	if out := ta.output(); !strings.Contains(out, "r2f-b cannot start under the current policy") || !strings.Contains(out, "`defenseclaw sandbox delete r2f-b`") {
		t.Fatalf("status:\n%s", out)
	}
	ta.daemon.errors["POST /api/v1/sandbox/sandboxes/r2f-b/start"] = &sandboxapi.Error{Code: sandboxapi.CodeAdminViolation, Message: sandboxapi.AdminMessage,
		Violation: &sandboxapi.Violation{Key: "workdir.mode", Admin: true, Fatal: true, Constraint: "openshell.admin.required_pack",
			Detail: "the required strict sandbox pack works on a copy of the project; host folders are not mounted"}}
	err := ta.Connect(context.Background(), ConnectOptions{Name: "r2f-b"})
	if err == nil || !strings.HasSuffix(err.Error(), "; delete it (`defenseclaw sandbox delete r2f-b`) and run it again") {
		t.Fatalf("Connect = %v", err)
	}
}

// Manual R2-106: a workspace failure on a full disk says so.
func TestDiskFullIsNamed(t *testing.T) {
	ta := newTestApp(t, "")
	for _, err := range []error{fmt.Errorf("write: %w", syscall.ENOSPC), errors.New("git: fatal: sha1 file write error: No space left on device")} {
		if hint := ta.diskFullHint(err); !strings.Contains(hint, "is full (no space left on device") {
			t.Errorf("diskFullHint(%v) = %q", err, hint)
		}
	}
	if hint := ta.diskFullHint(errors.New("connection reset")); hint != "" {
		t.Errorf("an unrelated failure got %q", hint)
	}
}

// Manual R2-76: an --env name that says it holds a secret is warned about.
func TestSecretLookingEnvIsWarned(t *testing.T) {
	for name, want := range map[string]bool{"KIRO_API_KEY": true, "GITHUB_TOKEN": true, "DB_PASSWORD": true, "OPENAI_KEY": true,
		"ANTHROPIC_BASE_URL": false, "KIRO_MOCK_CHAT_RESPONSE": false, "TOKENIZERS_PARALLELISM": false, "KEYBOARD": false} {
		if got := secretLooking(name); got != want {
			t.Errorf("secretLooking(%s) = %v", name, got)
		}
	}
	ta := newTestApp(t, "")
	ta.warnSecretEnv(map[string]string{"KIRO_API_KEY": "dclive-x", "ANTHROPIC_BASE_URL": "http://h"})
	out := ta.output()
	if strings.Count(out, "looks like a secret") != 1 || !strings.Contains(out, "`--credential KIRO_API_KEY=HOST` gives it a placeholder that works only at HOST") ||
		strings.Contains(out, "dclive-x") {
		t.Fatalf("output:\n%s", out)
	}
}

// Manual R2-30 and R2-104: status wording.
func TestStatusWording(t *testing.T) {
	ta := newTestApp(t, "")
	sb := sampleSandbox("r2b-s")
	sb.Hooks.HookRequests, sb.Hooks.ToolCalls, sb.Hooks.ToolBlocked = 5, 1, 0
	ta.daemon.add(sb)
	if err := ta.Status(context.Background(), "r2b-s", OutputText); err != nil {
		t.Fatal(err)
	}
	if out := ta.output(); !strings.Contains(out, "Hook traffic  5 requests, 1 tool call, 0 blocked") {
		t.Fatalf("status:\n%s", out)
	}
	ta.out.Reset()
	ta.daemon.status.Admin = sandboxapi.AdminStatus{Configured: true, Authority: "advisory",
		Detail: "openshell.admin is enforced but advisory: you own config.yaml and can edit it"}
	if err := ta.Status(context.Background(), "", OutputText); err != nil {
		t.Fatal(err)
	}
	if out := ta.output(); !strings.Contains(out, "Organization    openshell.admin is enforced but advisory: you own config.yaml and can edit it") {
		t.Fatalf("status:\n%s", out)
	}
}

// Manual R2-104: `policy explain` says "asked for" only for what the user
// asked for.
func TestExplainSaysAskedForOnlyWhenAsked(t *testing.T) {
	ta := newTestApp(t, "")
	ta.daemon.explain.Settings = append(ta.daemon.explain.Settings,
		sandboxapi.Setting{Key: "resources.cpu", Value: "1", Source: "admin", Origin: "openshell.admin.max_resources", Requested: "(unlimited)"},
		sandboxapi.Setting{Key: "profile", Value: "strict", Source: "admin", Origin: "openshell.admin.required_pack", Requested: "open"})
	ta.daemon.explain.Violations = []sandboxapi.Violation{{Key: "profile", Source: "flag", Attempted: "open", Enforced: "strict", Admin: true,
		Constraint: "openshell.admin.required_pack"}}
	if err := ta.PolicyExplain(context.Background(), PolicyOptions{Harness: "claude", Profile: "open"}); err != nil {
		t.Fatal(err)
	}
	out := ta.output()
	if !strings.Contains(out, "1 (instead of unlimited)") || !strings.Contains(out, "strict (asked for open)") || strings.Contains(out, "asked for (unlimited)") {
		t.Fatalf("explain:\n%s", out)
	}
}

// Manual R2-104: a --host-port the organization's required pack refuses
// says the organization requires the pack.
func TestHostPortRefusalNamesTheRequiredPack(t *testing.T) {
	ta := newTestApp(t, "")
	ta.Cfg.OpenShell.Admin.RequiredPack = "strict"
	ta.daemon.explain.Settings = append(ta.daemon.explain.Settings, sandboxapi.Setting{Key: "pack", Value: "strict", Source: "admin",
		Origin: "openshell.admin.required_pack"})
	err := ta.Run(context.Background(), RunOptions{Harness: "claude", HostPorts: []int{38790}})
	if err == nil || !strings.Contains(err.Error(), "--host-port 38790: not allowed by the strict sandbox pack your organization requires (openshell.admin.required_pack)") {
		t.Fatalf("Run = %v", err)
	}
}

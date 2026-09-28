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
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/openshell/harness"
	"github.com/defenseclaw/defenseclaw/internal/openshell/sandboxapi"
	"github.com/defenseclaw/defenseclaw/internal/openshell/workspace"
)

// runAnswers makes the fake sandbox report its latest detached run as state
// (the run-state script's key=value answer), log as the run's log, and
// answers everything else with success.
func runAnswers(ta *testApp, state, log string) {
	ta.stream.answer = func(argv []string) (int, string) {
		cmd := sandboxCommand(argv)
		switch {
		case len(cmd) > 2 && cmd[0] == "sh" && cmd[2] == runStateScript:
			return 0, state
		case len(cmd) > 2 && cmd[0] == "sh" && cmd[2] == runMarkScript:
			return 0, log
		case len(cmd) > 2 && cmd[0] == "sh" && cmd[2] == runFollowScript:
			return 0, log
		case len(cmd) > 0 && cmd[0] == "tail":
			return 0, log
		}
		return 0, ""
	}
}

func ranScript(ta *testApp, script string) bool {
	return slices.ContainsFunc(ta.stream.runs, func(argv []string) bool {
		cmd := sandboxCommand(argv)
		return len(cmd) > 2 && cmd[0] == "sh" && cmd[2] == script
	})
}

// Resuming a sandbox whose detached run is still going (connect, or the
// wrapper's "Resume it?") must not stop it at the end of the session: that
// killed the background agent (manual test H9). A sandbox the session did
// start is stopped as before.
func TestConnectLeavesARunningSandboxRunning(t *testing.T) {
	cases := []struct {
		name     string
		phase    string
		state    string
		rm       bool
		stops    int
		deletes  int
		want     []string
		undoLess bool
	}{
		{name: "detached run going", phase: "ready", state: "started=1790000000\nstate=running\n", stops: 0, undoLess: true,
			want: []string{"Sandbox m1-b keeps running: its detached run is still going", "logs m1-b -f",
				"the detached run in m1-b is still going; review or undo once it ends"}},
		{name: "detached run going, --rm", phase: "ready", state: "state=running\n", rm: true, stops: 0, deletes: 0, undoLess: true,
			want: []string{"m1-b is not deleted (--rm): its detached run is still going"}},
		{name: "running, no run", phase: "ready", state: "state=none\n", stops: 0,
			want: []string{"Sandbox m1-b keeps running (it was running when you connected)"}},
		{name: "stopped before the session", phase: "stopped", state: "state=none\n", stops: 1,
			want: []string{"Sandbox kept (stopped) → resume: defenseclaw sandbox connect m1-b"}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			ta := newTestApp(t, "y\n")
			sb := sampleSandbox("m1-b")
			sb.Phase = c.phase
			ta.daemon.add(sb)
			runAnswers(ta, c.state, "")
			if err := ta.Connect(context.Background(), ConnectOptions{Name: "m1-b", Rm: c.rm}); err != nil {
				t.Fatalf("Connect: %v\n%s", err, ta.output())
			}
			if n := len(ta.daemon.callsTo("POST", "/api/v1/sandbox/sandboxes/m1-b/stop")); n != c.stops {
				t.Fatalf("stop calls = %d, want %d\n%s", n, c.stops, ta.output())
			}
			if n := len(ta.daemon.callsTo("DELETE", "/api/v1/sandbox/sandboxes/m1-b")); n != c.deletes {
				t.Fatalf("delete calls = %d, want %d", n, c.deletes)
			}
			if n := len(ta.daemon.callsTo("POST", "/api/v1/sandbox/sandboxes/m1-b/undo")); c.undoLess && n != 0 {
				t.Fatalf("undo calls = %d; an undo stops the sandbox under the run", n)
			}
			out := ta.output()
			for _, w := range c.want {
				if !strings.Contains(out, w) {
					t.Errorf("output lacks %q:\n%s", w, out)
				}
			}
			if c.undoLess && strings.Contains(out, "Keep changes?") {
				t.Fatalf("the keep/undo question was asked with a detached run going:\n%s", out)
			}
		})
	}
}

// `sandbox stop` on a sandbox whose detached run is still going asks first
// on a terminal, marks the run interrupted and keeps its log on this
// machine, where `sandbox logs` reads it once the sandbox is stopped (manual
// test M1).
func TestStopWithALiveDetachedRun(t *testing.T) {
	const log = "working on it\nstill working\n"
	t.Run("declined", func(t *testing.T) {
		ta := newTestApp(t, "n\n")
		ta.daemon.add(sampleSandbox("box"))
		runAnswers(ta, "started=1790000000\nstate=running\n", log)
		if err := ta.Stop(context.Background(), StopOptions{Name: "box"}); err != nil {
			t.Fatal(err)
		}
		if n := len(ta.daemon.callsTo("POST", "/api/v1/sandbox/sandboxes/box/stop")); n != 0 {
			t.Fatal("the sandbox was stopped although the user kept the run going")
		}
		if out := ta.output(); !strings.Contains(out, "box's detached run (started ") || !strings.Contains(out, "Stop anyway? [y/N]") ||
			!strings.Contains(out, "box keeps running") {
			t.Fatalf("output:\n%s", out)
		}
		if ranScript(ta, runMarkScript) {
			t.Fatal("a kept run was marked interrupted")
		}
	})
	for _, c := range []struct {
		name string
		tty  bool
		yes  bool
		in   string
	}{{"confirmed", true, false, "y\n"}, {"--yes", true, true, ""}, {"no terminal", false, false, ""}} {
		t.Run(c.name, func(t *testing.T) {
			ta := newTestApp(t, c.in)
			ta.IO.TTY = c.tty
			ta.daemon.add(sampleSandbox("box"))
			runAnswers(ta, "started=1790000000\nstate=running\n", log)
			if err := ta.Stop(context.Background(), StopOptions{Name: "box", Yes: c.yes}); err != nil {
				t.Fatal(err)
			}
			if n := len(ta.daemon.callsTo("POST", "/api/v1/sandbox/sandboxes/box/stop")); n != 1 {
				t.Fatalf("stop calls = %d", n)
			}
			if !ranScript(ta, runMarkScript) {
				t.Fatal("the run was not marked interrupted before the stop")
			}
			out := ta.output()
			if !strings.Contains(out, "is still going; stopping the sandbox ends it") {
				t.Fatalf("the stop did not say it ends the run:\n%s", out)
			}
			if (c.yes || !c.tty) && strings.Contains(out, "Stop anyway?") {
				t.Fatalf("asked although it could not or should not:\n%s", out)
			}
			// Stopped, the kept log is what `logs` shows.
			ta.out.Reset()
			ta.stream.runs = nil
			if err := ta.Logs(context.Background(), LogsOptions{Name: "box", Lines: 1}); err != nil {
				t.Fatalf("logs after the stop: %v", err)
			}
			out = ta.output()
			if !strings.Contains(out, "still working") || strings.Contains(out, "working on it") ||
				!strings.Contains(out, "the log kept when it stopped") || !strings.Contains(out, "the run did not finish") {
				t.Fatalf("logs after the stop:\n%s", out)
			}
			if len(ta.stream.runs) != 0 {
				t.Fatalf("logs of a stopped sandbox ran %q in it", ta.stream.commands())
			}
			// Deleting the sandbox drops what the CLI kept of it.
			dir, _ := ta.cliStateDir("box")
			if _, err := os.Stat(filepath.Join(dir, "run.log")); err != nil {
				t.Fatalf("kept log: %v", err)
			}
			if err := ta.Delete(context.Background(), DeleteOptions{Names: []string{"box"}, Yes: true}); err != nil {
				t.Fatal(err)
			}
			if _, err := os.Stat(dir); !os.IsNotExist(err) {
				t.Fatalf("the kept state outlived the sandbox: %v", err)
			}
		})
	}
}

// A kept log belongs to one sandbox: a later sandbox of the same name does
// not show it, and a stopped sandbox without one says how to read its log.
func TestLogsOfAStoppedSandbox(t *testing.T) {
	ta := newTestApp(t, "")
	sb := sampleSandbox("box")
	ta.daemon.add(sb)
	if err := ta.saveRunLog(&sb, detachedRun{State: runExited, Exit: "0"}, []byte("done\n")); err != nil {
		t.Fatal(err)
	}
	sb.Phase, sb.ID = "stopped", "sb-another-box"
	ta.daemon.add(sb)
	err := ta.Logs(context.Background(), LogsOptions{Name: "box"})
	if err == nil || !strings.Contains(err.Error(), "no log of a detached run was kept") || !strings.Contains(err.Error(), "defenseclaw sandbox start box") {
		t.Fatalf("Logs = %v", err)
	}
}

// Without the kept marker, a run whose process is gone reads "did not
// finish", not "still going" (the pid check is the run-state script's).
func TestLogsReportsAnInterruptedRun(t *testing.T) {
	ta := newTestApp(t, "")
	ta.IO.TTY = false
	ta.daemon.add(sampleSandbox("box"))
	runAnswers(ta, "started=1790000000\nstate=interrupted\n", "partial\n")
	if err := ta.Logs(context.Background(), LogsOptions{Name: "box"}); err != nil {
		t.Fatal(err)
	}
	if out := ta.output(); !strings.Contains(out, "the run did not finish") || strings.Contains(out, "still going") {
		t.Fatalf("logs:\n%s", out)
	}
	for _, want := range []string{`kill -0 "$pid"`, "/proc/$pid/cmdline", "grep -q latest.exit", "state=interrupted"} {
		if !strings.Contains(runStateScript, want) {
			t.Errorf("the run-state script lacks %q", want)
		}
	}
	if !strings.Contains(runFollowScript, `while alive && [ ! -s "$d/latest.exit" ]`) || !strings.Contains(runFollowScript, `kill "$t"`) {
		t.Fatalf("follow script:\n%s", runFollowScript)
	}
}

// A detached Claude Code run streams its events, which `logs` renders; a
// user's own --output-format wins.
func TestDetachedClaudeStreamsAndLogsRenderIt(t *testing.T) {
	if got := streamingArgs(harness.ClaudeCode, []string{"--model", "sonnet"}); !slices.Equal(got,
		[]string{"--model", "sonnet", "--output-format", "stream-json", "--verbose"}) {
		t.Fatalf("streamingArgs = %q", got)
	}
	if got := streamingArgs(harness.ClaudeCode, []string{"--output-format=json"}); !slices.Equal(got, []string{"--output-format=json"}) {
		t.Fatalf("streamingArgs kept format = %q", got)
	}
	if got := streamingArgs(harness.Codex, []string{"exec", "x"}); !slices.Equal(got, []string{"exec", "x"}) {
		t.Fatalf("codex args = %q", got)
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
// the changes at the end of a session, the next start asks for a new
// snapshot (manual test M2).
func TestResumeKeepsAnUnacceptedUndoPoint(t *testing.T) {
	ta := newTestApp(t, "y\n")
	sb := sampleSandbox("m1-a")
	sb.Phase = "stopped"
	earlier := time.Date(2026, 9, 27, 9, 30, 0, 0, time.UTC)
	sb.Snapshot = &sandboxapi.SnapshotInfo{Kind: "git", CreatedAt: earlier}
	sb.Workspace = &sandboxapi.WorkspaceSummary{Project: "~/proj → /work/proj (live)"}
	ta.daemon.add(sb)
	ta.daemon.pendingChanges = true
	if err := ta.Connect(context.Background(), ConnectOptions{Name: "m1-a"}); err != nil {
		t.Fatalf("Connect: %v\n%s", err, ta.output())
	}
	starts := ta.daemon.callsTo("POST", "/api/v1/sandbox/sandboxes/m1-a/start")
	if len(starts) != 1 || strings.Contains(string(starts[0].Body), "snapshot") {
		t.Fatalf("start = %s; the daemon decides about an unaccepted undo point", starts[0].Body)
	}
	out := ta.output()
	for _, want := range []string{"kept the undo point from " + ta.clock(earlier),
		"undo point from " + ta.clock(earlier) + " kept → `defenseclaw sandbox undo m1-a` reverts every session since"} {
		if !strings.Contains(out, want) {
			t.Errorf("output lacks %q:\n%s", want, out)
		}
	}
	if strings.Contains(out, "undo point taken") {
		t.Fatalf("the banner claims a fresh snapshot:\n%s", out)
	}
	// The user kept the changes: the next start, `start` or `connect`,
	// asks for a new snapshot.
	ta.out.Reset()
	if err := ta.Start(context.Background(), "m1-a", StartOptions{}); err != nil {
		t.Fatal(err)
	}
	starts = ta.daemon.callsTo("POST", "/api/v1/sandbox/sandboxes/m1-a/start")
	if len(starts) != 2 || !strings.Contains(string(starts[1].Body), `"new_snapshot":true`) {
		t.Fatalf("start after keeping = %s", starts[len(starts)-1].Body)
	}
	if out := ta.output(); strings.Contains(out, "kept the undo point") || !strings.Contains(out, "undo point taken → `defenseclaw sandbox undo m1-a` restores it") {
		t.Fatalf("output:\n%s", out)
	}
}

// `connect` asks for a new snapshot after the user kept the changes, like
// `start`.
func TestConnectAfterKeepingAsksForANewSnapshot(t *testing.T) {
	ta := newTestApp(t, "y\n")
	sb := sampleSandbox("m1-b")
	sb.Phase = "stopped"
	sb.Snapshot = &sandboxapi.SnapshotInfo{Kind: "git", CreatedAt: time.Now().Add(-time.Hour)}
	sb.Workspace = &sandboxapi.WorkspaceSummary{Project: "~/proj → /work/proj (live)"}
	ta.daemon.add(sb)
	ta.daemon.pendingChanges = true
	ta.acceptUndoPoint(&sb)
	if err := ta.Connect(context.Background(), ConnectOptions{Name: "m1-b"}); err != nil {
		t.Fatalf("Connect: %v\n%s", err, ta.output())
	}
	starts := ta.daemon.callsTo("POST", "/api/v1/sandbox/sandboxes/m1-b/start")
	if len(starts) != 1 || !strings.Contains(string(starts[0].Body), `"new_snapshot":true`) {
		t.Fatalf("start = %s", starts[0].Body)
	}
	if out := ta.output(); strings.Contains(out, "kept the undo point") || !strings.Contains(out, "undo point taken → `defenseclaw sandbox undo m1-b` restores it") {
		t.Fatalf("output:\n%s", out)
	}
}

func TestStartTakesAFreshSnapshotWhenNothingIsOnTop(t *testing.T) {
	ta := newTestApp(t, "")
	ta.IO.TTY = false
	sb := sampleSandbox("box")
	sb.Phase = "stopped"
	sb.Snapshot = &sandboxapi.SnapshotInfo{Kind: "git", CreatedAt: time.Now().Add(-time.Hour)}
	ta.daemon.add(sb)
	if err := ta.Start(context.Background(), "box", StartOptions{}); err != nil {
		t.Fatal(err)
	}
	starts := ta.daemon.callsTo("POST", "/api/v1/sandbox/sandboxes/box/start")
	if len(starts) != 1 || strings.Contains(string(starts[0].Body), "snapshot") {
		t.Fatalf("start = %s", starts[0].Body)
	}
	if out := ta.output(); !strings.Contains(out, "undo point taken → `defenseclaw sandbox undo box` restores it") {
		t.Fatalf("output:\n%s", out)
	}
	// Changes nobody kept: the daemon keeps the undo point, and the start
	// says so.
	ta.out.Reset()
	sb.Phase = "stopped"
	ta.daemon.add(sb)
	ta.daemon.pendingChanges = true
	if err := ta.Start(context.Background(), "box", StartOptions{}); err != nil {
		t.Fatal(err)
	}
	starts = ta.daemon.callsTo("POST", "/api/v1/sandbox/sandboxes/box/start")
	if len(starts) != 2 || strings.Contains(string(starts[1].Body), "snapshot") {
		t.Fatalf("second start = %s", starts[1].Body)
	}
	if out := ta.output(); !strings.Contains(out, "kept the undo point from ") || !strings.Contains(out, "`defenseclaw sandbox undo box` still reverts them") ||
		strings.Contains(out, "reverts every session since") {
		t.Fatalf("output (one line on the kept undo point):\n%s", out)
	}
	// --new-snapshot accepts them.
	ta.out.Reset()
	sb.Phase = "stopped"
	ta.daemon.add(sb)
	if err := ta.Start(context.Background(), "box", StartOptions{NewSnapshot: true}); err != nil {
		t.Fatal(err)
	}
	starts = ta.daemon.callsTo("POST", "/api/v1/sandbox/sandboxes/box/start")
	if len(starts) != 3 || !strings.Contains(string(starts[2].Body), `"new_snapshot":true`) {
		t.Fatalf("third start = %s", starts[2].Body)
	}
	if out := ta.output(); strings.Contains(out, "kept the undo point") || !strings.Contains(out, "undo point taken") {
		t.Fatalf("output:\n%s", out)
	}
}

// A headless session in an existing sandbox runs without a terminal:
// `connect NAME --prompt TEXT` or the harness's own print flag (manual
// test M6).
func TestConnectRunsOnePromptHeadless(t *testing.T) {
	for _, c := range []struct {
		name string
		opts ConnectOptions
		tail []string
	}{
		{"--prompt", ConnectOptions{Name: "m1-a", Prompt: "add the tests"}, []string{"-p", "add the tests"}},
		{"print flag", ConnectOptions{Name: "m1-a", Args: []string{"-p", "add the tests"}}, []string{"-p", "add the tests"}},
	} {
		t.Run(c.name, func(t *testing.T) {
			ta := newTestApp(t, "")
			ta.IO.TTY = false
			sb := sampleSandbox("m1-a")
			sb.Phase = "stopped"
			ta.daemon.add(sb)
			if err := ta.Connect(context.Background(), c.opts); err != nil {
				t.Fatalf("Connect: %v\n%s", err, ta.output())
			}
			if len(ta.term.runs) != 0 {
				t.Fatal("a headless connect took the terminal")
			}
			found := slices.ContainsFunc(ta.stream.runs, func(argv []string) bool {
				cmd := sandboxCommand(argv)
				return len(cmd) >= 2 && cmd[0] == harness.ClaudeCodeLauncherPath && slices.Equal(cmd[len(cmd)-2:], c.tail)
			})
			if !found {
				t.Fatalf("stream runs = %q", ta.stream.commands())
			}
			if n := len(ta.daemon.callsTo("POST", "/api/v1/sandbox/sandboxes/m1-a/stop")); n != 1 {
				t.Fatalf("stop calls = %d; the session started the sandbox", n)
			}
			if !strings.Contains(ta.output(), "resume: defenseclaw sandbox connect m1-a --prompt TEXT") {
				t.Fatalf("output:\n%s", ta.output())
			}
		})
	}
	ta := newTestApp(t, "")
	ta.IO.TTY = false
	ta.daemon.add(sampleSandbox("m1-a"))
	err := ta.Connect(context.Background(), ConnectOptions{Name: "m1-a"})
	if err == nil || !strings.Contains(err.Error(), "pass --prompt TEXT") {
		t.Fatalf("Connect without a terminal = %v", err)
	}
	err = ta.Connect(context.Background(), ConnectOptions{Name: "m1-a", Shell: true})
	if err == nil || !strings.Contains(err.Error(), "defenseclaw sandbox exec m1-a -- COMMAND") {
		t.Fatalf("Connect --shell without a terminal = %v", err)
	}
}

// A headless run on a terminal offers this folder's sandbox too (the
// wrapper's `claude -p ...` created a new sandbox every time).
func TestRunHeadlessOnATerminalOffersResume(t *testing.T) {
	ta := newTestApp(t, "y\n")
	ta.daemon.add(sandboxapi.Sandbox{Name: "proj-0a1b", ID: "sb-proj-0a1b", Harness: "claudecode", HarnessName: "Claude Code", Phase: "stopped",
		WorkdirMode: "mount", Project: ta.project, Workdir: "/work/proj", CreatedAt: time.Now()})
	ta.daemon.review = sandboxapi.ReviewResponse{Report: &workspace.ReviewReport{}}
	if err := ta.Run(context.Background(), RunOptions{Harness: "claude", Prompt: "next step"}); err != nil {
		t.Fatalf("Run: %v\n%s", err, ta.output())
	}
	if n := len(ta.daemon.callsTo("POST", sandboxapi.PathSandboxes)); n != 0 {
		t.Fatal("the resumed run created a sandbox")
	}
	if !slices.ContainsFunc(ta.stream.runs, func(argv []string) bool {
		cmd := sandboxCommand(argv)
		return len(cmd) > 1 && cmd[0] == harness.ClaudeCodeLauncherPath && slices.Contains(cmd, "next step")
	}) {
		t.Fatalf("stream runs = %q", ta.stream.commands())
	}
}

// A resumed sandbox keeps the settings it was created with: the offer names
// the flags a resume would ignore (--safe on a skip-permissions sandbox, a
// credential) and defaults to starting a new sandbox; resuming anyway says
// what was left out.
func TestRunResumeNamesTheFlagsItIgnores(t *testing.T) {
	existing := func(ta *testApp) {
		ta.daemon.add(sandboxapi.Sandbox{Name: "proj-0a1b", ID: "sb-proj-0a1b", Harness: "claudecode", HarnessName: "Claude Code", Phase: "stopped",
			WorkdirMode: "mount", Project: ta.project, Workdir: "/work/proj", Pack: "open", Profile: "open", Yolo: true,
			Launch: sandboxapi.Launch{Yolo: true}, CreatedAt: time.Now()})
		ta.daemon.review = sandboxapi.ReviewResponse{Report: &workspace.ReviewReport{}}
	}
	opts := RunOptions{Harness: "claude", Safe: true, Pack: "open", Credentials: []string{"STRIPE_API_KEY=api.stripe.com"}}

	// No to the resume, the default (a copy) for the folder the old sandbox
	// still mounts live, and skip bringing the copy's changes back.
	ta := newTestApp(t, "\n\ns\n")
	ta.env["STRIPE_API_KEY"] = "stripe-test-value"
	existing(ta)
	if err := ta.Run(context.Background(), opts); err != nil {
		t.Fatalf("Run: %v\n%s", err, ta.output())
	}
	out := ta.output()
	if !strings.Contains(out, "Resuming it keeps its own settings and ignores --safe, --credential. Resume it anyway? [y/N]") {
		t.Fatalf("offer:\n%s", out)
	}
	if req := createRequest(t, ta.daemon); !req.Safe || len(req.Credentials) != 1 {
		t.Fatalf("the default must start a new sandbox with the flags: %+v", req)
	}
	if n := len(ta.daemon.callsTo("POST", "/api/v1/sandbox/sandboxes/proj-0a1b/start")); n != 0 {
		t.Fatal("the old sandbox was resumed")
	}

	ta = newTestApp(t, "y\ny\n")
	ta.env["STRIPE_API_KEY"] = "stripe-test-value"
	existing(ta)
	if err := ta.Run(context.Background(), opts); err != nil {
		t.Fatalf("Run: %v\n%s", err, ta.output())
	}
	if n := len(ta.daemon.callsTo("POST", sandboxapi.PathSandboxes)); n != 0 {
		t.Fatal("resuming anyway created a sandbox")
	}
	if out := ta.output(); !strings.Contains(out, "resuming proj-0a1b without --safe, --credential (they apply to a new sandbox: run with --new --copy, or delete proj-0a1b first (`defenseclaw sandbox delete proj-0a1b`))") {
		t.Fatalf("output:\n%s", out)
	}

	// Flags the sandbox already matches ask nothing new.
	if got := resumeIgnores(RunOptions{Pack: "open", Profile: "open", LLM: LLMAuto}, &sandboxapi.Sandbox{Pack: "open", Profile: "open"}, nil); len(got) != 0 {
		t.Fatalf("resumeIgnores = %v", got)
	}
}

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
	"errors"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/openshell"
	"github.com/defenseclaw/defenseclaw/internal/openshell/sandboxapi"
	"github.com/defenseclaw/defenseclaw/internal/openshell/workspace"
)

// isRunStatus reports whether cmd reads a detached run's status.
func isRunStatus(cmd []string) bool {
	return len(cmd) > 2 && cmd[0] == "sh" && strings.Contains(cmd[2], "latest.exit")
}

func wantExit(t *testing.T, err error, code int) {
	t.Helper()
	var exit *ExitError
	if !errors.As(err, &exit) || exit.Code != code {
		t.Fatalf("err = %v, want exit status %d", err, code)
	}
}

// lockedBuffer is a stderr the session's notice goroutines write while the
// test reads it.
type lockedBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *lockedBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *lockedBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}

// liveErr gives ta a stderr that is safe to read during the session.
func liveErr(ta *testApp) *lockedBuffer {
	b := &lockedBuffer{}
	ta.IO.Err = b
	return b
}

// waitFor polls cond until it holds or the test's patience runs out.
func waitFor(t *testing.T, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for %s", what)
		}
		time.Sleep(5 * time.Millisecond)
	}
}

// A session none of whose hooks reach DefenseClaw looks like a clean run to
// the harness. The run warns live once the first hook is overdue, ends the
// summary with the warning and the doctor hint, and exits
// ExitHooksUnreachable.
func TestRunWarnsWhenHooksNeverReachDefenseClaw(t *testing.T) {
	ta := newTestApp(t, "")
	stderr := liveErr(ta)
	ta.HookWindow = 10 * time.Millisecond
	ta.term.hooks = nil
	ta.daemon.review = sandboxapi.ReviewResponse{Report: &workspace.ReviewReport{}}
	ta.term.during = func() {
		waitFor(t, "the live warning", func() bool { return strings.Contains(stderr.String(), "[defenseclaw] ⚠ DefenseClaw hooks") })
	}
	err := ta.Run(context.Background(), RunOptions{Harness: "claude"})
	wantExit(t, err, ExitHooksUnreachable)
	live := stderr.String()
	for _, want := range []string{
		"[defenseclaw] ⚠ DefenseClaw hooks are not reaching the daemon; every tool call is being blocked",
		"not one hook request reached DefenseClaw in the session's first",
		"Run: defenseclaw sandbox doctor",
	} {
		if !strings.Contains(live, want) {
			t.Errorf("live output lacks %q:\n%s", want, live)
		}
	}
	if n := strings.Count(live, "DefenseClaw hooks are not reaching"); n != 1 {
		t.Errorf("live warnings = %d, want 1", n)
	}
	out := ta.output()
	if !strings.Contains(out, "Session ended · 0 tool calls") ||
		!strings.Contains(out, "✗ DefenseClaw hooks are not reaching the daemon; every tool call is being blocked (not one hook request of this session reached DefenseClaw). Run: defenseclaw sandbox doctor") {
		t.Fatalf("summary:\n%s", out)
	}
}

// The daemon's verdict (its feed event and reason) is what the run shows
// when it has one; the harness's own failure status wins the exit.
func TestRunShowsTheDaemonsHookVerdict(t *testing.T) {
	ta := newTestApp(t, "")
	stderr := liveErr(ta)
	ta.term.hooks = nil
	ta.term.code = 3
	reason := "OpenShell refused the hooks' connections to the DefenseClaw ingress (host.openshell.internal:18971)"
	ta.daemon.review = sandboxapi.ReviewResponse{Report: &workspace.ReviewReport{}}
	ta.daemon.live = []sandboxapi.ActivityEvent{
		{Seq: 1, Kind: sandboxapi.ActivityFinding, Sandbox: "other", Reason: sandboxapi.ReasonHooksUnreachable, Message: "⚠ not this sandbox"},
		{Seq: 2, Kind: sandboxapi.ActivityFinding, Sandbox: "dc-claude-proj-1a2b", Reason: sandboxapi.ReasonHooksUnreachable,
			Message: "⚠ " + hooksWarningText(reason)},
	}
	ta.term.during = func() {
		waitFor(t, "the daemon's warning", func() bool { return strings.Contains(stderr.String(), "OpenShell refused") })
		ta.daemon.mu.Lock()
		sb := ta.daemon.sandboxes["dc-claude-proj-1a2b"]
		sb.Hooks.Unreachable, sb.Hooks.UnreachableReason = true, reason
		ta.daemon.mu.Unlock()
	}
	err := ta.Run(context.Background(), RunOptions{Harness: "claude"})
	wantExit(t, err, 3)
	if live := stderr.String(); strings.Contains(live, "not this sandbox") || strings.Count(live, "[defenseclaw]") != 1 {
		t.Fatalf("live output:\n%s", live)
	}
	if out := ta.output(); !strings.Contains(out, "✗ "+hooksWarningText(reason)) {
		t.Fatalf("summary lacks the daemon's reason:\n%s", out)
	}
}

// Hooks that reach DefenseClaw leave the run alone: no warning, exit 0.
func TestRunWithHooksHasNoHookWarning(t *testing.T) {
	ta := newTestApp(t, "")
	ta.HookWindow = 10 * time.Millisecond
	ta.daemon.review = sandboxapi.ReviewResponse{Report: &workspace.ReviewReport{}}
	ta.term.during = func() {
		ta.daemon.hookTraffic([]string{"--name", "dc-claude-proj-1a2b"})
		time.Sleep(50 * time.Millisecond) // past the window
	}
	if err := ta.Run(context.Background(), RunOptions{Harness: "claude"}); err != nil {
		t.Fatalf("Run: %v", err)
	}
	if strings.Contains(ta.err.String()+ta.output(), "not reaching") {
		t.Fatalf("a run whose hooks arrived was warned:\n%s\n%s", ta.err.String(), ta.output())
	}
}

// A copy-mode session without hooks warns and fails the same way.
func TestRunCopySessionWithoutHooks(t *testing.T) {
	ta := newTestApp(t, "s\n")
	ta.term.hooks = nil
	err := ta.Run(context.Background(), RunOptions{Harness: "claude", Copy: true, Name: "copybox"})
	wantExit(t, err, ExitHooksUnreachable)
	if out := ta.output(); !strings.Contains(out, "✗ DefenseClaw hooks are not reaching the daemon") {
		t.Fatalf("summary:\n%s", out)
	}
}

func TestLogsChecksTheRunsHooks(t *testing.T) {
	started := time.Now().Add(-time.Minute)
	cases := []struct {
		name    string
		status  string // "" while the run is going
		hooks   sandboxapi.HookCoverage
		code    int
		warning string
	}{
		{"hooks during the run", fmt.Sprintf("0\n%d\n", started.Unix()),
			sandboxapi.HookCoverage{HookRequests: 3, LastHookAt: time.Now()}, 0, ""},
		{"no hook since the run started", fmt.Sprintf("0\n%d\n", started.Unix()),
			sandboxapi.HookCoverage{HookRequests: 3, LastHookAt: started.Add(-time.Hour)}, ExitHooksUnreachable,
			"not one hook request of this run reached DefenseClaw"},
		{"never a hook, the daemon knows why", fmt.Sprintf("0\n%d\n", started.Unix()),
			sandboxapi.HookCoverage{Unreachable: true, UnreachableReason: "OpenShell refused the hooks' connections"}, ExitHooksUnreachable,
			"(OpenShell refused the hooks' connections). Run: defenseclaw sandbox doctor"},
		{"run of an older version, no start", "0\n", sandboxapi.HookCoverage{}, ExitHooksUnreachable, "every tool call is being blocked"},
		{"run of an older version with hooks", "0\n", sandboxapi.HookCoverage{HookRequests: 1, LastHookAt: time.Now()}, 0, ""},
		{"still going, unreachable", "", sandboxapi.HookCoverage{Unreachable: true, UnreachableReason: "no hook request"}, 0,
			"every tool call is being blocked (no hook request)"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			ta := newTestApp(t, "")
			ta.IO.TTY = false
			sb := sampleSandbox("box")
			sb.Hooks = c.hooks
			ta.daemon.add(sb)
			ta.stream.answer = func(argv []string) (int, string) {
				if isRunStatus(sandboxCommand(argv)) {
					if c.status == "" {
						return 1, ""
					}
					return 0, c.status
				}
				return 0, "log line\n"
			}
			err := ta.Logs(context.Background(), LogsOptions{Name: "box"})
			if c.code == 0 && err != nil {
				t.Fatalf("Logs: %v", err)
			}
			if c.code != 0 {
				wantExit(t, err, c.code)
			}
			out := ta.output()
			if c.warning == "" && strings.Contains(out, "not reaching") {
				t.Fatalf("unexpected warning:\n%s", out)
			}
			if c.warning != "" && (!strings.Contains(out, "DefenseClaw hooks are not reaching the daemon") || !strings.Contains(out, c.warning)) {
				t.Fatalf("output lacks %q:\n%s", c.warning, out)
			}
		})
	}
}

func TestParseRunStatus(t *testing.T) {
	for in, want := range map[string]runStatus{
		"0\n":              {exit: "0"},
		"3\n1790000000\n":  {exit: "3", started: 1790000000},
		" 0 \n garbage \n": {exit: "0"},
	} {
		if got := parseRunStatus(in); got != want {
			t.Errorf("parseRunStatus(%q) = %+v, want %+v", in, got, want)
		}
	}
}

func TestDetachRecordsTheRunsStart(t *testing.T) {
	ta := newTestApp(t, "")
	ta.IO.TTY = false
	if err := ta.Run(context.Background(), RunOptions{Harness: "claude", Detach: true, Prompt: "x"}); err != nil {
		t.Fatal(err)
	}
	script := sandboxCommand(ta.stream.runs[len(ta.stream.runs)-1])[2]
	if !strings.Contains(script, `date +%s > "$d/latest.started"`) {
		t.Fatalf("detach script:\n%s", script)
	}
}

func TestStatusAndListShowUnreachableHooks(t *testing.T) {
	ta := newTestApp(t, "")
	sb := sampleSandbox("box")
	sb.Hooks.Unreachable, sb.Hooks.UnreachableSince, sb.Hooks.UnreachableReason = true, time.Now(), "OpenShell refused the hooks' connections"
	sb.Hooks.IngressRefused = 4
	ta.daemon.add(sb)
	if err := ta.Status(context.Background(), "box", OutputText); err != nil {
		t.Fatal(err)
	}
	out := ta.output()
	for _, want := range []string{"4 refused by OpenShell", "NOT REACHING DefenseClaw since",
		"⚠ " + hooksWarningText("OpenShell refused the hooks' connections")} {
		if !strings.Contains(out, want) {
			t.Errorf("status lacks %q:\n%s", want, out)
		}
	}
	ta.out.Reset()
	if err := ta.List(context.Background(), OutputText); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(ta.output(), "unreachable!") {
		t.Fatalf("list:\n%s", ta.output())
	}
}

func TestDoctorReportsSandboxHooks(t *testing.T) {
	check := func(ta *testApp) openshell.Check {
		t.Helper()
		ta.HostDoctor = func(context.Context, *openshell.Doctor) *openshell.DoctorReport { return &openshell.DoctorReport{} }
		for _, c := range ta.runDoctor(context.Background()).Checks {
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

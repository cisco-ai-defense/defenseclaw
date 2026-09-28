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

	"github.com/defenseclaw/defenseclaw/internal/openshell/sandboxapi"
	"github.com/defenseclaw/defenseclaw/internal/openshell/workspace"
)

const sbPath = "/api/v1/sandbox/sandboxes/dc-claude-proj-1a2b"

// What the agent left running inside the sandbox keeps writing to the
// mounted folder: a session that started the sandbox stops it before the
// review, so the review and the keep/undo answer cover every change.
func TestSessionStopsTheSandboxBeforeTheReview(t *testing.T) {
	ta := newTestApp(t, "y\n")
	if err := ta.Run(context.Background(), RunOptions{Harness: "claude"}); err != nil {
		t.Fatalf("Run: %v\n%s", err, ta.output())
	}
	paths := ta.daemon.paths()
	stop, review := slices.Index(paths, "POST "+sbPath+"/stop"), slices.Index(paths, "POST "+sbPath+"/review")
	if stop < 0 || review < 0 || stop > review {
		t.Fatalf("stop at %d, review at %d; want the stop first:\n%s", stop, review, strings.Join(paths, "\n"))
	}
	if n := len(ta.daemon.callsTo("POST", sbPath+"/stop")); n != 1 {
		t.Fatalf("stop calls = %d", n)
	}
	if !strings.Contains(ta.output(), "Sandbox kept (stopped)") {
		t.Fatalf("output:\n%s", ta.output())
	}
}

// A sandbox that was running before the session keeps running, so the
// review says it may miss what comes later.
func TestSessionInARunningSandboxSaysTheReviewIsLive(t *testing.T) {
	ta := newTestApp(t, "y\n")
	sb := sampleSandbox("m1-b")
	ta.daemon.add(sb)
	runAnswers(ta, "state=none\n", "")
	if err := ta.Connect(context.Background(), ConnectOptions{Name: "m1-b"}); err != nil {
		t.Fatalf("Connect: %v\n%s", err, ta.output())
	}
	if n := len(ta.daemon.callsTo("POST", "/api/v1/sandbox/sandboxes/m1-b/stop")); n != 0 {
		t.Fatalf("stop calls = %d", n)
	}
	if !strings.Contains(ta.output(), "m1-b is still running (it was running when you connected); changes it makes after this point are not in this review") {
		t.Fatalf("output:\n%s", ta.output())
	}
}

// A review that fails says nothing about what changed: the keep/undo
// question still comes, keeping does not make the changes the next
// session's base, and --rm keeps the undo snapshot.
func TestSessionWhoseReviewFailedKeepsUndo(t *testing.T) {
	ta := newTestApp(t, "\n")
	ta.daemon.errors["POST "+sbPath+"/review"] = sandboxapi.Errorf(sandboxapi.CodeInternal, "the snapshot is unreadable")
	if err := ta.Run(context.Background(), RunOptions{Harness: "claude", Rm: true}); err != nil {
		t.Fatalf("Run: %v\n%s", err, ta.output())
	}
	out := ta.output()
	for _, want := range []string{"could not review the session's changes", "Keep changes?",
		"its undo point is kept because the changes were not reviewed", "undo: defenseclaw sandbox undo dc-claude-proj-1a2b"} {
		if !strings.Contains(out, want) {
			t.Errorf("output lacks %q:\n%s", want, out)
		}
	}
	del := ta.daemon.callsTo("DELETE", sbPath)
	if len(del) != 1 || !strings.Contains(string(del[0].Body), `"keep_snapshot":true`) {
		t.Fatalf("delete calls = %+v; want the snapshot kept", del)
	}
	dir, _ := ta.cliStateDir("dc-claude-proj-1a2b")
	if _, err := os.Stat(filepath.Join(dir, "accepted.json")); err == nil {
		t.Fatal("unreviewed changes were accepted as the next session's base")
	}

	// Undone after a failed review, the snapshot has served.
	ta = newTestApp(t, "u\n")
	ta.daemon.errors["POST "+sbPath+"/review"] = sandboxapi.Errorf(sandboxapi.CodeInternal, "the snapshot is unreadable")
	if err := ta.Run(context.Background(), RunOptions{Harness: "claude", Rm: true}); err != nil {
		t.Fatalf("Run: %v\n%s", err, ta.output())
	}
	if n := len(ta.daemon.callsTo("POST", sbPath+"/undo")); n != 1 {
		t.Fatalf("undo calls = %d", n)
	}
	if del := ta.daemon.callsTo("DELETE", sbPath); len(del) != 1 || strings.Contains(string(del[0].Body), "keep_snapshot") {
		t.Fatalf("delete calls after undo = %+v", del)
	}
}

// A headless session (--prompt) on a terminal still asks "Keep changes?"
// at its end, and keeping them makes them the next session's base; only a
// session with no terminal to ask on leaves its changes unaccepted, so the
// next start keeps the undo point.
func TestHeadlessSessionOnATerminalAsksToKeepChanges(t *testing.T) {
	for _, c := range []struct {
		name string
		tty  bool
	}{
		{"terminal", true},
		{"no terminal", false},
	} {
		t.Run(c.name, func(t *testing.T) {
			ta := newTestApp(t, "y\n")
			ta.IO.TTY = c.tty
			sb := sampleSandbox("m1-a")
			sb.Phase = "stopped"
			sb.Snapshot = &sandboxapi.SnapshotInfo{Kind: "git", CreatedAt: time.Date(2026, 9, 27, 9, 30, 0, 0, time.UTC)}
			ta.daemon.add(sb)
			if err := ta.Connect(context.Background(), ConnectOptions{Name: "m1-a", Prompt: "add the tests"}); err != nil {
				t.Fatalf("Connect: %v\n%s", err, ta.output())
			}
			if len(ta.term.runs) != 0 {
				t.Fatal("a headless session took the terminal")
			}
			if asked := strings.Contains(ta.output(), "Keep changes?"); asked != c.tty {
				t.Fatalf("asked = %v, want %v:\n%s", asked, c.tty, ta.output())
			}
			if err := ta.Start(context.Background(), "m1-a", StartOptions{}); err != nil {
				t.Fatal(err)
			}
			starts := ta.daemon.callsTo("POST", "/api/v1/sandbox/sandboxes/m1-a/start")
			if len(starts) != 2 {
				t.Fatalf("start calls = %d", len(starts))
			}
			if fresh := strings.Contains(string(starts[1].Body), `"new_snapshot":true`); fresh != c.tty {
				t.Fatalf("the next start asks for a new snapshot = %v, want %v (body %s)", fresh, c.tty, starts[1].Body)
			}
		})
	}
}

// Without a terminal nobody answers the keep/undo question: the changes
// are kept but stay undoable, so --rm keeps the undo snapshot and says how
// to undo or drop it. With --yes the changes were accepted, and --rm drops
// the snapshot.
func TestHeadlessRmKeepsTheSnapshotOfUnacceptedChanges(t *testing.T) {
	ta := newTestApp(t, "")
	ta.IO.TTY = false
	if err := ta.Run(context.Background(), RunOptions{Harness: "claude", Prompt: "fix it", Rm: true}); err != nil {
		t.Fatalf("Run: %v\n%s", err, ta.output())
	}
	del := ta.daemon.callsTo("DELETE", sbPath)
	if len(del) != 1 || !strings.Contains(string(del[0].Body), `"keep_snapshot":true`) {
		t.Fatalf("delete calls = %+v; want the snapshot kept", del)
	}
	out := ta.output()
	for _, want := range []string{"its undo point is kept because nobody accepted the changes",
		"undo: defenseclaw sandbox undo dc-claude-proj-1a2b", "drop it: defenseclaw sandbox delete dc-claude-proj-1a2b"} {
		if !strings.Contains(out, want) {
			t.Errorf("output lacks %q:\n%s", want, out)
		}
	}

	ta = newTestApp(t, "")
	ta.IO.TTY = false
	if err := ta.Run(context.Background(), RunOptions{Harness: "claude", Prompt: "fix it", Rm: true, Yes: true}); err != nil {
		t.Fatalf("Run --yes: %v\n%s", err, ta.output())
	}
	if del := ta.daemon.callsTo("DELETE", sbPath); len(del) != 1 || strings.Contains(string(del[0].Body), "keep_snapshot") {
		t.Fatalf("delete calls with --yes = %+v; want the snapshot dropped", del)
	}
}

// An ask waits for the user while the harness owns the terminal: the
// banner says where asks are answered, each one is announced live with the
// command that answers it, and the end of the session names those left.
func TestSessionShowsAsks(t *testing.T) {
	ta := newTestApp(t, "y\n")
	stderr := liveErr(ta)
	ta.daemon.live = []sandboxapi.ActivityEvent{{Seq: 1, Kind: sandboxapi.ActivityApprovalRequested, Sandbox: "dc-claude-proj-1a2b",
		ApprovalID: "ap-1", Host: "db.example.internal", Port: 5432}}
	ta.term.during = func() {
		waitFor(t, "the ask notice", func() bool { return strings.Contains(stderr.String(), "ap-1") })
		ta.daemon.mu.Lock()
		ta.daemon.sandboxes["dc-claude-proj-1a2b"].PendingApprovals = 1
		ta.daemon.mu.Unlock()
	}
	if err := ta.Run(context.Background(), RunOptions{Harness: "claude"}); err != nil {
		t.Fatalf("Run: %v\n%s", err, ta.output())
	}
	if live := stderr.String(); !strings.Contains(live, "? ask ap-1: db.example.internal:5432 is waiting for you → in another terminal: defenseclaw sandbox approve dc-claude-proj-1a2b ap-1") {
		t.Fatalf("live output:\n%s", live)
	}
	out := ta.output()
	for _, want := range []string{"Asks      announced in this terminal's title as they come; answer them in another terminal: defenseclaw sandbox approvals --sandbox dc-claude-proj-1a2b (or `defenseclaw tui`: 7, then t)",
		"? 1 ask is still waiting for you → defenseclaw sandbox approvals --sandbox dc-claude-proj-1a2b"} {
		if !strings.Contains(out, want) {
			t.Errorf("output lacks %q:\n%s", want, out)
		}
	}
}

// Bringing back a copy-mode sandbox's work asks first when the agent wrote
// a critical secret, as `pull --apply` does, though no risk line names it.
func TestCopySessionAsksBeforeBringingBackASecret(t *testing.T) {
	ta := newTestApp(t, "a\n\n")
	ta.copy.pull = &workspace.PullResult{Name: "fix-tests", Kind: workspace.CopyGit,
		Changes: []workspace.TreeChange{{Path: "config/keys.txt", Status: "A", Added: 1}},
		Review: workspace.ReviewReport{FilesChanged: 1, Insertions: 1, Findings: []workspace.ScanFinding{
			{Path: "config/keys.txt", Scanner: "clawshield-secrets", RuleID: "CS-SEC-MARKER", Severity: "CRITICAL", Title: "marker secret"}}}}
	if err := ta.Run(context.Background(), RunOptions{Harness: "claude", Copy: true, Name: "fix-tests"}); err != nil {
		t.Fatalf("Run: %v\n%s", err, ta.output())
	}
	out := ta.output()
	for _, want := range []string{"the sandbox wrote what looks like a secret: config/keys.txt",
		"Some changes hold what looks like a secret. Bring them back anyway?"} {
		if !strings.Contains(out, want) {
			t.Errorf("output lacks %q:\n%s", want, out)
		}
	}
	if len(ta.copy.apply) != 0 {
		t.Fatalf("the secret was brought back without a yes: %+v", ta.copy.apply)
	}

	ta = newTestApp(t, "a\ny\n")
	ta.copy.pull = &workspace.PullResult{Name: "fix-tests", Kind: workspace.CopyGit, Changes: []workspace.TreeChange{{Path: "config/keys.txt", Status: "A"}},
		Review: workspace.ReviewReport{FilesChanged: 1, Findings: []workspace.ScanFinding{{Path: "config/keys.txt", Scanner: "clawshield-secrets", Severity: "CRITICAL"}}}}
	if err := ta.Run(context.Background(), RunOptions{Harness: "claude", Copy: true, Name: "fix-tests"}); err != nil {
		t.Fatalf("Run: %v\n%s", err, ta.output())
	}
	if len(ta.copy.apply) != 1 || !ta.copy.apply[0].AcceptSensitive {
		t.Fatalf("apply after yes = %+v", ta.copy.apply)
	}
}

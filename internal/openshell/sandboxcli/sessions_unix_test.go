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

//go:build unix

package sandboxcli

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/openshell/sandboxapi"
)

// Two sessions can share a sandbox (a second `claude` in the folder resumes
// it): one session's end stops nothing, undoes nothing and deletes nothing
// (--rm) under the other's harness, whichever of them started it.
func TestSessionLeavesASandboxAnotherSessionIsAttachedTo(t *testing.T) {
	check := func(t *testing.T, ta *testApp, name string) {
		t.Helper()
		for _, verb := range []string{"stop", "undo"} {
			if n := len(ta.daemon.callsTo("POST", "/api/v1/sandbox/sandboxes/"+name+"/"+verb)); n != 0 {
				t.Errorf("%s calls = %d under the other session", verb, n)
			}
		}
		if n := len(ta.daemon.callsTo("DELETE", "/api/v1/sandbox/sandboxes/"+name)); n != 0 {
			t.Errorf("delete calls = %d under the other session", n)
		}
		out := ta.output()
		for _, want := range []string{name + " keeps running: 1 other session is attached to it, so what changes after this review is not in it",
			"1 other session is attached to it; review or undo once they end: `defenseclaw sandbox review " + name + "`",
			name + " is not deleted (--rm): 1 other session is attached to it",
			"Sandbox " + name + " keeps running: 1 other session is attached to it → stop it once they end: defenseclaw sandbox stop " + name} {
			if !strings.Contains(out, want) {
				t.Errorf("output lacks %q:\n%s", want, out)
			}
		}
		if strings.Contains(out, "Keep changes?") {
			t.Errorf("undo was offered under the other session:\n%s", out)
		}
	}
	t.Run("the session that started it", func(t *testing.T) {
		ta := newTestApp(t, "u\n")
		// The other session resumed the sandbox this run creates.
		release := ta.holdSession("dc-claude-proj-1a2b")
		defer release()
		if err := ta.Run(context.Background(), RunOptions{Harness: "claude", Rm: true}); err != nil {
			t.Fatalf("Run: %v\n%s", err, ta.output())
		}
		check(t, ta, "dc-claude-proj-1a2b")
	})
	t.Run("a session that resumed it", func(t *testing.T) {
		ta := newTestApp(t, "u\n")
		sb := sampleSandbox("m1-b")
		sb.Snapshot = &sandboxapi.SnapshotInfo{Kind: "git", CreatedAt: time.Now().Add(-time.Hour)}
		ta.daemon.add(sb)
		runAnswers(ta, "state=none\n", "")
		release := ta.holdSession("m1-b")
		defer release()
		if err := ta.Connect(context.Background(), ConnectOptions{Name: "m1-b", Rm: true}); err != nil {
			t.Fatalf("Connect: %v\n%s", err, ta.output())
		}
		check(t, ta, "m1-b")
	})
	t.Run("once the other session ended", func(t *testing.T) {
		ta := newTestApp(t, "y\n")
		release := ta.holdSession("dc-claude-proj-1a2b")
		release()
		if err := ta.Run(context.Background(), RunOptions{Harness: "claude"}); err != nil {
			t.Fatalf("Run: %v\n%s", err, ta.output())
		}
		if n := len(ta.daemon.callsTo("POST", sbPath+"/stop")); n != 1 {
			t.Fatalf("stop calls = %d; the session that started the sandbox stops it when it is alone", n)
		}
	})
}

// A session's lease lasts while its process holds it: released, or left by
// a process that is gone, it no longer counts, and a count removes it.
func TestSessionLeases(t *testing.T) {
	ta := newTestApp(t, "")
	if n := ta.attachedSessions("box"); n != 0 {
		t.Fatalf("attached = %d before any session", n)
	}
	one, two := ta.holdSession("box"), ta.holdSession("box")
	if n := ta.attachedSessions("box"); n != 2 {
		t.Fatalf("attached = %d, want 2", n)
	}
	one()
	one()
	if n := ta.attachedSessions("box"); n != 1 {
		t.Fatalf("attached = %d after one release, want 1", n)
	}
	two()
	dir, err := ta.sessionsDir("box")
	if err != nil {
		t.Fatal(err)
	}
	// A lease file nobody holds (its process died).
	stale := filepath.Join(dir, "4242-0a0b0c0d0e0f"+leaseSuffix)
	if err := os.WriteFile(stale, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if n := ta.attachedSessions("box"); n != 0 {
		t.Fatalf("attached = %d with only a stale lease", n)
	}
	if _, err := os.Stat(stale); !os.IsNotExist(err) {
		t.Fatalf("the stale lease is still there: %v", err)
	}
}

// The offer to resume a sandbox another session is attached to says so:
// the two sessions share it.
func TestRunResumeNamesTheAttachedSessions(t *testing.T) {
	ta := newTestApp(t, "y\ny\n")
	ta.daemon.add(sandboxapi.Sandbox{Name: "proj-0a1b", ID: "sb-proj-0a1b", Harness: "claudecode", HarnessName: "Claude Code", Phase: "ready",
		WorkdirMode: "mount", Project: ta.project, Workdir: "/work/proj", Pack: "open", Profile: "open", Yolo: true,
		Launch: sandboxapi.Launch{Yolo: true}, CreatedAt: time.Now()})
	runAnswers(ta, "state=none\n", "")
	release := ta.holdSession("proj-0a1b")
	defer release()
	if err := ta.Run(context.Background(), RunOptions{Harness: "claude"}); err != nil {
		t.Fatalf("Run: %v\n%s", err, ta.output())
	}
	if out := ta.output(); !strings.Contains(out, "Sandbox proj-0a1b (ready, mount) already holds this folder, and 1 session is attached to it. Resume it? [Y/n]") {
		t.Fatalf("offer:\n%s", out)
	}
}

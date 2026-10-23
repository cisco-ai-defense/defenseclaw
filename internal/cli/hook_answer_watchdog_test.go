// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/gateway/connector/hookexec"
)

// GAP-0155: the hook command arms the answer watchdog of a tool call before
// it resolves its runtime, from the payload it reads first, and hands Run
// the same bytes.
func TestHookArmsTheAnswerWatchdogBeforeTheRuntimeResolution(t *testing.T) {
	savedSecureClient := secureClientHost
	secureClientHost = func() bool { return false }
	t.Cleanup(func() { secureClientHost = savedSecureClient })
	for _, test := range []struct {
		payload string
		armed   bool
	}{
		{`{"hook_event_name":"PreToolUse","tool_name":"Bash","tool_input":{"command":"echo ok"}}`, true},
		{`{"hook_event_name":"SessionStart"}`, false},
	} {
		reader, writer, err := os.Pipe()
		if err != nil {
			t.Fatal(err)
		}
		if _, err := writer.WriteString(test.payload); err != nil {
			t.Fatal(err)
		}
		_ = writer.Close()
		savedStdin := os.Stdin
		os.Stdin = reader
		stdin, watchdog := armHookAnswerWatchdog("claudecode", "", "", "", true, time.Now(), func(int) {})
		os.Stdin = savedStdin
		if (watchdog != nil) != test.armed {
			t.Fatalf("%s: watchdog armed=%v, want %v", test.payload, watchdog != nil, test.armed)
		}
		got, err := io.ReadAll(stdin)
		_ = reader.Close()
		if err != nil || string(got) != test.payload {
			t.Fatalf("Run would read %q (%v), want the agent's payload %q", got, err, test.payload)
		}
		if code := watchdog.Finish(7); code != 7 {
			t.Fatalf("Finish before the deadline returned %d, want the call's own 7", code)
		}
	}
}

// A managed hook arms its answer watchdog before anything resolves the
// user's diagnostic directory: on Windows that is a token-bound Known Folder
// lookup that can stall, and a stall before the watchdog runs left the call
// with no fail-closed answer at its deadline. Once armed, the hook starts
// that lookup in the background (G-small loop 2): a lookup slower than the
// watchdog's log wait left the call it answered with no failure row.
func TestManagedHookArmsTheWatchdogThenPrefetchesTheProfileLookup(t *testing.T) {
	savedSecureClient, savedProfile := secureClientHost, hookUserProfileDir
	secureClientHost = func() bool { return false }
	looked := make(chan struct{}, 1)
	stalled := make(chan struct{})
	hookUserProfileDir = func() (string, error) {
		looked <- struct{}{}
		<-stalled
		return "", nil
	}
	t.Cleanup(func() {
		close(stalled)
		secureClientHost, hookUserProfileDir = savedSecureClient, savedProfile
	})
	reader, writer, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := writer.WriteString(`{"hook_event_name":"PreToolUse","tool_name":"Bash","tool_input":{"command":"echo ok"}}`); err != nil {
		t.Fatal(err)
	}
	_ = writer.Close()
	savedStdin := os.Stdin
	os.Stdin = reader
	t.Cleanup(func() { os.Stdin = savedStdin; _ = reader.Close() })
	armed := make(chan *hookexec.AnswerWatchdog, 1)
	go func() {
		_, watchdog := armHookAnswerWatchdog("claudecode", "", "", "", true, time.Now(), func(int) {})
		armed <- watchdog
	}()
	var watchdog *hookexec.AnswerWatchdog
	select {
	case watchdog = <-armed:
		if watchdog == nil {
			t.Fatal("the managed tool call armed no watchdog")
		}
	case <-time.After(10 * time.Second):
		t.Fatal("arming the watchdog waited on the stalled profile lookup")
	}
	defer watchdog.Finish(0)
	select {
	case <-looked:
	case <-time.After(10 * time.Second):
		t.Fatal("the armed hook did not start the profile lookup of its failure rows")
	}
}

// GAP-0862: a per-user hook in fail mode open armed its watchdog with an
// open answer and no data directory, so a deadline that passed before Run
// (a stalled runtime resolution) allowed the tool call during an install or
// upgrade. The hook command arms the watchdog with this account's data
// directory (DEFENSECLAW_HOME included), and its install lock closes the
// early answer. Without the lock the call blocks too: since
// fix/r104-sa-hook-pause no answer closes every hook outside Secure Client.
func TestPerUserHookEarlyAnswerIsClosedWhileTheInstallerHoldsTheDataDirectory(t *testing.T) {
	savedSecureClient := secureClientHost
	secureClientHost = func() bool { return false }
	t.Cleanup(func() { secureClientHost = savedSecureClient })
	for _, installing := range []bool{false, true} {
		home := t.TempDir()
		t.Setenv("DEFENSECLAW_HOME", home)
		if installing {
			if err := os.Mkdir(filepath.Join(home, ".install.lock"), 0o700); err != nil {
				t.Fatal(err)
			}
		}
		reader, writer, err := os.Pipe()
		if err != nil {
			t.Fatal(err)
		}
		if _, err := writer.WriteString(`{"hook_event_name":"PreToolUse","tool_name":"Bash","tool_input":{"command":"echo ok"}}`); err != nil {
			t.Fatal(err)
		}
		_ = writer.Close()
		answer, err := os.Create(filepath.Join(t.TempDir(), "answer"))
		if err != nil {
			t.Fatal(err)
		}
		savedStdin, savedStdout, savedStderr := os.Stdin, os.Stdout, os.Stderr
		os.Stdin, os.Stdout, os.Stderr = reader, answer, answer
		exited := make(chan int, 1)
		// The 3.5 s answer budget is nearly spent: the deadline passes
		// while the work before Run is held.
		started := time.Now().Add(-3400 * time.Millisecond)
		_, watchdog := armHookAnswerWatchdog("claudecode", "PreToolUse", "open", "", false, started, func(code int) { exited <- code })
		os.Stdin, os.Stdout, os.Stderr = savedStdin, savedStdout, savedStderr
		_ = reader.Close()
		if watchdog == nil {
			t.Fatal("the per-user tool call armed no watchdog")
		}
		var code int
		select {
		case code = <-exited:
		case <-time.After(5 * time.Second):
			t.Fatal("no answer at the deadline")
		}
		_ = answer.Close()
		out, _ := os.ReadFile(answer.Name())
		// Claude Code blocks with exit 2 or a structured deny.
		blocked := code == 2 || strings.Contains(string(out), `"permissionDecision":"deny"`)
		if !blocked {
			t.Fatalf("installing=%v: exit %d output %q, want blocked", installing, code, out)
		}
	}
}

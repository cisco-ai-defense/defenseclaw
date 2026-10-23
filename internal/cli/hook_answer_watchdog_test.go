// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"io"
	"os"
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

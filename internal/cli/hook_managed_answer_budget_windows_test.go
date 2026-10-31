// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package cli

import (
	"bytes"
	"io"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/enterprisehooks"
	"github.com/defenseclaw/defenseclaw/internal/hookruntime"
)

// rel-1-0-4 GAP-0872: during a Claude attestation repair, registered managed
// Claude hooks were answered after 5.2 and 5.8 s. The hook process resolved
// its managed runtime (machine policy, runtime generation, their ACLs) in
// main, through NativeHookRuntimeNoop, before the hook command armed the
// answer watchdog, so a resolution the repair held up was not bounded by the
// answer budget. Run the hook as main does with a resolution that never
// finishes: the call must still be answered closed (no answer from the
// gateway) inside the five seconds the agent waits.
func TestManagedHookIsAnsweredInsideTheBudgetWhileItsRuntimeResolutionStalls(t *testing.T) {
	stubNativeDelegatedHookRuntimeReader(t, func(string) (hookruntime.State, bool, error) {
		return hookruntime.State{}, false, nil
	})
	stubNativeHookRuntimeReader(t, func(string) (hookruntime.State, bool, error) {
		return hookruntime.State{}, false, nil
	})
	resolving := make(chan struct{}, 1)
	never := make(chan struct{})
	stubEnterpriseManagedRuntimeResolver(t, func(string, string) (enterprisehooks.WindowsManagedHookRuntime, error) {
		resolving <- struct{}{}
		<-never // a resolution the host never lets finish
		return enterprisehooks.WindowsManagedHookRuntime{}, nil
	})
	savedSecureClient := secureClientHost
	secureClientHost = func() bool { return false }
	t.Cleanup(func() { secureClientHost = savedSecureClient })

	payload := `{"hook_event_name":"PreToolUse","session_id":"s","tool_name":"Bash","tool_input":{"command":"echo ok"}}`
	stdinRead, stdinWrite, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := stdinWrite.WriteString(payload); err != nil {
		t.Fatal(err)
	}
	_ = stdinWrite.Close()
	// Claude Code reads a block from exit status 2 and the reason on stderr.
	stderrRead, stderrWrite, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	var answer bytes.Buffer
	copied := make(chan struct{})
	go func() {
		_, _ = io.Copy(&answer, stderrRead)
		close(copied)
	}()
	savedArgs, savedStdin, savedStderr := os.Args, os.Stdin, os.Stderr
	os.Stdin, os.Stderr = stdinRead, stderrWrite
	exited := make(chan int, 2)
	savedExit := hookProcessExit
	hookProcessExit = func(code int) { exited <- code }
	t.Cleanup(func() {
		hookProcessExit = savedExit
		os.Args, os.Stdin, os.Stderr = savedArgs, savedStdin, savedStderr
		_ = stdinRead.Close()
	})

	args := []string{"hook", "--connector", "claudecode", "--enterprise-managed"}
	started := time.Now()
	go func() {
		// cmd/defenseclaw-hook main: the launcher check, then the command.
		os.Args = append([]string{savedArgs[0]}, args...)
		if NativeHookRuntimeNoop() {
			exited <- -1
			return
		}
		// The call's budget counts from here (an in-process command starts now).
		os.Args = savedArgs[:1]
		cmd := newHookCmd()
		cmd.SetArgs(args[1:])
		cmd.SetOut(io.Discard)
		cmd.SetErr(io.Discard)
		_ = cmd.Execute()
	}()

	var code int
	select {
	case code = <-exited:
	case <-time.After(8 * time.Second):
		t.Fatal("no answer within 8 s: the managed runtime resolution held the call before its answer deadline")
	}
	elapsed := time.Since(started)
	<-resolving // the stalled resolution ran, after the watchdog was armed
	_ = stderrWrite.Close()
	<-copied
	if code == -1 {
		t.Fatal("the stalled managed call ended as a no-op")
	}
	if elapsed >= 5*time.Second {
		t.Fatalf("answered after %s, want inside the 5 s the agent waits", elapsed)
	}
	if got := answer.String(); code != 2 || !strings.Contains(got, "enterprise_managed_gateway_no_answer") {
		t.Fatalf("answer = exit %d, stderr %q; want the closed no-answer block (exit 2)", code, got)
	}
}

// rel-1-0-3 GAP-0159: during a Setup /repair one registered managed Claude
// call was answered after 5.2 s while the others failed closed in 2.9 s.
// NativeHookRuntimeNoop ran the per-user stable runtime reads (the
// LocalAppData known folder, the runtime folder's ACLs) for a managed call
// too, before its answer watchdog was armed, although their result answers
// nothing for it. A managed call must leave main without them.
func TestManagedHookLeavesMainWithoutThePerUserRuntimeReads(t *testing.T) {
	release := make(chan struct{})
	var once sync.Once
	unblock := func() { once.Do(func() { close(release) }) }
	t.Cleanup(unblock)
	stalled := func(string) (hookruntime.State, bool, error) {
		<-release // a read the repair holds
		return hookruntime.State{}, false, nil
	}
	stubNativeDelegatedHookRuntimeReader(t, stalled)
	stubNativeHookRuntimeReader(t, stalled)
	savedArgs := os.Args
	t.Cleanup(func() { os.Args = savedArgs })
	os.Args = []string{savedArgs[0], "hook", "--connector", "claudecode", "--enterprise-managed"}

	done := make(chan bool, 1)
	go func() { done <- NativeHookRuntimeNoop() }()
	select {
	case noop := <-done:
		if noop {
			t.Fatal("the managed call ended as a no-op")
		}
	case <-time.After(2 * time.Second):
		unblock()
		<-done
		t.Fatal("the managed call waited in main on the per-user runtime reads, before its answer watchdog")
	}
	if _, _, _, prepared := preparedNativeHookRuntime(nativeHookExecutable()); prepared {
		t.Fatal("a managed call prepared the per-user runtime snapshot")
	}
}

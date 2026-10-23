// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package connector

import (
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"
)

// An earlier gateway can render its hooks again after the installer's
// refresh and before it exits: a 1.0.x Windows Codex registration check
// rewrites the open it resolved in hooks/.hookcfg. The hook it leaves would
// follow that open while the gateway is down for the swap. The hold keeps
// the sidecar lock every release's writer takes, so the old writer waits
// and the sidecar stays closed until the gateway has exited and the second
// refresh has run.
func TestHoldHookFailModesKeepsAnOldGatewaysRenderOutUntilItExits(t *testing.T) {
	hookDir := t.TempDir()
	// What a 1.0.2 gateway rendered for Codex in observe with no mode set.
	if err := os.WriteFile(filepath.Join(hookDir, hookConfigSidecarName),
		[]byte(`{"version":2,"gateway_addr":"127.0.0.1:18970","fail_modes":{"codex":"open"}}`+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	contended := make(chan struct{}, 1)
	setFileLockContendedHookForTest(t, func(lockPath string) {
		if filepath.Base(lockPath) == hookConfigSidecarName+".lock" {
			select {
			case contended <- struct{}{}:
			default:
			}
		}
	})
	var running atomic.Bool
	running.Store(true)
	held := make(chan HookFailModeRefresh, 1)
	done := make(chan error, 1)
	go func() {
		_, err := HoldHookFailModes(hookDir, func(string) string { return "closed" },
			func(first HookFailModeRefresh) { held <- first }, running.Load, time.Minute)
		done <- err
	}()
	select {
	case first := <-held:
		if len(first.Sidecar) != 1 || first.Sidecar[0] != "codex" {
			t.Fatalf("first refresh %+v", first)
		}
	case err := <-done:
		t.Fatalf("the hold ended before it held: %v", err)
	case <-time.After(30 * time.Second):
		t.Fatal("the hold did not take the lock")
	}
	if state := readHookConfigSidecarForTest(t, hookDir); state.FailModes["codex"] != "closed" {
		t.Fatalf("after the first refresh codex = %q", state.FailModes["codex"])
	}

	// The old gateway renders its open again while it stops (it records no
	// source, as 1.0.2 did).
	rewrote := make(chan error, 1)
	go func() {
		rewrote <- writeHookConfigSidecarUsing(hookDir, "127.0.0.1:18970", "codex", "open", "", false, hookRuntimeFileWriter(false))
	}()
	select {
	case <-contended:
	case err := <-rewrote:
		t.Fatalf("the old gateway wrote past the hold: %v", err)
	case <-time.After(30 * time.Second):
		t.Fatal("the old gateway's writer never reached the lock")
	}
	if state := readHookConfigSidecarForTest(t, hookDir); state.FailModes["codex"] != "closed" {
		t.Fatalf("while the old gateway stops codex = %q, want closed", state.FailModes["codex"])
	}

	// The gateway exits. In this test its writer lives on and writes once the
	// hold lets go; a writer in an exited gateway never does.
	running.Store(false)
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(30 * time.Second):
		t.Fatal("the hold did not end after the gateway exited")
	}
	if err := <-rewrote; err != nil {
		t.Fatal(err)
	}
}

// A gateway that is still running at the deadline: the hold refreshes once
// more, lets go and says so.
func TestHoldHookFailModesGivesUpAtItsDeadline(t *testing.T) {
	hookDir := t.TempDir()
	if err := os.WriteFile(filepath.Join(hookDir, hookConfigSidecarName),
		[]byte(`{"version":2,"gateway_addr":"127.0.0.1:18970","fail_modes":{"codex":"open"}}`+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	calls := 0
	_, err := HoldHookFailModes(hookDir, func(string) string { calls++; return "closed" }, nil,
		func() bool { return true }, 50*time.Millisecond)
	if err == nil {
		t.Fatal("a gateway still running at the deadline is not reported")
	}
	if state := readHookConfigSidecarForTest(t, hookDir); state.FailModes["codex"] != "closed" {
		t.Fatalf("codex = %q, want closed", state.FailModes["codex"])
	}
	if calls == 0 {
		t.Fatal("the hold never asked for the modes")
	}
	// The lock is free again.
	if err := writeHookConfigSidecar(hookDir, "127.0.0.1:18970", "codex", "closed", false); err != nil {
		t.Fatal(err)
	}
}

// No hook directory: nothing to hold, and the caller still hears it is held.
func TestHoldHookFailModesWithoutHooks(t *testing.T) {
	heard := false
	if _, err := HoldHookFailModes(filepath.Join(t.TempDir(), "hooks"), func(string) string { return "closed" },
		func(HookFailModeRefresh) { heard = true }, func() bool { return true }, time.Minute); err != nil {
		t.Fatal(err)
	}
	if !heard {
		t.Fatal("held was not called")
	}
}

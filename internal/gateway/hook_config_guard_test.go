// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/gateway/connector"
)

const guardTestDebounce = 40 * time.Millisecond

// installedCursorConnector wires the cursor connector to a temp config path,
// runs its initial Setup, and returns the connector, opts, and resolved config
// path. The path override is reset on cleanup.
func installedCursorConnector(t *testing.T) (connector.Connector, connector.SetupOpts, string) {
	t.Helper()
	cfgPath := filepath.Join(t.TempDir(), "hooks.json")
	prev := connector.CursorHooksPathOverride
	connector.CursorHooksPathOverride = cfgPath
	t.Cleanup(func() { connector.CursorHooksPathOverride = prev })

	opts := connector.SetupOpts{
		DataDir:      t.TempDir(),
		APIAddr:      "127.0.0.1:18970",
		APIToken:     "tok-test",
		WorkspaceDir: t.TempDir(),
	}
	conn := connector.NewCursorConnector()
	if err := conn.Setup(context.Background(), opts); err != nil {
		t.Fatalf("cursor Setup: %v", err)
	}
	return conn, opts, cfgPath
}

func installedWindsurfConnector(t *testing.T) (connector.Connector, connector.SetupOpts, string) {
	t.Helper()
	cfgPath := filepath.Join(t.TempDir(), "hooks.json")
	prev := connector.WindsurfHooksPathOverride
	connector.WindsurfHooksPathOverride = cfgPath
	t.Cleanup(func() { connector.WindsurfHooksPathOverride = prev })

	opts := connector.SetupOpts{
		DataDir:      t.TempDir(),
		APIAddr:      "127.0.0.1:18970",
		APIToken:     "tok-test",
		WorkspaceDir: t.TempDir(),
	}
	conn := connector.NewWindsurfConnector()
	if err := conn.Setup(context.Background(), opts); err != nil {
		t.Fatalf("windsurf Setup: %v", err)
	}
	return conn, opts, cfgPath
}

func waitForPresence(t *testing.T, conn connector.Connector, opts connector.SetupOpts, want bool, timeout time.Duration) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		present, err := connector.OwnedHooksPresent(conn, opts)
		if err == nil && present == want {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	present, err := connector.OwnedHooksPresent(conn, opts)
	t.Fatalf("timed out waiting for OwnedHooksPresent==%v (last present=%v err=%v)", want, present, err)
}

func TestHookConfigGuard_RestoresDeletedHookBlock(t *testing.T) {
	conn, opts, cfgPath := installedCursorConnector(t)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	guard := NewHookConfigGuard(nil, nil, guardTestDebounce)
	guard.Start(ctx, conn, opts)
	defer guard.Stop()

	waitForPresence(t, conn, opts, true, time.Second)

	// Simulate a user deleting the DefenseClaw hook block.
	if err := os.WriteFile(cfgPath, []byte("{}\n"), 0o600); err != nil {
		t.Fatalf("strip hook block: %v", err)
	}

	// The guard should re-install it within a few debounce cycles.
	waitForPresence(t, conn, opts, true, 3*time.Second)
}

func TestHookConfigGuard_RecreatesDeletedFile(t *testing.T) {
	conn, opts, cfgPath := installedCursorConnector(t)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	guard := NewHookConfigGuard(nil, nil, guardTestDebounce)
	guard.Start(ctx, conn, opts)
	defer guard.Stop()

	waitForPresence(t, conn, opts, true, time.Second)

	if err := os.Remove(cfgPath); err != nil {
		t.Fatalf("remove config file: %v", err)
	}

	waitForPresence(t, conn, opts, true, 3*time.Second)
	if _, err := os.Stat(cfgPath); err != nil {
		t.Fatalf("config file not recreated: %v", err)
	}
}

func TestHookConfigGuard_IgnoresUnrelatedEdits(t *testing.T) {
	conn, opts, cfgPath := installedCursorConnector(t)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	guard := NewHookConfigGuard(nil, nil, guardTestDebounce)
	guard.Start(ctx, conn, opts)
	defer guard.Stop()

	waitForPresence(t, conn, opts, true, time.Second)

	// Edit an unrelated top-level key while keeping the hook block intact.
	data, err := os.ReadFile(cfgPath)
	if err != nil {
		t.Fatalf("read config: %v", err)
	}
	var cfg map[string]interface{}
	if err := json.Unmarshal(data, &cfg); err != nil {
		t.Fatalf("unmarshal config: %v", err)
	}
	cfg["_dc_test_unrelated"] = "keepme"
	edited, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		t.Fatalf("marshal config: %v", err)
	}
	if err := os.WriteFile(cfgPath, edited, 0o600); err != nil {
		t.Fatalf("write edited config: %v", err)
	}

	// Give the guard several debounce cycles to (incorrectly) react.
	time.Sleep(20 * guardTestDebounce)

	// Hooks must still be present, the unrelated key must survive, and the
	// guard must not have rewritten the file (no churn on legitimate edits).
	present, err := connector.OwnedHooksPresent(conn, opts)
	if err != nil {
		t.Fatalf("OwnedHooksPresent: %v", err)
	}
	if !present {
		t.Fatal("hooks no longer present after unrelated edit")
	}
	after, err := os.ReadFile(cfgPath)
	if err != nil {
		t.Fatalf("re-read config: %v", err)
	}
	if string(after) != string(edited) {
		t.Fatalf("guard rewrote config on an unrelated edit:\nwant:\n%s\ngot:\n%s", edited, after)
	}
	var afterCfg map[string]interface{}
	if err := json.Unmarshal(after, &afterCfg); err != nil {
		t.Fatalf("unmarshal after: %v", err)
	}
	if afterCfg["_dc_test_unrelated"] != "keepme" {
		t.Fatal("unrelated key was clobbered by the guard")
	}
}

func TestHookConfigGuard_DisabledDoesNotHeal(t *testing.T) {
	// Mirrors guardrail.hook_self_heal=false: the guard is never started,
	// so a manual deletion is NOT restored.
	conn, opts, cfgPath := installedCursorConnector(t)

	if err := os.WriteFile(cfgPath, []byte("{}\n"), 0o600); err != nil {
		t.Fatalf("strip hook block: %v", err)
	}
	time.Sleep(20 * guardTestDebounce)

	present, err := connector.OwnedHooksPresent(conn, opts)
	if err != nil {
		t.Fatalf("OwnedHooksPresent: %v", err)
	}
	if present {
		t.Fatal("hook block restored even though no guard was started")
	}
}

func TestHookConfigGuard_NotifierFiresOnHeal(t *testing.T) {
	conn, opts, cfgPath := installedCursorConnector(t)

	type healCall struct {
		name  string
		paths []string
	}
	calls := make(chan healCall, 4)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	guard := NewHookConfigGuard(nil, nil, guardTestDebounce)
	guard.SetHealNotifier(func(name string, paths []string) {
		calls <- healCall{name: name, paths: paths}
	})
	guard.Start(ctx, conn, opts)
	defer guard.Stop()

	waitForPresence(t, conn, opts, true, time.Second)

	if err := os.WriteFile(cfgPath, []byte("{}\n"), 0o600); err != nil {
		t.Fatalf("strip hook block: %v", err)
	}
	waitForPresence(t, conn, opts, true, 3*time.Second)

	select {
	case got := <-calls:
		if got.name != conn.Name() {
			t.Errorf("notifier connector name = %q, want %q", got.name, conn.Name())
		}
		if len(got.paths) == 0 {
			t.Error("notifier received no changed paths")
		} else if got.paths[0] != cfgPath {
			t.Errorf("notifier path = %q, want %q", got.paths[0], cfgPath)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("heal notifier did not fire after a successful re-install")
	}
}

func TestHookConfigGuard_SuppressHealingPausesThenResumes(t *testing.T) {
	conn, opts, cfgPath := installedCursorConnector(t)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	guard := NewHookConfigGuard(nil, nil, guardTestDebounce)
	guard.Start(ctx, conn, opts)
	defer guard.Stop()
	waitForPresence(t, conn, opts, true, time.Second)

	// Suppress healing, then strip the hook block. The deletion lands
	// inside the suppression window and must NOT be auto-restored.
	const window = 600 * time.Millisecond
	guard.SuppressHealing(window)
	if err := os.WriteFile(cfgPath, []byte("{}\n"), 0o600); err != nil {
		t.Fatalf("strip hook block: %v", err)
	}

	// Mid-window: the guard must still be holding off.
	time.Sleep(window / 2)
	present, err := connector.OwnedHooksPresent(conn, opts)
	if err != nil {
		t.Fatalf("OwnedHooksPresent: %v", err)
	}
	if present {
		t.Fatal("hook restored during the suppression window; SuppressHealing did not pause healing")
	}

	// After the window elapses a fresh edit must be healed again, proving
	// suppression is temporary and not a permanent disable.
	time.Sleep(window)
	if err := os.WriteFile(cfgPath, []byte("{}\n"), 0o600); err != nil {
		t.Fatalf("re-strip hook block after window: %v", err)
	}
	waitForPresence(t, conn, opts, true, 3*time.Second)
}

func TestHookConfigGuard_RepointFollowsConnectorSwitch(t *testing.T) {
	cursorConn, cursorOpts, cursorPath := installedCursorConnector(t)
	windsurfConn, windsurfOpts, windsurfPath := installedWindsurfConnector(t)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	guard := NewHookConfigGuard(nil, nil, guardTestDebounce)
	guard.Start(ctx, cursorConn, cursorOpts)
	defer guard.Stop()
	waitForPresence(t, cursorConn, cursorOpts, true, time.Second)

	// Switch the guard to the windsurf connector.
	guard.Repoint(windsurfConn, windsurfOpts)

	// Deleting windsurf's hook block is now healed.
	if err := os.WriteFile(windsurfPath, []byte("{}\n"), 0o600); err != nil {
		t.Fatalf("strip windsurf hook block: %v", err)
	}
	waitForPresence(t, windsurfConn, windsurfOpts, true, 3*time.Second)

	// Deleting the previous connector's hook block is NOT healed: the guard
	// repointed away from it.
	if err := os.WriteFile(cursorPath, []byte("{}\n"), 0o600); err != nil {
		t.Fatalf("strip cursor hook block: %v", err)
	}
	time.Sleep(20 * guardTestDebounce)
	present, err := connector.OwnedHooksPresent(cursorConn, cursorOpts)
	if err != nil {
		t.Fatalf("OwnedHooksPresent cursor: %v", err)
	}
	if present {
		t.Fatal("cursor hook block restored after the guard repointed to windsurf")
	}
}

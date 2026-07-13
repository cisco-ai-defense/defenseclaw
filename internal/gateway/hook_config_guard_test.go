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

	"github.com/defenseclaw/defenseclaw/internal/audit"
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

func TestHookConfigGuard_ContinuesAfterWatcherReplacement(t *testing.T) {
	conn, opts, cfgPath := installedCursorConnector(t)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	guard := NewHookConfigGuard(nil, nil, time.Hour)
	guard.Start(ctx, conn, opts)
	defer guard.Stop()

	// Prove the run loop consumed an event from the original watcher before
	// replacing it. The long debounce keeps the event pending and the loop
	// blocked on that watcher's channels.
	if err := os.WriteFile(cfgPath, []byte("{}\n"), 0o600); err != nil {
		t.Fatalf("trigger original watcher: %v", err)
	}
	deadline := time.Now().Add(3 * time.Second)
	for {
		guard.mu.Lock()
		pending := len(guard.pending)
		guard.mu.Unlock()
		if pending > 0 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("original watcher event was not consumed")
		}
		time.Sleep(10 * time.Millisecond)
	}
	time.Sleep(2 * guardTestDebounce)

	guard.mu.Lock()
	original := guard.fsw
	guard.resyncTargetsLocked(conn, opts)
	replacement := guard.fsw
	guard.pending = map[string]time.Time{}
	guard.mu.Unlock()
	if replacement == original {
		t.Fatal("resync did not replace the filesystem watcher")
	}

	select {
	case <-guard.done:
		t.Fatal("guard stopped when the superseded watcher channels closed")
	case <-time.After(4 * guardTestDebounce):
	}

	// The replacement watcher must remain live and consume a fresh event.
	if err := os.WriteFile(cfgPath, []byte("{\"replacement\":true}\n"), 0o600); err != nil {
		t.Fatalf("trigger replacement watcher: %v", err)
	}
	deadline = time.Now().Add(3 * time.Second)
	for {
		guard.mu.Lock()
		pending := len(guard.pending)
		guard.mu.Unlock()
		if pending > 0 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("replacement watcher event was not consumed")
		}
		time.Sleep(10 * time.Millisecond)
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

// TestHookConfigGuard_HealAuditRowsCarryConnectorAndSeverity locks in the
// connector-attribution contract for the self-heal audit rows. Regression
// guard for the gap where heal rows used the bare LogAction helper so the
// connector name only reached the `target` column and the dedicated
// `connector` column stayed empty. Both the tamper and repair rows must carry
// the connector column so SIEM consumers can filter by connector. Severity is
// deliberately left at the logger default (INFO) — the original severity of
// these rows is not the multi-connector feature's to redesign.
func TestHookConfigGuard_HealAuditRowsCarryConnector(t *testing.T) {
	conn, opts, cfgPath := installedCursorConnector(t)

	store, err := audit.NewStore(filepath.Join(t.TempDir(), "audit.db"))
	if err != nil {
		t.Fatalf("audit.NewStore: %v", err)
	}
	if err := store.Init(); err != nil {
		t.Fatalf("store.Init: %v", err)
	}
	t.Cleanup(func() { _ = store.Close() })
	logger := audit.NewLogger(store)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	guard := NewHookConfigGuard(logger, nil, guardTestDebounce)
	guard.Start(ctx, conn, opts)
	defer guard.Stop()

	waitForPresence(t, conn, opts, true, time.Second)
	if err := os.WriteFile(cfgPath, []byte("{}\n"), 0o600); err != nil {
		t.Fatalf("strip hook block: %v", err)
	}
	waitForPresence(t, conn, opts, true, 3*time.Second)

	// The audit rows are written inside heal() around the presence flip;
	// poll briefly so the assertion does not race the heal's DB writes.
	var tampered, repaired *audit.Event
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		events, err := store.ListEvents(50)
		if err != nil {
			t.Fatalf("ListEvents: %v", err)
		}
		tampered, repaired = nil, nil
		for i := range events {
			switch events[i].Action {
			case string(audit.ActionConnectorHookTampered):
				tampered = &events[i]
			case string(audit.ActionConnectorHookRepaired):
				repaired = &events[i]
			}
		}
		if tampered != nil && repaired != nil {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}

	if tampered == nil {
		t.Fatal("no connector-hook-tampered audit row was written")
	}
	if repaired == nil {
		t.Fatal("no connector-hook-repaired audit row was written")
	}
	for _, ev := range []*audit.Event{tampered, repaired} {
		if ev.Connector != conn.Name() {
			t.Errorf("%s row connector column = %q, want %q", ev.Action, ev.Connector, conn.Name())
		}
		// Severity is intentionally the logger default (INFO), not an
		// elevated level — the multi-connector work adds the connector
		// dimension without redesigning the original severity.
		if ev.Severity != "INFO" {
			t.Errorf("%s row severity = %q, want INFO (default; not redesigned)", ev.Action, ev.Severity)
		}
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

func TestHookConfigGuard_DoesNotReportRepairWhenClaudePolicyStillDisablesHooks(t *testing.T) {
	settingsDir := filepath.Join(t.TempDir(), "claude")
	settingsPath := filepath.Join(settingsDir, "settings.json")
	previous := connector.ClaudeCodeSettingsPathOverride
	connector.ClaudeCodeSettingsPathOverride = settingsPath
	t.Cleanup(func() { connector.ClaudeCodeSettingsPathOverride = previous })
	opts := connector.SetupOpts{DataDir: t.TempDir(), APIAddr: "127.0.0.1:18970", APIToken: "tok-test"}
	conn := connector.NewClaudeCodeConnector()
	if err := os.MkdirAll(settingsDir, 0o700); err != nil {
		t.Fatalf("create Claude settings directory: %v", err)
	}
	if err := conn.Setup(context.Background(), opts); err != nil {
		t.Fatalf("Claude Code Setup: %v", err)
	}
	data, err := os.ReadFile(settingsPath)
	if err != nil {
		t.Fatal(err)
	}
	var settings map[string]interface{}
	if err := json.Unmarshal(data, &settings); err != nil {
		t.Fatal(err)
	}
	settings["disableAllHooks"] = true
	out, err := json.MarshalIndent(settings, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(settingsPath, out, 0o600); err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	guard := NewHookConfigGuard(nil, nil, guardTestDebounce)
	notified := make(chan struct{}, 1)
	guard.SetHealNotifier(func(string, []string) { notified <- struct{}{} })
	guard.Start(ctx, conn, opts)
	t.Cleanup(guard.Stop)

	// Queue a target-file removal and then replace its watched directory
	// before the debounce fires. Setup must recreate the owned hooks while
	// preserving the disabling setting, so verification still fails.
	if err := os.Remove(settingsPath); err != nil {
		t.Fatalf("remove Claude settings: %v", err)
	}
	if err := os.RemoveAll(settingsDir); err != nil {
		t.Fatalf("remove watched Claude directory: %v", err)
	}
	if err := os.MkdirAll(settingsDir, 0o700); err != nil {
		t.Fatalf("recreate Claude directory: %v", err)
	}
	if err := os.WriteFile(settingsPath, []byte("{\"disableAllHooks\":true}\n"), 0o600); err != nil {
		t.Fatalf("restore disabled Claude settings: %v", err)
	}

	deadline := time.Now().Add(3 * time.Second)
	for {
		data, readErr := os.ReadFile(settingsPath)
		var current map[string]interface{}
		if readErr == nil && json.Unmarshal(data, &current) == nil {
			_, hooksRestored := current["hooks"].(map[string]interface{})
			if hooksRestored && current["disableAllHooks"] == true {
				break
			}
		}
		if time.Now().After(deadline) {
			t.Fatalf("guard did not attempt the policy-blocked repair (readErr=%v settings=%v)", readErr, current)
		}
		time.Sleep(20 * time.Millisecond)
	}

	select {
	case <-notified:
		t.Fatal("guard reported a repair even though Claude Code still disables all hooks")
	default:
	}

	// The failed verification must not strand the watcher on the deleted
	// directory object. Let the normal self-write suppression expire, then
	// remove the policy and strip the hooks; the running guard must observe and
	// heal this edit.
	guard.mu.Lock()
	suppressedUntil := guard.suppressUntil
	guard.mu.Unlock()
	if remaining := time.Until(suppressedUntil) + 2*guardTestDebounce; remaining > 0 {
		time.Sleep(remaining)
	}
	if err := os.WriteFile(settingsPath, []byte("{}\n"), 0o600); err != nil {
		t.Fatalf("remove Claude policy and hooks: %v", err)
	}
	deadline = time.Now().Add(3 * time.Second)
	for {
		present, presenceErr := connector.OwnedHooksPresent(conn, opts)
		if presenceErr == nil && present {
			break
		}
		if time.Now().After(deadline) {
			data, _ := os.ReadFile(settingsPath)
			guard.mu.Lock()
			pending := len(guard.pending)
			suppressedUntil := guard.suppressUntil
			watchList := guard.fsw.WatchList()
			started := guard.started
			guard.mu.Unlock()
			t.Fatalf(
				"guard did not heal subsequent edit (err=%v started=%v pending=%d suppressedUntil=%s watches=%v settings=%s)",
				presenceErr,
				started,
				pending,
				suppressedUntil.Format(time.RFC3339Nano),
				watchList,
				data,
			)
		}
		time.Sleep(20 * time.Millisecond)
	}
	select {
	case <-notified:
	case <-time.After(2 * time.Second):
		t.Fatal("guard did not report the subsequent successful repair")
	}

	guard.Stop()
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

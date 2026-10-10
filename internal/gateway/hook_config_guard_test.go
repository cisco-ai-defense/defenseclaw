// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/audit"
	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/gateway/connector"
	"github.com/defenseclaw/defenseclaw/internal/observability"
	"github.com/defenseclaw/defenseclaw/internal/testenv"
)

const guardTestDebounce = 40 * time.Millisecond

type runtimePolicyCaptureConnector struct {
	stubConnector
	configPath   string
	mu           sync.Mutex
	setupCalls   int
	lastOpts     connector.SetupOpts
	setupStarted chan struct{}
	releaseSetup <-chan struct{}
}

func (c *runtimePolicyCaptureConnector) Setup(_ context.Context, opts connector.SetupOpts) error {
	c.mu.Lock()
	c.setupCalls++
	c.lastOpts = opts
	started := c.setupStarted
	release := c.releaseSetup
	c.mu.Unlock()
	if started != nil {
		select {
		case started <- struct{}{}:
		default:
		}
	}
	if release != nil {
		<-release
	}
	payload := fmt.Sprintf("{\"command\":\"managed-hook --fail-mode %s\"}\n", opts.HookFailMode)
	return os.WriteFile(c.configPath, []byte(payload), 0o600)
}

func (c *runtimePolicyCaptureConnector) HookCapabilities(connector.SetupOpts) connector.HookCapability {
	return connector.HookCapability{ConfigPath: c.configPath}
}

func (*runtimePolicyCaptureConnector) HookConfigReferenceNeedles(opts connector.SetupOpts) []string {
	return []string{fmt.Sprintf("managed-hook --fail-mode %s", opts.HookFailMode)}
}

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

func installedDevinConnector(t *testing.T) (connector.Connector, connector.SetupOpts, string) {
	t.Helper()
	cfgPath := filepath.Join(t.TempDir(), "config.json")
	prev := connector.DevinHooksPathOverride
	connector.DevinHooksPathOverride = cfgPath
	t.Cleanup(func() { connector.DevinHooksPathOverride = prev })

	opts := connector.SetupOpts{
		DataDir:      t.TempDir(),
		APIAddr:      "127.0.0.1:18970",
		APIToken:     "tok-test",
		WorkspaceDir: t.TempDir(),
	}
	conn := connector.NewDevinConnector()
	if err := conn.Setup(context.Background(), opts); err != nil {
		t.Fatalf("devin Setup: %v", err)
	}
	return conn, opts, cfgPath
}

func requireOwnedHooks(t *testing.T, conn connector.Connector, opts connector.SetupOpts) {
	t.Helper()
	if present, err := connector.OwnedHooksPresent(conn, opts); err != nil || !present {
		t.Fatalf("OwnedHooksPresent = %v, %v; want true", present, err)
	}
}

// observeRepairs subscribes to the guard's repair outcomes. Waiting on them,
// rather than polling the config, keeps the test from holding the file open
// while the guard's Setup replaces it.
func observeRepairs(guard *HookConfigGuard) <-chan hookGuardRepairOutcome {
	outcomes := make(chan hookGuardRepairOutcome, 16)
	guard.mu.Lock()
	guard.repairObserver = func(outcome hookGuardRepairOutcome) {
		select {
		case outcomes <- outcome:
		default:
		}
	}
	guard.mu.Unlock()
	return outcomes
}

// waitForRepair blocks until the guard completes a repair and then verifies
// the restored hook contract. A busy-file failure re-arms the guard, so it
// keeps waiting; any other failure is final. The wait is bounded only by the
// go test timeout.
func waitForRepair(t *testing.T, outcomes <-chan hookGuardRepairOutcome, conn connector.Connector, opts connector.SetupOpts) hookGuardRepairOutcome {
	t.Helper()
	for {
		outcome := <-outcomes
		if outcome.err == nil {
			requireOwnedHooks(t, conn, opts)
			return outcome
		}
		if !outcome.rearmed {
			t.Fatalf("hook guard repair failed without re-arming: %v", outcome.err)
		}
	}
}

func TestHookConfigGuard_RestoresDeletedHookBlock(t *testing.T) {
	conn, opts, cfgPath := installedCursorConnector(t)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	guard := NewHookConfigGuard(nil, nil, guardTestDebounce)
	repairs := observeRepairs(guard)
	guard.Start(ctx, conn, opts)
	defer guard.Stop()

	requireOwnedHooks(t, conn, opts)

	// Simulate a user deleting the DefenseClaw hook block.
	if err := os.WriteFile(cfgPath, []byte("{}\n"), 0o600); err != nil {
		t.Fatalf("strip hook block: %v", err)
	}

	waitForRepair(t, repairs, conn, opts)
}

func TestHookConfigGuard_RecreatesDeletedFile(t *testing.T) {
	conn, opts, cfgPath := installedCursorConnector(t)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	guard := NewHookConfigGuard(nil, nil, guardTestDebounce)
	repairs := observeRepairs(guard)
	guard.Start(ctx, conn, opts)
	defer guard.Stop()

	requireOwnedHooks(t, conn, opts)

	if err := os.Remove(cfgPath); err != nil {
		t.Fatalf("remove config file: %v", err)
	}

	waitForRepair(t, repairs, conn, opts)
	if _, err := os.Stat(cfgPath); err != nil {
		t.Fatalf("config file not recreated: %v", err)
	}
}

func TestHookConfigGuardRepairUsesCurrentRuntimePolicy(t *testing.T) {
	root := t.TempDir()
	configPath := filepath.Join(root, "hooks.json")
	conn := &runtimePolicyCaptureConnector{
		stubConnector: stubConnector{name: "policy-capture"},
		configPath:    configPath,
	}
	cached := connector.SetupOpts{
		DataDir:      root,
		HookFailMode: "open",
	}
	if err := conn.Setup(context.Background(), cached); err != nil {
		t.Fatalf("initial Setup: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	guard := NewHookConfigGuard(nil, nil, time.Hour)
	if !guard.Start(ctx, conn, cached) {
		t.Fatal("hook registration guard did not start")
	}
	defer guard.Stop()

	if err := os.WriteFile(configPath, []byte("{}\n"), 0o600); err != nil {
		t.Fatalf("remove managed registration: %v", err)
	}
	sidecar := &Sidecar{}
	sidecar.bindHookRuntimePolicyResolver(guard)
	conn.mu.Lock()
	before := conn.setupCalls
	conn.mu.Unlock()
	if err := guard.EnsurePresent(ctx, conn.Name(), root, "test missing policy"); err == nil ||
		!strings.Contains(err.Error(), "authoritative hook runtime policy is unavailable") {
		t.Fatalf("missing runtime policy error = %v", err)
	}
	conn.mu.Lock()
	if conn.setupCalls != before {
		conn.mu.Unlock()
		t.Fatal("guard repaired with cached policy after current policy became unavailable")
	}
	conn.mu.Unlock()

	live := config.DefaultConfig()
	live.DataDir = root
	live.Guardrail.Mode = "action"
	live.Guardrail.HookFailMode = "closed"
	live.Guardrail.HILT.Enabled = true
	sidecar.publishConfig(live)
	if err := guard.EnsurePresent(ctx, conn.Name(), root, "test current policy"); err != nil {
		t.Fatalf("repair with current runtime policy: %v", err)
	}
	conn.mu.Lock()
	last := conn.lastOpts
	conn.mu.Unlock()
	if last.HookFailMode != "closed" || last.GuardrailMode != "action" || !last.HILTEnabled {
		t.Fatalf(
			"repair posture = mode:%q fail:%q hilt:%t, want action/closed/true",
			last.GuardrailMode, last.HookFailMode, last.HILTEnabled,
		)
	}

	stale := cloneConfig(live)
	stale.Guardrail.Mode = "observe"
	stale.Guardrail.HookFailMode = "open"
	stale.Guardrail.HILT.Enabled = false
	sidecar.publishConfig(stale)
	guard.mu.Lock()
	guard.suppressUntil = time.Time{}
	guard.mu.Unlock()
	if err := os.WriteFile(configPath, []byte("{}\n"), 0o600); err != nil {
		t.Fatalf("remove managed registration before concurrent reload: %v", err)
	}
	setupStarted := make(chan struct{}, 1)
	releaseSetup := make(chan struct{})
	var releaseSetupOnce sync.Once
	releaseBlockedSetup := func() {
		releaseSetupOnce.Do(func() { close(releaseSetup) })
	}
	// Keep a failed scheduler/timing assertion from deadlocking guard.Stop on
	// the deliberately blocked Setup call during package-wide parallel runs.
	t.Cleanup(releaseBlockedSetup)
	conn.mu.Lock()
	conn.setupStarted = setupStarted
	conn.releaseSetup = releaseSetup
	conn.mu.Unlock()
	repairDone := make(chan error, 1)
	go func() {
		repairDone <- guard.EnsurePresent(ctx, conn.Name(), root, "test concurrent reload")
	}()
	select {
	case <-setupStarted:
	case <-time.After(5 * time.Second):
		t.Fatal("stale-policy repair did not enter Setup")
	}
	publishStarted := make(chan struct{})
	publishDone := make(chan struct{})
	go func() {
		close(publishStarted)
		sidecar.publishConfig(live)
		close(publishDone)
	}()
	<-publishStarted
	select {
	case <-publishDone:
		t.Fatal("new runtime policy published before the old-policy repair lease completed")
	case <-time.After(50 * time.Millisecond):
	}
	releaseBlockedSetup()
	if err := <-repairDone; err != nil {
		t.Fatalf("stale-policy repair: %v", err)
	}
	select {
	case <-publishDone:
	case <-time.After(time.Second):
		t.Fatal("new runtime policy did not publish after the repair lease completed")
	}
	guard.mu.Lock()
	guard.suppressUntil = time.Time{}
	guard.mu.Unlock()
	if err := guard.EnsurePresent(ctx, conn.Name(), root, "test after concurrent reload"); err != nil {
		t.Fatalf("current-policy repair after publication: %v", err)
	}
	conn.mu.Lock()
	conn.setupStarted = nil
	conn.releaseSetup = nil
	last = conn.lastOpts
	conn.mu.Unlock()
	if last.HookFailMode != "closed" || last.GuardrailMode != "action" || !last.HILTEnabled {
		t.Fatalf(
			"post-publication registration = mode:%q fail:%q hilt:%t, want action/closed/true",
			last.GuardrailMode, last.HookFailMode, last.HILTEnabled,
		)
	}
}

// failModeBakedConnector keeps its registration independent of the hook fail
// mode, like the real hook connectors: the mode lives in the generated script,
// so a stale mode leaves the registration present.
type failModeBakedConnector struct{ runtimePolicyCaptureConnector }

func (c *failModeBakedConnector) Setup(_ context.Context, opts connector.SetupOpts) error {
	c.mu.Lock()
	c.setupCalls++
	c.mu.Unlock()
	return os.WriteFile(c.configPath, fmt.Appendf(nil, "{\"command\":\"managed-hook\",\"failMode\":%q}\n", opts.HookFailMode), 0o600)
}

func (*failModeBakedConnector) HookConfigReferenceNeedles(connector.SetupOpts) []string {
	return []string{"managed-hook"}
}

// TestHookConfigGuardRefreshPolicyRerendersStaleFailMode pins GAP-0029:
// guardrail.mode action implies the global (closed) hook fail mode, and the
// rendered hooks follow it without a restart; nothing re-renders when the
// effective fail mode is unchanged.
func TestHookConfigGuardRefreshPolicyRerendersStaleFailMode(t *testing.T) {
	root := t.TempDir()
	configPath := filepath.Join(root, "hooks.json")
	conn := &failModeBakedConnector{runtimePolicyCaptureConnector{
		stubConnector: stubConnector{name: "baked-mode"},
		configPath:    configPath,
	}}
	cached := connector.SetupOpts{DataDir: root, HookFailMode: "open"}
	if err := conn.Setup(context.Background(), cached); err != nil {
		t.Fatalf("initial Setup: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	guard := NewHookConfigGuard(nil, nil, time.Hour)
	if !guard.Start(ctx, conn, cached) {
		t.Fatal("hook registration guard did not start")
	}
	defer guard.Stop()
	sidecar := &Sidecar{}
	sidecar.bindHookRuntimePolicyResolver(guard)
	setupCalls := func() int {
		conn.mu.Lock()
		defer conn.mu.Unlock()
		return conn.setupCalls
	}

	live := config.DefaultConfig()
	live.DataDir = root
	live.Guardrail.Mode = "observe"
	live.Guardrail.HookFailMode = "closed"
	sidecar.publishConfig(live)
	before := setupCalls()
	if err := guard.RefreshPolicy(ctx); err != nil || setupCalls() != before {
		t.Fatalf("observe mode (fail open, as rendered): err=%v, Setup calls %d -> %d, want none", err, before, setupCalls())
	}

	action := cloneConfig(live)
	action.Guardrail.Mode = "action"
	sidecar.publishConfig(action)
	if err := guard.RefreshPolicy(ctx); err != nil {
		t.Fatalf("refresh after guardrail.mode action: %v", err)
	}
	if setupCalls() != before+1 {
		t.Fatalf("Setup calls = %d, want %d (one re-render)", setupCalls(), before+1)
	}
	if body, err := os.ReadFile(configPath); err != nil || !strings.Contains(string(body), `"failMode":"closed"`) {
		t.Fatalf("rendered hooks = %q (%v), want fail mode closed", body, err)
	}
	if lock := connector.LoadHookContractLockEntry(root, conn.Name()); lock.HookFailMode != "closed" {
		t.Fatalf("hook contract lock fail mode = %q, want closed (doctor compares it with the rendered hooks)", lock.HookFailMode)
	}
	if err := guard.RefreshPolicy(ctx); err != nil || setupCalls() != before+1 {
		t.Fatalf("second refresh: err=%v, Setup calls %d, want %d", err, setupCalls(), before+1)
	}

	// A mode change inside the suppression window of that re-render is
	// applied when the window ends, not dropped (GAP-0317).
	guard.mu.Lock()
	guard.suppressUntil = time.Now().Add(100 * time.Millisecond)
	guard.mu.Unlock()
	sidecar.publishConfig(live)
	if err := guard.RefreshPolicy(ctx); err != nil || setupCalls() != before+2 {
		t.Fatalf("refresh inside the suppression window: err=%v, Setup calls %d, want %d", err, setupCalls(), before+2)
	}
	if body, err := os.ReadFile(configPath); err != nil || !strings.Contains(string(body), `"failMode":"open"`) {
		t.Fatalf("rendered hooks = %q (%v), want fail mode open", body, err)
	}
}

type failOnceBakedConnector struct {
	failModeBakedConnector
	failClosedOnce bool
}

func (c *failOnceBakedConnector) Setup(ctx context.Context, opts connector.SetupOpts) error {
	if opts.HookFailMode == "closed" && c.failClosedOnce {
		c.failClosedOnce = false
		return errors.New("temporary hook write failure")
	}
	return c.failModeBakedConnector.Setup(ctx, opts)
}

func TestHookConfigGuardRetriesFailedFailModeRefresh(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, "hooks.json")
	conn := &failOnceBakedConnector{
		failModeBakedConnector: failModeBakedConnector{runtimePolicyCaptureConnector{
			stubConnector: stubConnector{name: "baked-mode"}, configPath: path,
		}},
		failClosedOnce: true,
	}
	opts := connector.SetupOpts{DataDir: root, HookFailMode: "open"}
	if err := conn.Setup(context.Background(), opts); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	guard := NewHookConfigGuard(nil, nil, time.Hour)
	if !guard.Start(ctx, conn, opts) {
		t.Fatal("guard did not start")
	}
	defer guard.Stop()
	sidecar := &Sidecar{}
	sidecar.bindHookRuntimePolicyResolver(guard)
	cfg := config.DefaultConfig()
	cfg.DataDir = root
	cfg.Guardrail.Mode = "action"
	cfg.Guardrail.HookFailMode = "closed"
	sidecar.publishConfig(cfg)
	if err := guard.RefreshPolicy(ctx); err == nil {
		t.Fatal("expected first refresh to fail")
	}
	guard.mu.Lock()
	pending := guard.pendingPolicyRefresh
	guard.suppressUntil = time.Time{}
	guard.mu.Unlock()
	if !pending {
		t.Fatal("failed refresh was not queued for the policy audit")
	}
	guard.processPolicyAudit()
	raw, err := os.ReadFile(path)
	if err != nil || !strings.Contains(string(raw), `"failMode":"closed"`) {
		t.Fatalf("hooks after retry = %q, %v; want closed", raw, err)
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

	requireOwnedHooks(t, conn, opts)

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

// GAP-0906: with one of Copilot's per-event entries edited, the other entries
// still matched, so the guard saw its hooks as present and never repaired the
// file: no log line, mtime unchanged, the edited event unguarded until the
// gateway restarted. The file watcher must now restore the Setup render. An
// operator-removed connector is still not re-added.
func TestHookConfigGuard_RepairsOneEditedEntry(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Windows registers the native hook launcher, not a hook script")
	}
	root := testenv.PrivateTempDir(t)
	cfgPath := filepath.Join(root, "copilot", "hooks", "defenseclaw.json")
	prev := connector.CopilotHooksPathOverride
	connector.CopilotHooksPathOverride = cfgPath
	t.Cleanup(func() { connector.CopilotHooksPathOverride = prev })
	opts := connector.SetupOpts{
		DataDir:      filepath.Join(root, ".defenseclaw"),
		APIAddr:      "127.0.0.1:18970",
		APIToken:     "tok-test",
		WorkspaceDir: t.TempDir(),
	}
	conn := connector.NewCopilotConnector()
	if err := conn.Setup(context.Background(), opts); err != nil {
		t.Fatalf("copilot Setup: %v", err)
	}
	pristine, err := os.ReadFile(cfgPath)
	if err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	guard := NewHookConfigGuard(nil, nil, guardTestDebounce)
	repairs := observeRepairs(guard)
	guard.Start(ctx, conn, opts)
	defer guard.Stop()
	requireOwnedHooks(t, conn, opts)

	edited := strings.Replace(string(pristine), "copilot-hook.sh' --event 'agentStop'", "copilot-hookX.sh' --event 'agentStop'", 1)
	if edited == string(pristine) {
		t.Fatalf("fixture has no agentStop entry:\n%s", pristine)
	}
	if err := os.WriteFile(cfgPath, []byte(edited), 0o600); err != nil {
		t.Fatal(err)
	}
	waitForRepair(t, repairs, conn, opts)
	if got, err := os.ReadFile(cfgPath); err != nil || string(got) != string(pristine) {
		t.Fatalf("repair is not the Setup render (%v):\n%s", err, got)
	}

	if _, err := connector.MarkConnectorInactive(opts.DataDir, conn.Name()); err != nil {
		t.Fatalf("mark connector inactive: %v", err)
	}
	if err := os.WriteFile(cfgPath, []byte("{}\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	time.Sleep(20 * guardTestDebounce)
	if present, err := connector.OwnedHooksPresent(conn, opts); err != nil || present {
		t.Fatalf("hook guard re-added a removed connector: present=%v err=%v", present, err)
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

func TestHookConfigGuard_ExplicitTeardownStateDoesNotHeal(t *testing.T) {
	conn, opts, cfgPath := installedCursorConnector(t)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	guard := NewHookConfigGuard(nil, nil, guardTestDebounce)
	guard.Start(ctx, conn, opts)
	defer guard.Stop()

	if _, err := connector.MarkConnectorInactive(opts.DataDir, conn.Name()); err != nil {
		t.Fatalf("mark connector inactive: %v", err)
	}
	if err := os.WriteFile(cfgPath, []byte("{}\n"), 0o600); err != nil {
		t.Fatalf("strip hook block: %v", err)
	}
	time.Sleep(20 * guardTestDebounce)

	present, err := connector.OwnedHooksPresent(conn, opts)
	if err != nil {
		t.Fatalf("OwnedHooksPresent: %v", err)
	}
	if present {
		t.Fatal("hook guard reinstalled an explicitly torn-down connector")
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
	runtime, capture := newProxyGeneratedTraceRuntime(t)
	store, logger := testStoreAndLogger(t)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	guard := NewHookConfigGuard(logger, runtime, guardTestDebounce)
	repairs := observeRepairs(guard)
	guard.Start(ctx, conn, opts)
	defer guard.Stop()

	requireOwnedHooks(t, conn, opts)
	if err := os.WriteFile(cfgPath, []byte("{}\n"), 0o600); err != nil {
		t.Fatalf("strip hook block: %v", err)
	}
	waitForRepair(t, repairs, conn, opts)

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
	watcherEvents := generatedMetricByName(
		capture.metricSnapshot(), observability.TelemetryInstrumentDefenseClawWatcherEvents,
	)
	if len(watcherEvents) != 1 {
		t.Fatalf("generated watcher heal events=%d", len(watcherEvents))
	}
	attributes := watcherEvents[0].Attributes()
	if watcherEvents[0].CanonicalRecord().Source() != observability.SourceWatcher ||
		watcherEvents[0].CanonicalRecord().Connector() != conn.Name() ||
		attributes["defenseclaw.connector.source"] != conn.Name() ||
		attributes["defenseclaw.metric.event_type"] != "hook-heal" ||
		attributes["defenseclaw.metric.target_type"] != conn.Name() {
		t.Fatalf("generated watcher heal record=%s/%q attributes=%v",
			watcherEvents[0].CanonicalRecord().Source(), watcherEvents[0].CanonicalRecord().Connector(), attributes)
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
	repairs := observeRepairs(guard)
	guard.Start(ctx, conn, opts)
	defer guard.Stop()

	requireOwnedHooks(t, conn, opts)

	if err := os.WriteFile(cfgPath, []byte("{}\n"), 0o600); err != nil {
		t.Fatalf("strip hook block: %v", err)
	}
	waitForRepair(t, repairs, conn, opts)

	// The notifier runs inside the repair, before its outcome is published.
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
	default:
		t.Fatal("heal notifier did not fire after a successful re-install")
	}
}

func TestHookConfigGuard_DoesNotReportRepairWhenClaudePolicyStillDisablesHooks(t *testing.T) {
	settingsDir := filepath.Join(testenv.PrivateTempDir(t), "claude")
	settingsPath := filepath.Join(settingsDir, "settings.json")
	previous := connector.ClaudeCodeSettingsPathOverride
	connector.ClaudeCodeSettingsPathOverride = settingsPath
	t.Cleanup(func() { connector.ClaudeCodeSettingsPathOverride = previous })
	opts := connector.SetupOpts{DataDir: testenv.PrivateTempDir(t), APIAddr: "127.0.0.1:18970", APIToken: "tok-test"}
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
	// before the debounce fires. The effective-policy resolver must diagnose
	// the explicit disabling source without trying to fight administrator/user
	// policy by rewriting hooks underneath it.
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
		guard.mu.Lock()
		failure := guard.lastPolicyFailure
		guard.mu.Unlock()
		if strings.Contains(failure, "disableAllHooks=true") && strings.Contains(failure, settingsPath) {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("guard did not report the exact policy-blocked source (last failure=%q)", failure)
		}
		time.Sleep(20 * time.Millisecond)
	}
	data, err = os.ReadFile(settingsPath)
	if err != nil {
		t.Fatal(err)
	}
	var blocked map[string]interface{}
	if err := json.Unmarshal(data, &blocked); err != nil {
		t.Fatal(err)
	}
	if _, hooksRestored := blocked["hooks"]; hooksRestored {
		t.Fatal("guard rewrote hooks even though the effective source explicitly disabled them")
	}

	select {
	case <-notified:
		t.Fatal("guard reported a repair even though Claude Code still disables all hooks")
	default:
	}

	// The blocked evaluation must not strand the watcher on the deleted
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
	// The notifier is the guard's completion barrier: it fires only after
	// Setup and the effective-policy verification both succeed. Polling
	// OwnedHooksPresent here races those same reads against Setup's atomic
	// replacement on Windows and can either starve the heal or observe the
	// installed bytes before the notifier step has completed.
	repairNotified := false
	select {
	case <-notified:
		repairNotified = true
	case <-time.After(5 * time.Second):
		// The timeout can race a repair that has already restored the hook
		// bytes but is still completing verification and lifecycle emission
		// before it invokes the notifier. Join that serialized repair before
		// diagnosing a missing notification so a slow Windows runner does not
		// report failure at the completion boundary.
		guard.repairMu.Lock()
		guard.repairMu.Unlock()
		select {
		case <-notified:
			repairNotified = true
		default:
		}
	}
	if !repairNotified {
		present, presenceErr := connector.OwnedHooksPresent(conn, opts)
		data, _ := os.ReadFile(settingsPath)
		guard.mu.Lock()
		pending := len(guard.pending)
		suppressedUntil := guard.suppressUntil
		watchList := guard.fsw.WatchList()
		started := guard.started
		guard.mu.Unlock()
		t.Fatalf(
			"guard did not report the subsequent successful repair (present=%v err=%v started=%v pending=%d suppressedUntil=%s watches=%v settings=%s)",
			present,
			presenceErr,
			started,
			pending,
			suppressedUntil.Format(time.RFC3339Nano),
			watchList,
			data,
		)
	}
	present, presenceErr := connector.OwnedHooksPresent(conn, opts)
	if presenceErr != nil || !present {
		t.Fatalf("guard reported repair without an effective hook contract (present=%v err=%v)", present, presenceErr)
	}

	guard.Stop()
}

func TestHookConfigGuard_PeriodicClaudePolicyAuditRepairsWithoutFileDebounce(t *testing.T) {
	settingsDir := filepath.Join(t.TempDir(), "claude")
	settingsPath := filepath.Join(settingsDir, "settings.json")
	managedRoot := filepath.Join(t.TempDir(), "managed")
	previousSettings := connector.ClaudeCodeSettingsPathOverride
	previousManaged := connector.ClaudeCodeManagedSettingsRootOverride
	connector.ClaudeCodeSettingsPathOverride = settingsPath
	connector.ClaudeCodeManagedSettingsRootOverride = managedRoot
	t.Cleanup(func() {
		connector.ClaudeCodeSettingsPathOverride = previousSettings
		connector.ClaudeCodeManagedSettingsRootOverride = previousManaged
	})

	opts := connector.SetupOpts{DataDir: t.TempDir(), APIAddr: "127.0.0.1:18970", APIToken: "tok-test"}
	conn := connector.NewClaudeCodeConnector()
	if err := conn.Setup(context.Background(), opts); err != nil {
		t.Fatalf("Claude Code Setup: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	// A one-hour filesystem debounce proves the repair comes from the policy
	// audit ticker rather than the ordinary fsnotify processing path.
	guard := NewHookConfigGuard(nil, nil, time.Hour)
	guard.policyAudit = 20 * time.Millisecond
	healed := make(chan []string, 1)
	guard.SetHealNotifier(func(_ string, paths []string) {
		healed <- append([]string(nil), paths...)
	})
	guard.Start(ctx, conn, opts)
	t.Cleanup(guard.Stop)

	if err := os.WriteFile(settingsPath, []byte("{}\n"), 0o600); err != nil {
		t.Fatalf("strip Claude hooks: %v", err)
	}
	// The notifier is the completion barrier for Setup and its effective-policy
	// verification. Polling OwnedHooksPresent while Setup atomically replaces the
	// file races the repair on Windows.
	repairNotified := false
	select {
	case paths := <-healed:
		repairNotified = true
		if len(paths) != 1 || paths[0] != "periodic effective-policy audit" {
			t.Fatalf("heal notifier paths = %v, want periodic effective-policy audit", paths)
		}
	case <-time.After(5 * time.Second):
		// Join an in-flight serialized repair before diagnosing a missing
		// notification. The notifier runs before repairMu is released, so this
		// waits for actual completion without changing the audit-start deadline.
		guard.repairMu.Lock()
		guard.repairMu.Unlock()
		select {
		case paths := <-healed:
			repairNotified = true
			if len(paths) != 1 || paths[0] != "periodic effective-policy audit" {
				t.Fatalf("heal notifier paths = %v, want periodic effective-policy audit", paths)
			}
		default:
		}
	}
	if !repairNotified {
		present, err := connector.OwnedHooksPresent(conn, opts)
		t.Fatalf("periodic policy audit did not report a completed repair (present=%v err=%v)", present, err)
	}
	present, err := connector.OwnedHooksPresent(conn, opts)
	if err != nil || !present {
		t.Fatalf("periodic policy audit reported repair without an effective hook contract (present=%v err=%v)", present, err)
	}
}

func TestHookConfigGuard_SuppressHealingPausesThenResumes(t *testing.T) {
	conn, opts, cfgPath := installedCursorConnector(t)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	guard := NewHookConfigGuard(nil, nil, guardTestDebounce)
	repairs := observeRepairs(guard)
	guard.Start(ctx, conn, opts)
	defer guard.Stop()
	requireOwnedHooks(t, conn, opts)

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
	waitForRepair(t, repairs, conn, opts)
}

func TestHookConfigGuard_RepointFollowsConnectorSwitch(t *testing.T) {
	cursorConn, cursorOpts, cursorPath := installedCursorConnector(t)
	devinConn, devinOpts, devinPath := installedDevinConnector(t)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	guard := NewHookConfigGuard(nil, nil, guardTestDebounce)
	repairs := observeRepairs(guard)
	guard.Start(ctx, cursorConn, cursorOpts)
	defer guard.Stop()
	requireOwnedHooks(t, cursorConn, cursorOpts)

	// Switch the guard to the devin connector.
	guard.Repoint(devinConn, devinOpts)

	// Deleting devin's hook block is now healed.
	if err := os.WriteFile(devinPath, []byte("{}\n"), 0o600); err != nil {
		t.Fatalf("strip devin hook block: %v", err)
	}
	if outcome := waitForRepair(t, repairs, devinConn, devinOpts); outcome.connector != devinConn.Name() {
		t.Fatalf("repaired connector = %q, want %q", outcome.connector, devinConn.Name())
	}

	// Deleting the previous connector's hook block is NOT healed: after the
	// repoint the guard neither targets nor watches cursor's config, so the
	// edit cannot reach it, and every repair runs for the active connector.
	cursorClean := filepath.Clean(cursorPath)
	guard.mu.Lock()
	_, cursorTargeted := guard.targets[cursorClean]
	_, cursorDirWatched := guard.watchedDirs[filepath.Dir(cursorClean)]
	activeConnector := guard.conn.Name()
	guard.mu.Unlock()
	if cursorTargeted || cursorDirWatched || activeConnector != devinConn.Name() {
		t.Fatalf("guard still follows cursor after repoint (targeted=%v watched=%v active=%s)",
			cursorTargeted, cursorDirWatched, activeConnector)
	}
	if err := os.WriteFile(cursorPath, []byte("{}\n"), 0o600); err != nil {
		t.Fatalf("strip cursor hook block: %v", err)
	}
	present, err := connector.OwnedHooksPresent(cursorConn, cursorOpts)
	if err != nil {
		t.Fatalf("OwnedHooksPresent cursor: %v", err)
	}
	if present {
		t.Fatal("cursor hook block restored after the guard repointed to devin")
	}
}

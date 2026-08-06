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

package gateway

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/gateway/connector"
	"github.com/defenseclaw/defenseclaw/internal/guardrail"
	"github.com/defenseclaw/defenseclaw/internal/managed"
	"github.com/defenseclaw/defenseclaw/internal/testenv"
)

// bootStubConnector embeds stubConnector (full connector.Connector) and lets a
// test inject a Setup error plus count lifecycle calls, so the multi-connector
// boot loop's failure-isolation behavior can be exercised without touching the
// real connector registry.
type bootStubConnector struct {
	stubConnector
	setupErr      error
	setupCalls    int
	teardownCalls int
	credsSet      bool
	artifactPath  string
}

func (b *bootStubConnector) Setup(context.Context, connector.SetupOpts) error {
	b.setupCalls++
	return b.setupErr
}

func (b *bootStubConnector) Teardown(context.Context, connector.SetupOpts) error {
	b.teardownCalls++
	return nil
}

func (b *bootStubConnector) SetCredentials(string, string) { b.credsSet = true }

type hookBootStubConnector struct{ bootStubConnector }

func (*hookBootStubConnector) HookScriptNames(connector.SetupOpts) []string {
	return []string{"codex-hook.sh"}
}

func (b *bootStubConnector) HookRuntimeArtifacts(connector.SetupOpts) []string {
	if b.artifactPath == "" {
		return nil
	}
	return []string{b.artifactPath}
}

type failingOpenCodeConnector struct {
	bootStubConnector
	pluginPath    string
	poisonRestore bool
}

type incompletePublicationRollbackConnector struct {
	bootStubConnector
	rollbackErr error
	verifyErr   error
}

type postureChangingConnector struct {
	bootStubConnector
	setupModes []string
}

type lockRestoreFailureConnector struct {
	bootStubConnector
}

type failedSetupCleanupConnector struct {
	bootStubConnector
	teardownErr error
	verifyErr   error
}

type registrationPostureConnector struct {
	bootStubConnector
	setupPostures []string
}

type orphanReconcileFailureConnector struct {
	bootStubConnector
	hookPath             string
	removeHookOnTeardown bool
	teardownErr          error
	verifyErr            error
}

func (c *orphanReconcileFailureConnector) Teardown(context.Context, connector.SetupOpts) error {
	c.teardownCalls++
	if c.teardownErr != nil {
		return c.teardownErr
	}
	if c.removeHookOnTeardown {
		if err := os.Remove(c.hookPath); err != nil && !os.IsNotExist(err) {
			return err
		}
	}
	return nil
}

func (c *orphanReconcileFailureConnector) VerifyClean(connector.SetupOpts) error {
	if c.verifyErr != nil {
		return c.verifyErr
	}
	if c.removeHookOnTeardown {
		if _, err := os.Stat(c.hookPath); !os.IsNotExist(err) {
			return fmt.Errorf("orphan hook still exists: %v", err)
		}
	}
	return nil
}

func (c *failedSetupCleanupConnector) Teardown(context.Context, connector.SetupOpts) error {
	c.teardownCalls++
	return c.teardownErr
}

func (c *failedSetupCleanupConnector) VerifyClean(connector.SetupOpts) error {
	return c.verifyErr
}

func (c *registrationPostureConnector) Setup(_ context.Context, opts connector.SetupOpts) error {
	c.setupCalls++
	posture := fmt.Sprintf("%s|hilt=%t", opts.GuardrailMode, opts.HILTEnabled)
	c.setupPostures = append(c.setupPostures, posture)
	return os.WriteFile(c.artifactPath, []byte(posture+"\n"), 0o600)
}

func (c *registrationPostureConnector) Teardown(context.Context, connector.SetupOpts) error {
	c.teardownCalls++
	if err := os.Remove(c.artifactPath); err != nil && !os.IsNotExist(err) {
		return err
	}
	return nil
}

func (c *lockRestoreFailureConnector) Setup(_ context.Context, opts connector.SetupOpts) error {
	c.setupCalls++
	lockPath := filepath.Join(opts.DataDir, "hook_contract_lock.json")
	if err := os.Remove(lockPath); err != nil && !os.IsNotExist(err) {
		return err
	}
	if err := os.Mkdir(lockPath, 0o700); err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(lockPath, "foreign"), []byte("not rollback-owned"), 0o600); err != nil {
		return err
	}
	return errors.New("injected setup failure after lock-path replacement")
}

func (c *postureChangingConnector) Setup(_ context.Context, opts connector.SetupOpts) error {
	c.setupCalls++
	c.setupModes = append(c.setupModes, opts.HookFailMode)
	return os.WriteFile(c.artifactPath, []byte(opts.HookFailMode+"\n"), 0o600)
}

func (c *postureChangingConnector) Teardown(context.Context, connector.SetupOpts) error {
	c.teardownCalls++
	if err := os.Remove(c.artifactPath); err != nil && !os.IsNotExist(err) {
		return err
	}
	return nil
}

func (c *incompletePublicationRollbackConnector) Setup(context.Context, connector.SetupOpts) error {
	c.setupCalls++
	if err := os.WriteFile(c.artifactPath, []byte("new connector artifact"), 0o600); err != nil {
		return err
	}
	return nil
}

func (c *incompletePublicationRollbackConnector) Teardown(context.Context, connector.SetupOpts) error {
	c.teardownCalls++
	return c.rollbackErr
}

func (c *incompletePublicationRollbackConnector) VerifyClean(connector.SetupOpts) error {
	return c.verifyErr
}

func (c *failingOpenCodeConnector) Setup(context.Context, connector.SetupOpts) error {
	c.setupCalls++
	if err := os.WriteFile(c.pluginPath, []byte("partial OpenCode plugin"), 0o600); err != nil {
		return err
	}
	return errors.New("injected OpenCode setup failure")
}

func (c *failingOpenCodeConnector) Teardown(context.Context, connector.SetupOpts) error {
	c.teardownCalls++
	if err := os.Remove(c.pluginPath); err != nil && !os.IsNotExist(err) {
		return err
	}
	if c.poisonRestore {
		if err := os.Mkdir(c.pluginPath, 0o700); err != nil {
			return err
		}
		if err := os.WriteFile(filepath.Join(c.pluginPath, "foreign"), []byte("not rollback-owned"), 0o600); err != nil {
			return err
		}
	}
	return nil
}

func multiBootSidecar(t *testing.T) *Sidecar {
	t.Helper()
	return &Sidecar{
		cfg: &config.Config{
			DataDir:   t.TempDir(),
			Guardrail: config.GuardrailConfig{},
		},
	}
}

func failingHookTokenDataDir(t *testing.T) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "not-a-directory")
	if err := os.WriteFile(path, []byte("fixture"), 0o600); err != nil {
		t.Fatalf("write failing hook-token fixture: %v", err)
	}
	return path
}

func makeActiveConnectorPublicationUnsafe(t *testing.T, dataDir string) {
	t.Helper()
	lockPath := filepath.Join(dataDir, "active_connector.json.lock")
	if err := os.Remove(lockPath); err != nil && !os.IsNotExist(err) {
		t.Fatalf("remove active connector advisory lock: %v", err)
	}
	if err := os.Mkdir(lockPath, 0o700); err != nil {
		t.Fatalf("make active connector advisory lock unsafe: %v", err)
	}
}

func TestRunActiveGuardrailPublishesScopedTokenFailure(t *testing.T) {
	s := &Sidecar{
		cfg: &config.Config{
			DataDir:        failingHookTokenDataDir(t),
			DeploymentMode: string(config.DeploymentModeManagedEnterprise),
			Gateway:        config.GatewayConfig{Token: "gateway-token"},
			Guardrail: config.GuardrailConfig{
				Enabled:   true,
				Connector: "codex",
				Mode:      "action",
			},
		},
		health: NewSidecarHealth(),
		router: routerWithDefaultRulePack(t),
	}

	err := s.runActiveGuardrail(context.Background())
	if err == nil || !strings.Contains(err.Error(), "scoped hook token") {
		t.Fatalf("runActiveGuardrail error = %v, want scoped-token failure", err)
	}
	snapshot := s.health.Snapshot()
	if snapshot.Guardrail.State != StateError {
		t.Fatalf("guardrail health state = %s, want %s", snapshot.Guardrail.State, StateError)
	}
	if !strings.Contains(snapshot.Guardrail.LastError, "scoped hook token") {
		t.Fatalf("guardrail health error = %q, want scoped-token failure", snapshot.Guardrail.LastError)
	}
}

func mustConnectorSetupOpts(t *testing.T, s *Sidecar, conn connector.Connector, apiToken, proxyAddr, apiAddr string) connector.SetupOpts {
	t.Helper()
	opts, err := s.connectorSetupOptsChecked(conn, apiToken, proxyAddr, apiAddr)
	if err != nil {
		t.Fatalf("connectorSetupOptsChecked: %v", err)
	}
	return opts
}

func TestConnectorSetupOptsCarryCodexOtelEnvironment(t *testing.T) {
	s := multiBootSidecar(t)
	s.cfg.Environment = "windows"
	conn := &bootStubConnector{stubConnector: stubConnector{name: "codex"}}

	opts := mustConnectorSetupOpts(t, s, conn, "tok", "127.0.0.1:4000", "127.0.0.1:18970")
	if opts.CodexOtelEnvironment != s.cfg.Environment {
		t.Fatalf("setup environment = %q; want %q", opts.CodexOtelEnvironment, s.cfg.Environment)
	}
}

// TestSetupOneConnector_SetupErrorReturnsWithoutRollback verifies that a
// Setup() failure surfaces as an error and does NOT trigger a teardown: there
// is nothing to roll back because Setup never reached a verified state.
func TestSetupOneConnector_SetupErrorReturnsWithoutRollback(t *testing.T) {
	s := multiBootSidecar(t)
	conn := &bootStubConnector{stubConnector: stubConnector{name: "codex"}, setupErr: errors.New("boom")}
	cache := guardrail.NewRulePackCache()

	opts := mustConnectorSetupOpts(t, s, conn, "tok", "127.0.0.1:0", "127.0.0.1:0")
	err := s.setupOneConnector(context.Background(), conn, opts, "master", cache)
	if err == nil {
		t.Fatal("expected error from failing Setup, got nil")
	}
	if conn.setupCalls != 1 {
		t.Errorf("setupCalls=%d, want 1", conn.setupCalls)
	}
	if conn.teardownCalls != 0 {
		t.Errorf("Setup failure must not roll back; teardownCalls=%d, want 0", conn.teardownCalls)
	}
	if !conn.credsSet {
		t.Error("credentials must be injected before Setup")
	}
}

// TestSetupOneConnector_SuccessNoTeardown confirms the happy path returns nil
// and leaves the connector installed (no teardown).
func TestSetupOneConnector_SuccessNoTeardown(t *testing.T) {
	s := multiBootSidecar(t)
	conn := &bootStubConnector{stubConnector: stubConnector{name: "claudecode"}}
	cache := guardrail.NewRulePackCache()

	opts := mustConnectorSetupOpts(t, s, conn, "tok", "127.0.0.1:0", "127.0.0.1:0")
	if err := s.setupOneConnector(context.Background(), conn, opts, "master", cache); err != nil {
		t.Fatalf("expected nil error on clean setup, got %v", err)
	}
	if conn.teardownCalls != 0 {
		t.Errorf("clean setup must not tear down; teardownCalls=%d, want 0", conn.teardownCalls)
	}
}

// TestSetupOneConnector_ActionModeUnverifiedContractSkips verifies the
// multi-connector boot loop applies the same hook-contract gate as the
// single-connector path: in action mode, a connector whose installed agent
// version cannot be verified against a known hook contract is refused (so the
// caller isolates/skips it) BEFORE Setup runs, instead of installing an
// enforcing hook against an unverified surface.
func TestSetupOneConnector_ActionModeUnverifiedContractSkips(t *testing.T) {
	s := multiBootSidecar(t)
	s.cfg.Guardrail.Mode = "action"
	// No cached agent version in the temp data dir → contract resolves as
	// "unversioned", which requires an explicit action-mode override.
	conn := &bootStubConnector{stubConnector: stubConnector{name: "codex"}}
	cache := guardrail.NewRulePackCache()

	opts := mustConnectorSetupOpts(t, s, conn, "tok", "127.0.0.1:0", "127.0.0.1:0")
	err := s.setupOneConnector(context.Background(), conn, opts, "master", cache)
	if err == nil {
		t.Fatal("expected action-mode unverified contract to be refused, got nil")
	}
	if !strings.Contains(err.Error(), "hook contract") {
		t.Errorf("error = %q, want a hook-contract gate error", err)
	}
	if conn.setupCalls != 0 {
		t.Errorf("Setup must not run for a gated connector; setupCalls=%d, want 0", conn.setupCalls)
	}
}

func TestSetupOneConnector_ObserveModeUnsupportedVersionSkipsBeforeSetup(t *testing.T) {
	s := multiBootSidecar(t)
	s.cfg.Guardrail.Mode = "observe"
	conn := &bootStubConnector{stubConnector: stubConnector{name: "opencode"}}
	opts := mustConnectorSetupOpts(t, s, conn, "tok", "127.0.0.1:0", "127.0.0.1:0")
	opts.AgentVersion = "opencode 1.18.12"

	err := s.setupOneConnector(
		context.Background(), conn, opts, "master", guardrail.NewRulePackCache(),
	)
	if err == nil || !strings.Contains(err.Error(), "not covered by a known hook contract") {
		t.Fatalf("error = %v, want observe-mode unsupported-version refusal", err)
	}
	if conn.setupCalls != 0 {
		t.Fatalf("setupCalls = %d, want fail-before-setup", conn.setupCalls)
	}
}

func TestSetupOneConnector_PeerObserveModeUnknownVersionStillRuns(t *testing.T) {
	s := multiBootSidecar(t)
	s.cfg.Guardrail.Mode = "observe"
	conn := &bootStubConnector{stubConnector: stubConnector{name: "codex"}}
	opts := mustConnectorSetupOpts(t, s, conn, "tok", "127.0.0.1:0", "127.0.0.1:0")
	opts.AgentVersion = "codex 0.123.0"

	err := s.setupOneConnector(
		context.Background(), conn, opts, "master", guardrail.NewRulePackCache(),
	)
	if err != nil {
		t.Fatalf("peer observe-mode unknown version should retain warning-and-run behavior: %v", err)
	}
	if conn.setupCalls != 1 {
		t.Fatalf("setupCalls = %d, want peer observe setup to run", conn.setupCalls)
	}
}

// TestSetupOneConnector_ActionModeContractDriftOverride verifies the explicit
// exploratory override (DEFENSECLAW_ALLOW_HOOK_CONTRACT_DRIFT=1) bypasses the
// gate so Setup proceeds — matching the single-connector path's escape hatch.
func TestSetupOneConnector_ActionModeContractDriftOverride(t *testing.T) {
	t.Setenv("DEFENSECLAW_ALLOW_HOOK_CONTRACT_DRIFT", "1")
	s := multiBootSidecar(t)
	s.cfg.Guardrail.Mode = "action"
	conn := &bootStubConnector{stubConnector: stubConnector{name: "codex"}}
	cache := guardrail.NewRulePackCache()

	opts := mustConnectorSetupOpts(t, s, conn, "tok", "127.0.0.1:0", "127.0.0.1:0")
	if err := s.setupOneConnector(context.Background(), conn, opts, "master", cache); err != nil {
		t.Fatalf("drift override must allow setup, got %v", err)
	}
	if conn.setupCalls != 1 {
		t.Errorf("setupCalls=%d, want 1 (override should let Setup run)", conn.setupCalls)
	}
}

// An observe-mode connector in a mixed-mode batch must use its own effective
// mode for the action-only hook-contract gate. The global mode may be action
// because another connector enforces; that must not make an unversioned
// observe connector fail before Setup can refresh its hooks.
func TestSetupOneConnector_ObserveOverrideIgnoresGlobalActionContractGate(t *testing.T) {
	s := multiBootSidecar(t)
	s.cfg.Guardrail.Mode = "action"
	s.cfg.Guardrail.Connectors = map[string]config.PerConnectorGuardrailConfig{
		"claudecode": {Mode: "observe"},
	}
	conn := &bootStubConnector{stubConnector: stubConnector{name: "claudecode"}}

	opts := mustConnectorSetupOpts(t, s, conn, "tok", "127.0.0.1:0", "127.0.0.1:0")
	if opts.AgentVersion != "" {
		t.Fatalf("test requires an unversioned connector, got %q", opts.AgentVersion)
	}
	if err := s.setupOneConnector(context.Background(), conn, opts, "master", guardrail.NewRulePackCache()); err != nil {
		t.Fatalf("observe override should allow hook refresh despite global action mode: %v", err)
	}
	if conn.setupCalls != 1 {
		t.Fatalf("setupCalls=%d, want 1", conn.setupCalls)
	}
}

// Existing action connectors must be refreshed during the same boot as newly
// added peers. A stale generated hook digest is exactly what an upgrade/setup
// needs Connector.Setup to replace; it is not evidence that the upstream
// agent contract changed.
func TestSetupConnectorsIsolated_RefreshesExistingStaleHookAlongsideNewPeer(t *testing.T) {
	s := multiBootSidecar(t)
	s.cfg.DataDir = testenv.PrivateTempDir(t)
	s.cfg.Guardrail.Mode = "action"
	s.cfg.Guardrail.Connectors = map[string]config.PerConnectorGuardrailConfig{
		"codex": {Mode: "action"},
	}

	discovery := map[string]any{
		"agents": map[string]any{
			"codex":      map[string]any{"version": "codex-cli 0.142.4"},
			"claudecode": map[string]any{"version": "Claude Code v2.1.154"},
		},
	}
	raw, err := json.Marshal(discovery)
	if err != nil {
		t.Fatalf("marshal discovery: %v", err)
	}
	if err := os.WriteFile(filepath.Join(s.cfg.DataDir, "agent_discovery.json"), raw, 0o600); err != nil {
		t.Fatalf("write discovery: %v", err)
	}

	artifact := filepath.Join(s.cfg.DataDir, "hooks", "codex-hook.sh")
	if err := os.MkdirAll(filepath.Dir(artifact), 0o700); err != nil {
		t.Fatalf("mkdir hooks: %v", err)
	}
	if err := os.WriteFile(artifact, []byte("stale generated hook"), 0o600); err != nil {
		t.Fatalf("write stale hook: %v", err)
	}
	previous := stageCodexExecutableEvidenceFixture(t, s.cfg.DataDir)
	previous.HookScriptDigests = map[string]string{
		"codex-hook.sh": "sha256:previous-generated-build",
	}
	if err := connector.SaveHookContractLockEntry(s.cfg.DataDir, previous); err != nil {
		t.Fatalf("save previous lock: %v", err)
	}

	existing := &bootStubConnector{
		stubConnector: stubConnector{name: "codex"},
		artifactPath:  artifact,
	}
	added := &bootStubConnector{stubConnector: stubConnector{name: "claudecode"}}
	got, err := s.setupConnectorsIsolated(
		context.Background(),
		[]connector.Connector{existing, added},
		"tok", "127.0.0.1:0", "127.0.0.1:0", "master",
		guardrail.NewRulePackCache(),
	)
	if err != nil {
		t.Fatalf("setupConnectorsIsolated: %v", err)
	}
	if want := []string{"codex", "claudecode"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("refreshed connectors=%v, want %v", got, want)
	}
	if existing.setupCalls != 1 || added.setupCalls != 1 {
		t.Fatalf(
			"setupCalls existing=%d added=%d, want 1/1",
			existing.setupCalls,
			added.setupCalls,
		)
	}
}

// TestSetupConnectorsIsolated_AllSucceed verifies every connector that sets up
// cleanly appears in the returned set, in input order.
func TestSetupConnectorsIsolated_AllSucceed(t *testing.T) {
	s := multiBootSidecar(t)
	conns := []connector.Connector{
		&bootStubConnector{stubConnector: stubConnector{name: "codex"}},
		&bootStubConnector{stubConnector: stubConnector{name: "claudecode"}},
	}
	got, err := s.setupConnectorsIsolated(context.Background(), conns, "tok", "127.0.0.1:0", "127.0.0.1:0", "master", guardrail.NewRulePackCache())
	if err != nil {
		t.Fatalf("setupConnectorsIsolated: %v", err)
	}
	want := []string{"codex", "claudecode"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("succeeded=%v, want %v", got, want)
	}
}

func TestSetupConnectorsIsolated_UnsafeLockFailsBeforeSetup(t *testing.T) {
	s := multiBootSidecar(t)
	if err := os.Mkdir(filepath.Join(s.cfg.DataDir, "hook_contract_lock.json"), 0o700); err != nil {
		t.Fatal(err)
	}
	conn := &bootStubConnector{stubConnector: stubConnector{name: "codex"}}

	got, err := s.setupConnectorsIsolated(
		context.Background(), []connector.Connector{conn}, "tok", "a", "b", "master",
		guardrail.NewRulePackCache(),
	)
	if err == nil || !strings.Contains(err.Error(), "capture pre-setup hook contract lock") {
		t.Fatalf("setupConnectorsIsolated error = %v, want unsafe pre-setup lock rejection", err)
	}
	if len(got) != 0 {
		t.Fatalf("succeeded = %v, want no setup after snapshot rejection", got)
	}
	if conn.setupCalls != 0 || conn.teardownCalls != 0 {
		t.Fatalf("setupCalls=%d teardownCalls=%d, want fail-before-mutation", conn.setupCalls, conn.teardownCalls)
	}
	if active := connector.LoadActiveConnector(s.cfg.DataDir); active != "" {
		t.Fatalf("active connector = %q, want unsafe snapshot preflight to preserve roster", active)
	}
}

func TestSetupConnectorsIsolated_FailurePreservesPriorRoster(t *testing.T) {
	s := multiBootSidecar(t)
	s.cfg.DataDir = testenv.PrivateTempDir(t)
	s.health = NewSidecarHealth()
	s.health.SetWatcher(StateRunning, "", map[string]interface{}{"last_known_state": "healthy"})
	want := []string{"codex", "cursor"}
	if err := connector.SaveActiveConnectors(s.cfg.DataDir, want); err != nil {
		t.Fatal(err)
	}
	failed := &bootStubConnector{
		stubConnector: stubConnector{name: "claudecode"},
		setupErr:      errors.New("injected setup failure"),
	}

	got, err := s.setupConnectorsIsolated(
		context.Background(), []connector.Connector{failed}, "tok", "a", "b", "master",
		guardrail.NewRulePackCache(),
	)
	if err != nil {
		t.Fatalf("setupConnectorsIsolated: %v", err)
	}
	if len(got) != 0 {
		t.Fatalf("succeeded = %v, want none", got)
	}
	if active := connector.LoadActiveConnectors(s.cfg.DataDir); !reflect.DeepEqual(active, want) {
		t.Fatalf("active connectors = %v, want exact prior roster %v", active, want)
	}
	if watcher := s.health.Snapshot().Watcher; watcher.State != StateRunning {
		t.Fatalf("watcher state = %q, want unchanged running state after isolated setup failure", watcher.State)
	}
}

func TestSetupConnectorsIsolated_OpenCodeFailureRestoresPluginAndLock(t *testing.T) {
	s := multiBootSidecar(t)
	s.cfg.DataDir = testenv.PrivateTempDir(t)
	configDir := testenv.PrivateTempDir(t)
	t.Setenv("OPENCODE_CONFIG_DIR", configDir)
	pluginPath := filepath.Join(configDir, "plugins", "defenseclaw.js")
	if err := os.MkdirAll(filepath.Dir(pluginPath), 0o700); err != nil {
		t.Fatal(err)
	}
	priorPlugin := []byte("// prior managed OpenCode plugin\n")
	if err := os.WriteFile(pluginPath, priorPlugin, 0o600); err != nil {
		t.Fatal(err)
	}
	priorLock := connector.HookContractLockEntry{
		Connector:           "opencode",
		ContractID:          "opencode-hooks-v1",
		CompatibilityStatus: connector.HookCompatibilityKnown,
		HookScriptVersion:   "v7",
		RawAgentVersion:     "opencode 1.18.11",
	}
	if err := connector.SaveHookContractLockEntry(s.cfg.DataDir, priorLock); err != nil {
		t.Fatal(err)
	}
	failed := &failingOpenCodeConnector{
		bootStubConnector: bootStubConnector{stubConnector: stubConnector{name: "opencode"}},
		pluginPath:        pluginPath,
	}

	got, err := s.setupConnectorsIsolated(
		context.Background(), []connector.Connector{failed}, "tok", "a", "b", "master",
		guardrail.NewRulePackCache(),
	)
	if err != nil {
		t.Fatalf("setupConnectorsIsolated: %v", err)
	}
	if len(got) != 0 {
		t.Fatalf("succeeded = %v, want failed OpenCode skipped", got)
	}
	plugin, err := os.ReadFile(pluginPath)
	if err != nil {
		t.Fatalf("read restored plugin: %v", err)
	}
	if !reflect.DeepEqual(plugin, priorPlugin) {
		t.Fatalf("restored plugin = %q, want exact prior bytes %q", plugin, priorPlugin)
	}
	if lock := connector.LoadHookContractLockEntry(s.cfg.DataDir, "opencode"); lock.ContractID != priorLock.ContractID || lock.RawAgentVersion != priorLock.RawAgentVersion {
		t.Fatalf("restored lock = %+v, want prior contract/version", lock)
	}
	if active := connector.LoadActiveConnector(s.cfg.DataDir); active != "" {
		t.Fatalf("active connector = %q, want failed OpenCode absent", active)
	}
}

func TestSetupConnectorsIsolated_OpenCodeRestoreFailureAbortsSurvivors(t *testing.T) {
	s := multiBootSidecar(t)
	s.cfg.DataDir = testenv.PrivateTempDir(t)
	configDir := testenv.PrivateTempDir(t)
	t.Setenv("OPENCODE_CONFIG_DIR", configDir)
	pluginPath := filepath.Join(configDir, "plugins", "defenseclaw.js")
	failed := &failingOpenCodeConnector{
		bootStubConnector: bootStubConnector{stubConnector: stubConnector{name: "opencode"}},
		pluginPath:        pluginPath,
		poisonRestore:     true,
	}
	survivor := &bootStubConnector{stubConnector: stubConnector{name: "codex"}}

	got, err := s.setupConnectorsIsolated(
		context.Background(), []connector.Connector{survivor, failed}, "tok", "a", "b", "master",
		guardrail.NewRulePackCache(),
	)
	if err == nil || !strings.Contains(err.Error(), "per-connector rollback incomplete") ||
		!strings.Contains(err.Error(), "restore prior OpenCode registration") {
		t.Fatalf("setupConnectorsIsolated error = %v, want fail-loud OpenCode restoration failure", err)
	}
	if len(got) != 0 {
		t.Fatalf("succeeded = %v, want no published survivors after incomplete rollback", got)
	}
	if survivor.setupCalls != 1 || survivor.teardownCalls != 1 {
		t.Fatalf(
			"survivor lifecycle = setup %d, teardown %d; want earlier success rolled back before returning residue error",
			survivor.setupCalls, survivor.teardownCalls,
		)
	}
	if active := connector.LoadActiveConnectors(s.cfg.DataDir); len(active) != 0 {
		t.Fatalf("active connectors = %v, want no rolled-back survivor publication", active)
	}
	if lock := connector.LoadHookContractLockEntry(s.cfg.DataDir, "codex"); lock.Connector != "" {
		t.Fatalf("codex lock = %+v, want earlier survivor lock rolled back", lock)
	}
	if info, statErr := os.Stat(pluginPath); statErr != nil || !info.IsDir() {
		t.Fatalf("injected foreign residue = %v, %v; want retained directory proving rollback was incomplete", info, statErr)
	}
}

func TestSetupConnectorsIsolated_PriorLockRestoreFailureAbortsSurvivors(t *testing.T) {
	s := multiBootSidecar(t)
	s.cfg.DataDir = testenv.PrivateTempDir(t)
	failed := &lockRestoreFailureConnector{bootStubConnector: bootStubConnector{
		stubConnector: stubConnector{name: "codex"},
	}}
	survivor := &bootStubConnector{stubConnector: stubConnector{name: "claudecode"}}

	got, err := s.setupConnectorsIsolated(
		context.Background(), []connector.Connector{failed, survivor}, "tok", "a", "b", "master",
		guardrail.NewRulePackCache(),
	)
	if err == nil || !strings.Contains(err.Error(), "per-connector rollback incomplete") ||
		!strings.Contains(err.Error(), "restore prior codex hook contract lock") {
		t.Fatalf("setupConnectorsIsolated error = %v, want fail-loud prior-lock restoration failure", err)
	}
	if len(got) != 0 || survivor.setupCalls != 0 {
		t.Fatalf("succeeded=%v survivor.setupCalls=%d, want abort before survivor publication", got, survivor.setupCalls)
	}
}

func TestSetupConnectorsIsolated_CleanupResidueAbortsAndRollsBackSurvivors(t *testing.T) {
	s := multiBootSidecar(t)
	s.cfg.DataDir = testenv.PrivateTempDir(t)
	survivor := &bootStubConnector{stubConnector: stubConnector{name: "codex"}}
	failed := &failedSetupCleanupConnector{
		bootStubConnector: bootStubConnector{
			stubConnector: stubConnector{name: "claudecode"},
			setupErr:      errors.New("injected connector setup failure"),
		},
		teardownErr: errors.New("injected teardown residue"),
		verifyErr:   errors.New("injected VerifyClean residue"),
	}

	got, err := s.setupConnectorsIsolated(
		context.Background(), []connector.Connector{survivor, failed}, "tok", "a", "b", "master",
		guardrail.NewRulePackCache(),
	)
	if err == nil || !strings.Contains(err.Error(), "per-connector rollback incomplete") ||
		!strings.Contains(err.Error(), "injected teardown residue") ||
		!strings.Contains(err.Error(), "injected VerifyClean residue") {
		t.Fatalf("setupConnectorsIsolated error = %v, want joined teardown/VerifyClean rollback failure", err)
	}
	if len(got) != 0 {
		t.Fatalf("succeeded = %v, want aborted survivor result cleared", got)
	}
	if survivor.setupCalls != 1 || survivor.teardownCalls != 1 {
		t.Fatalf(
			"survivor lifecycle = setup %d, teardown %d; want earlier success rolled back",
			survivor.setupCalls, survivor.teardownCalls,
		)
	}
	if active := connector.LoadActiveConnectors(s.cfg.DataDir); len(active) != 0 {
		t.Fatalf("active connectors = %v, want no survivor publication beside failed cleanup residue", active)
	}
	if lock := connector.LoadHookContractLockEntry(s.cfg.DataDir, "codex"); lock.Connector != "" {
		t.Fatalf("codex lock = %+v, want earlier survivor lock rolled back", lock)
	}
}

func TestMultiConnectorActivePublicationFailureRestoresPreviouslyActivePosture(t *testing.T) {
	s := multiBootSidecar(t)
	s.cfg.DataDir = testenv.PrivateTempDir(t)
	s.cfg.Guardrail.Enabled = true
	s.cfg.Guardrail.Mode = "observe"
	s.cfg.Guardrail.HookFailMode = "closed"
	s.cfg.Guardrail.Connectors = map[string]config.PerConnectorGuardrailConfig{
		"codex": {Mode: "observe", HookFailMode: "closed"},
	}
	s.health = NewSidecarHealth()
	artifactPath := filepath.Join(testenv.PrivateTempDir(t), "codex-registration-posture")
	if err := os.WriteFile(artifactPath, []byte("open\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := connector.SaveActiveConnectors(s.cfg.DataDir, []string{"codex"}); err != nil {
		t.Fatal(err)
	}
	priorLockEntry := connector.HookContractLockEntry{
		Connector:           "codex",
		ContractID:          "codex-hooks-v4",
		CompatibilityStatus: connector.HookCompatibilityKnown,
		HookScriptVersion:   "v8",
		HookFailMode:        "open",
		DefenseClawVersion:  "prior-build",
		RegistrationPosture: &connector.HookRegistrationPosture{
			GuardrailMode: "observe",
			HILTEnabled:   false,
		},
	}
	if err := connector.SaveHookContractLockEntry(s.cfg.DataDir, priorLockEntry); err != nil {
		t.Fatal(err)
	}
	priorLock, err := os.ReadFile(filepath.Join(s.cfg.DataDir, "hook_contract_lock.json"))
	if err != nil {
		t.Fatal(err)
	}
	priorActive, err := os.ReadFile(filepath.Join(s.cfg.DataDir, "active_connector.json"))
	if err != nil {
		t.Fatal(err)
	}
	makeActiveConnectorPublicationUnsafe(t, s.cfg.DataDir)
	applied := &postureChangingConnector{bootStubConnector: bootStubConnector{
		stubConnector: stubConnector{name: "codex"},
		artifactPath:  artifactPath,
	}}

	transaction, err := s.setupConnectorsIsolatedTransaction(
		context.Background(), []connector.Connector{applied},
		"synthetic gateway token", "127.0.0.1:0", "127.0.0.1:0", "synthetic master key",
		guardrail.NewRulePackCache(),
	)
	if err != nil {
		t.Fatalf("setup transaction: %v", err)
	}
	if body, readErr := os.ReadFile(artifactPath); readErr != nil || string(body) != "closed\n" {
		t.Fatalf("setup posture = %q, %v; want changed closed posture before publication", body, readErr)
	}

	err = s.publishMultiConnectorReadyState(context.Background(), transaction, []string{"codex"}, nil)
	if err == nil || !strings.Contains(err.Error(), "restored applied connectors to their pre-setup state") {
		t.Fatalf("publication error = %v, want successful prior-posture rollback", err)
	}
	if !reflect.DeepEqual(applied.setupModes, []string{"closed", "open"}) {
		t.Fatalf("setup postures = %v, want current closed then prior open reapplication", applied.setupModes)
	}
	if applied.teardownCalls != 0 {
		t.Fatalf("teardownCalls = %d, want prior active connector re-applied rather than torn down", applied.teardownCalls)
	}
	if body, readErr := os.ReadFile(artifactPath); readErr != nil || string(body) != "open\n" {
		t.Fatalf("restored posture = %q, %v; want exact prior open posture", body, readErr)
	}
	if afterLock, readErr := os.ReadFile(filepath.Join(s.cfg.DataDir, "hook_contract_lock.json")); readErr != nil || !reflect.DeepEqual(afterLock, priorLock) {
		t.Fatalf("restored lock = %q, %v; want exact prior bytes %q", afterLock, readErr, priorLock)
	}
	if afterActive, readErr := os.ReadFile(filepath.Join(s.cfg.DataDir, "active_connector.json")); readErr != nil || !reflect.DeepEqual(afterActive, priorActive) {
		t.Fatalf("restored active state = %q, %v; want exact prior bytes %q", afterActive, readErr, priorActive)
	}
}

func TestMultiConnectorActivePublicationFailureRestoresCursorModeAndHILTPosture(t *testing.T) {
	tests := []struct {
		name        string
		priorMode   string
		priorHILT   bool
		currentMode string
		currentHILT bool
	}{
		{name: "action_to_observe_failure", priorMode: "action", priorHILT: true, currentMode: "observe"},
		{name: "observe_to_action_failure", priorMode: "observe", currentMode: "action", currentHILT: true},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			s := multiBootSidecar(t)
			s.cfg.DataDir = testenv.PrivateTempDir(t)
			s.cfg.Guardrail.Enabled = true
			s.cfg.Guardrail.Mode = test.currentMode
			s.cfg.Guardrail.Connectors = map[string]config.PerConnectorGuardrailConfig{
				"cursor": {
					Mode: test.currentMode,
					HILT: &config.HILTConfig{Enabled: test.currentHILT, MinSeverity: "HIGH"},
				},
			}
			s.health = NewSidecarHealth()

			discovery, err := json.Marshal(map[string]any{
				"agents": map[string]any{"cursor": map[string]any{"version": "cursor-agent 2026.07.23-e383d2b"}},
			})
			if err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(s.cfg.DataDir, "agent_discovery.json"), discovery, 0o600); err != nil {
				t.Fatal(err)
			}

			artifactPath := filepath.Join(testenv.PrivateTempDir(t), "cursor-registration-posture")
			priorPosture := fmt.Sprintf("%s|hilt=%t\n", test.priorMode, test.priorHILT)
			if err := os.WriteFile(artifactPath, []byte(priorPosture), 0o600); err != nil {
				t.Fatal(err)
			}
			if err := connector.SaveActiveConnectors(s.cfg.DataDir, []string{"cursor"}); err != nil {
				t.Fatal(err)
			}
			priorLockEntry := connector.HookContractLockEntry{
				Connector:           "cursor",
				RawAgentVersion:     "cursor-agent 2026.07.23-e383d2b",
				ContractID:          "cursor-hooks-v1",
				CompatibilityStatus: connector.HookCompatibilityKnown,
				HookScriptVersion:   "v8",
				HookFailMode:        "open",
				DefenseClawVersion:  "prior-build",
				RegistrationPosture: &connector.HookRegistrationPosture{
					GuardrailMode: test.priorMode,
					HILTEnabled:   test.priorHILT,
				},
			}
			if err := connector.SaveHookContractLockEntry(s.cfg.DataDir, priorLockEntry); err != nil {
				t.Fatal(err)
			}
			priorLock, err := os.ReadFile(filepath.Join(s.cfg.DataDir, "hook_contract_lock.json"))
			if err != nil {
				t.Fatal(err)
			}
			priorActive, err := os.ReadFile(filepath.Join(s.cfg.DataDir, "active_connector.json"))
			if err != nil {
				t.Fatal(err)
			}
			makeActiveConnectorPublicationUnsafe(t, s.cfg.DataDir)
			applied := &registrationPostureConnector{bootStubConnector: bootStubConnector{
				stubConnector: stubConnector{name: "cursor"},
				artifactPath:  artifactPath,
			}}

			transaction, err := s.setupConnectorsIsolatedTransaction(
				context.Background(), []connector.Connector{applied},
				"synthetic gateway token", "127.0.0.1:0", "127.0.0.1:0", "synthetic master key",
				guardrail.NewRulePackCache(),
			)
			if err != nil {
				t.Fatalf("setup transaction: %v", err)
			}
			currentPosture := fmt.Sprintf("%s|hilt=%t", test.currentMode, test.currentHILT)
			if body, readErr := os.ReadFile(artifactPath); readErr != nil || string(body) != currentPosture+"\n" {
				t.Fatalf("setup posture = %q, %v; want %q", body, readErr, currentPosture)
			}

			err = s.publishMultiConnectorReadyState(context.Background(), transaction, []string{"cursor"}, nil)
			if err == nil || !strings.Contains(err.Error(), "restored applied connectors to their pre-setup state") {
				t.Fatalf("publication error = %v, want successful prior-posture rollback", err)
			}
			wantPostures := []string{currentPosture, strings.TrimSuffix(priorPosture, "\n")}
			if !reflect.DeepEqual(applied.setupPostures, wantPostures) {
				t.Fatalf("setup postures = %v, want current then exact prior %v", applied.setupPostures, wantPostures)
			}
			if applied.teardownCalls != 0 {
				t.Fatalf("teardownCalls = %d, want prior active Cursor re-applied", applied.teardownCalls)
			}
			if body, readErr := os.ReadFile(artifactPath); readErr != nil || string(body) != priorPosture {
				t.Fatalf("restored posture = %q, %v; want %q", body, readErr, priorPosture)
			}
			if afterLock, readErr := os.ReadFile(filepath.Join(s.cfg.DataDir, "hook_contract_lock.json")); readErr != nil || !reflect.DeepEqual(afterLock, priorLock) {
				t.Fatalf("restored lock = %q, %v; want exact prior bytes %q", afterLock, readErr, priorLock)
			}
			if afterActive, readErr := os.ReadFile(filepath.Join(s.cfg.DataDir, "active_connector.json")); readErr != nil || !reflect.DeepEqual(afterActive, priorActive) {
				t.Fatalf("restored active state = %q, %v; want exact prior bytes %q", afterActive, readErr, priorActive)
			}
		})
	}
}

func TestMultiConnectorActivePublicationFailureRestoresExactOpenCodeTransaction(t *testing.T) {
	s := multiBootSidecar(t)
	s.cfg.DataDir = testenv.PrivateTempDir(t)
	s.cfg.Guardrail.Enabled = true
	s.cfg.Guardrail.Mode = "observe"
	s.health = NewSidecarHealth()
	configDir := testenv.PrivateTempDir(t)
	t.Setenv("OPENCODE_CONFIG_DIR", configDir)
	pluginPath := filepath.Join(configDir, "plugins", "defenseclaw.js")
	receiptPath := filepath.Join(s.cfg.DataDir, "connector_backups", "opencode", "config.json")

	if err := connector.SaveActiveConnectors(s.cfg.DataDir, []string{"codex", "cursor"}); err != nil {
		t.Fatal(err)
	}
	if _, err := connector.MarkConnectorInactive(s.cfg.DataDir, "hermes"); err != nil {
		t.Fatal(err)
	}
	priorActive, err := os.ReadFile(filepath.Join(s.cfg.DataDir, "active_connector.json"))
	if err != nil {
		t.Fatal(err)
	}
	priorLockEntry := connector.HookContractLockEntry{
		Connector:           "cursor",
		ContractID:          "cursor-hooks-v1",
		CompatibilityStatus: connector.HookCompatibilityKnown,
		HookScriptVersion:   "v7",
	}
	if err := connector.SaveHookContractLockEntry(s.cfg.DataDir, priorLockEntry); err != nil {
		t.Fatal(err)
	}
	priorLock, err := os.ReadFile(filepath.Join(s.cfg.DataDir, "hook_contract_lock.json"))
	if err != nil {
		t.Fatal(err)
	}
	makeActiveConnectorPublicationUnsafe(t, s.cfg.DataDir)

	transaction, err := s.setupConnectorsIsolatedTransaction(
		context.Background(), []connector.Connector{connector.NewOpenCodeConnector()},
		"synthetic gateway token", "127.0.0.1:0", "127.0.0.1:0", "synthetic master key",
		guardrail.NewRulePackCache(),
	)
	if err != nil {
		t.Fatalf("setup transaction: %v", err)
	}
	if len(transaction.succeeded) != 1 || transaction.succeeded[0] != "opencode" {
		t.Fatalf("succeeded = %v, want [opencode]", transaction.succeeded)
	}
	if _, err := os.Stat(pluginPath); err != nil {
		t.Fatalf("OpenCode plugin was not published before active-state failure: %v", err)
	}
	if _, err := os.Stat(receiptPath); err != nil {
		t.Fatalf("OpenCode receipt was not published before active-state failure: %v", err)
	}
	if got := connector.LoadHookContractLockEntry(s.cfg.DataDir, "opencode"); got.Connector != "opencode" {
		t.Fatalf("OpenCode lock was not published before active-state failure: %+v", got)
	}

	err = s.publishMultiConnectorReadyState(
		context.Background(), transaction, []string{"cursor", "opencode"}, []string{"cursor"},
	)
	if err == nil || !strings.Contains(err.Error(), "restored applied connectors to their pre-setup state") {
		t.Fatalf("publication error = %v, want successful transaction rollback", err)
	}
	if _, err := os.Stat(pluginPath); !os.IsNotExist(err) {
		t.Fatalf("failed active publication left OpenCode plugin residue: %v", err)
	}
	if _, err := os.Stat(receiptPath); !os.IsNotExist(err) {
		t.Fatalf("failed active publication left OpenCode receipt residue: %v", err)
	}
	if got := connector.LoadHookContractLockEntry(s.cfg.DataDir, "opencode"); got.Connector != "" {
		t.Fatalf("failed active publication left OpenCode lock residue: %+v", got)
	}
	afterLock, err := os.ReadFile(filepath.Join(s.cfg.DataDir, "hook_contract_lock.json"))
	if err != nil || !reflect.DeepEqual(afterLock, priorLock) {
		t.Fatalf("hook lock rollback = %q, %v; want exact prior bytes %q", afterLock, err, priorLock)
	}
	afterActive, err := os.ReadFile(filepath.Join(s.cfg.DataDir, "active_connector.json"))
	if err != nil || !reflect.DeepEqual(afterActive, priorActive) {
		t.Fatalf("active roster rollback = %q, %v; want exact prior bytes %q", afterActive, err, priorActive)
	}
	if got := connector.LoadActiveConnectors(s.cfg.DataDir); !reflect.DeepEqual(got, []string{"codex", "cursor"}) {
		t.Fatalf("active roster = %v, want exact prior [codex cursor]", got)
	}
	if !connector.ConnectorExplicitlyInactive(s.cfg.DataDir, "hermes") {
		t.Fatal("failed active publication lost unrelated inactive Hermes tombstone")
	}
	if health := s.health.Snapshot().Guardrail; health.State != StateError || !strings.Contains(health.LastError, "save active connector set with teardown retry state (cursor)") {
		t.Fatalf("guardrail health = %+v, want truthful active-publication failure", health)
	}
}

func TestMultiConnectorActivePublicationReportsIncompleteRollback(t *testing.T) {
	s := multiBootSidecar(t)
	s.cfg.DataDir = testenv.PrivateTempDir(t)
	s.cfg.Guardrail.Enabled = true
	s.cfg.Guardrail.Mode = "observe"
	s.health = NewSidecarHealth()
	if err := connector.SaveActiveConnectors(s.cfg.DataDir, []string{"codex"}); err != nil {
		t.Fatal(err)
	}
	priorActive, err := os.ReadFile(filepath.Join(s.cfg.DataDir, "active_connector.json"))
	if err != nil {
		t.Fatal(err)
	}
	makeActiveConnectorPublicationUnsafe(t, s.cfg.DataDir)
	artifactPath := filepath.Join(testenv.PrivateTempDir(t), "new-connector-hook.js")
	applied := &incompletePublicationRollbackConnector{
		bootStubConnector: bootStubConnector{
			stubConnector: stubConnector{name: "claudecode"},
			artifactPath:  artifactPath,
		},
		verifyErr: errors.New("injected verification rollback failure"),
	}

	transaction, err := s.setupConnectorsIsolatedTransaction(
		context.Background(), []connector.Connector{applied},
		"synthetic gateway token", "127.0.0.1:0", "127.0.0.1:0", "synthetic master key",
		guardrail.NewRulePackCache(),
	)
	if err != nil {
		t.Fatalf("setup transaction: %v", err)
	}
	err = s.publishMultiConnectorReadyState(
		context.Background(), transaction, []string{"claudecode"}, nil,
	)
	if err == nil || !strings.Contains(err.Error(), "multi-connector publication rollback incomplete") ||
		!strings.Contains(err.Error(), "injected verification rollback failure") {
		t.Fatalf("publication error = %v, want truthful incomplete rollback", err)
	}
	if _, err := os.Stat(artifactPath); err != nil {
		t.Fatalf("injected incomplete rollback did not leave its expected residue: %v", err)
	}
	if _, err := os.Stat(filepath.Join(s.cfg.DataDir, "hook_contract_lock.json")); !os.IsNotExist(err) {
		t.Fatalf("incomplete connector teardown also left lock residue: %v", err)
	}
	afterActive, err := os.ReadFile(filepath.Join(s.cfg.DataDir, "active_connector.json"))
	if err != nil || !reflect.DeepEqual(afterActive, priorActive) {
		t.Fatalf("active state = %q, %v; want exact prior bytes %q", afterActive, err, priorActive)
	}
	if health := s.health.Snapshot().Guardrail; health.State != StateError ||
		!strings.Contains(health.LastError, "rollback incomplete") {
		t.Fatalf("guardrail health = %+v, want truthful incomplete rollback", health)
	}
}

func TestReconcileOrphanedConnectorRegistrationCleansLegacyWindsurfBeforeRequestedSetup(t *testing.T) {
	for _, requestedConnector := range []string{"copilot", "antigravity", "opencode"} {
		t.Run(requestedConnector, func(t *testing.T) {
			dataDir := testenv.PrivateTempDir(t)
			configDir := testenv.PrivateTempDir(t)
			configPath := filepath.Join(configDir, "hooks.json")
			priorConfig := []byte("{\n  \"hooks\": {\"operator-owned\": []}\n}\n")
			if err := os.WriteFile(configPath, priorConfig, 0o600); err != nil {
				t.Fatal(err)
			}
			previousOverride := connector.WindsurfHooksPathOverride
			connector.WindsurfHooksPathOverride = configPath
			t.Cleanup(func() { connector.WindsurfHooksPathOverride = previousOverride })

			windsurf := connector.NewWindsurfConnector()
			opts := connector.SetupOpts{
				DataDir:       dataDir,
				APIAddr:       "127.0.0.1:18970",
				APIToken:      "synthetic connector token",
				HookAPIToken:  "synthetic hook token",
				HookFailMode:  "closed",
				GuardrailMode: "action",
			}
			if err := windsurf.Setup(context.Background(), opts); err != nil {
				t.Fatalf("stage legacy Windsurf registration: %v", err)
			}
			registeredConfig, err := os.ReadFile(configPath)
			if err != nil {
				t.Fatal(err)
			}
			hookScripts := windsurf.HookScripts(opts)
			registeredHook := filepath.Base(hookScripts[len(hookScripts)-1])
			if reflect.DeepEqual(registeredConfig, priorConfig) || !strings.Contains(string(registeredConfig), registeredHook) {
				t.Fatalf("fixture did not stage a Windsurf registration: %q", registeredConfig)
			}
			entry := connector.NewHookContractLockEntry(opts, windsurf, "0.8.10")
			entry.RegistrationPosture = nil // Models the pre-transaction lock found on the affected installation.
			if err := connector.SaveFreshHookContractLockEntry(dataDir, entry); err != nil {
				t.Fatalf("stage legacy Windsurf lock: %v", err)
			}
			priorRoster := []string{"claudecode", "codex", "cursor", "omnigent"}
			if err := connector.SaveActiveConnectors(dataDir, priorRoster); err != nil {
				t.Fatalf("stage prior active roster: %v", err)
			}

			requested := append(append([]string(nil), priorRoster...), requestedConnector)
			err = reconcileOrphanedConnectorRegistrations(
				context.Background(),
				connector.NewDefaultRegistry(),
				dataDir,
				requested,
				orphanConnectorReconcileOps{
					resolveOpts: func(conn connector.Connector) (connector.SetupOpts, error) {
						if conn.Name() != "windsurf" {
							return connector.SetupOpts{}, fmt.Errorf("unexpected connector %s", conn.Name())
						}
						return opts, nil
					},
					clearLock: connector.ClearHookContractLockEntry,
				},
			)
			if err != nil {
				t.Fatalf("reconcile legacy lock-only registration: %v", err)
			}
			afterConfig, err := os.ReadFile(configPath)
			if err != nil {
				t.Fatal(err)
			}
			if !reflect.DeepEqual(afterConfig, priorConfig) {
				t.Fatalf("Windsurf config = %q, want exact prior bytes %q", afterConfig, priorConfig)
			}
			if got := connector.LoadHookContractLockEntry(dataDir, "windsurf"); got.Connector != "" {
				t.Fatalf("orphaned Windsurf lock survived cleanup: %+v", got)
			}
			if got := connector.LoadActiveConnectors(dataDir); !reflect.DeepEqual(got, priorRoster) {
				t.Fatalf("active roster = %v, want exact prior %v", got, priorRoster)
			}
			if !connector.ConnectorExplicitlyInactive(dataDir, "windsurf") {
				t.Fatal("orphaned Windsurf cleanup did not retain its inactive tombstone")
			}
		})
	}
}

func TestReconcileOrphanedConnectorRegistrationFailureRestoresExactActiveState(t *testing.T) {
	for _, tc := range []struct {
		name                 string
		teardownErr          error
		verifyErr            error
		clearErr             error
		removeHookOnTeardown bool
		wantHook             bool
		wantError            string
	}{
		{name: "teardown", teardownErr: errors.New("injected teardown failure"), wantHook: true, wantError: "teardown lock-only connector"},
		{name: "verify", verifyErr: errors.New("injected verify failure"), wantHook: true, wantError: "verify lock-only connector"},
		{name: "lock-clear", clearErr: errors.New("injected lock clear failure"), removeHookOnTeardown: true, wantError: "clear lock-only connector"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dataDir := testenv.PrivateTempDir(t)
			hookPath := filepath.Join(testenv.PrivateTempDir(t), "windsurf-hook")
			const hookBody = "truthful pre-reconciliation hook bytes\n"
			if err := os.WriteFile(hookPath, []byte(hookBody), 0o600); err != nil {
				t.Fatal(err)
			}
			conn := &orphanReconcileFailureConnector{
				bootStubConnector: bootStubConnector{
					stubConnector: stubConnector{name: "windsurf"},
					artifactPath:  hookPath,
				},
				hookPath:             hookPath,
				removeHookOnTeardown: tc.removeHookOnTeardown,
				teardownErr:          tc.teardownErr,
				verifyErr:            tc.verifyErr,
			}
			opts := connector.SetupOpts{
				DataDir:       dataDir,
				HookFailMode:  "closed",
				GuardrailMode: "action",
			}
			if err := connector.SaveFreshHookContractLockEntry(
				dataDir,
				connector.NewHookContractLockEntry(opts, conn, "0.8.10"),
			); err != nil {
				t.Fatal(err)
			}
			priorRoster := []string{"claudecode", "codex", "cursor", "omnigent"}
			if err := connector.SaveActiveConnectors(dataDir, priorRoster); err != nil {
				t.Fatal(err)
			}
			activePath := filepath.Join(dataDir, "active_connector.json")
			lockPath := filepath.Join(dataDir, "hook_contract_lock.json")
			priorActive, err := os.ReadFile(activePath)
			if err != nil {
				t.Fatal(err)
			}
			priorLock, err := os.ReadFile(lockPath)
			if err != nil {
				t.Fatal(err)
			}
			registry := connector.NewRegistry()
			registry.RegisterBuiltin(conn)
			clearCalls := 0
			err = reconcileOrphanedConnectorRegistrations(
				context.Background(),
				registry,
				dataDir,
				append(append([]string(nil), priorRoster...), "copilot"),
				orphanConnectorReconcileOps{
					resolveOpts: func(connector.Connector) (connector.SetupOpts, error) { return opts, nil },
					clearLock: func(dataDir, name string) error {
						clearCalls++
						if tc.clearErr != nil {
							return tc.clearErr
						}
						return connector.ClearHookContractLockEntry(dataDir, name)
					},
				},
			)
			if err == nil || !strings.Contains(err.Error(), tc.wantError) {
				t.Fatalf("reconciliation error = %v, want %q", err, tc.wantError)
			}
			if body, readErr := os.ReadFile(activePath); readErr != nil || !reflect.DeepEqual(body, priorActive) {
				t.Fatalf("active state = %q, %v; want exact prior bytes %q", body, readErr, priorActive)
			}
			if connector.ConnectorExplicitlyInactive(dataDir, "windsurf") {
				t.Fatal("failed reconciliation committed a new inactive tombstone")
			}
			if body, readErr := os.ReadFile(lockPath); readErr != nil || !reflect.DeepEqual(body, priorLock) {
				t.Fatalf("lock state = %q, %v; want exact prior bytes %q", body, readErr, priorLock)
			}
			hookBodyAfter, hookErr := os.ReadFile(hookPath)
			if tc.wantHook {
				if hookErr != nil || string(hookBodyAfter) != hookBody {
					t.Fatalf("hook state = %q, %v; want exact prior hook bytes", hookBodyAfter, hookErr)
				}
			} else if !os.IsNotExist(hookErr) {
				t.Fatalf("verified cleanup left hook state %q, %v", hookBodyAfter, hookErr)
			}
			if tc.clearErr != nil && clearCalls != 1 {
				t.Fatalf("lock clear calls = %d, want 1", clearCalls)
			}
		})
	}
}

func TestReconcileOrphanedConnectorRegistrationRequiresProtectedActiveAuthority(t *testing.T) {
	for _, tc := range []struct {
		name       string
		activeBody []byte
	}{
		{name: "missing"},
		{name: "malformed", activeBody: []byte("{malformed active state")},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dataDir := testenv.PrivateTempDir(t)
			hookPath := filepath.Join(testenv.PrivateTempDir(t), "windsurf-hook")
			const hookBody = "protected orphan hook bytes\n"
			if err := os.WriteFile(hookPath, []byte(hookBody), 0o600); err != nil {
				t.Fatal(err)
			}
			conn := &orphanReconcileFailureConnector{
				bootStubConnector: bootStubConnector{
					stubConnector: stubConnector{name: "windsurf"},
					artifactPath:  hookPath,
				},
				hookPath: hookPath,
			}
			opts := connector.SetupOpts{DataDir: dataDir, HookFailMode: "closed", GuardrailMode: "action"}
			if err := connector.SaveFreshHookContractLockEntry(
				dataDir,
				connector.NewHookContractLockEntry(opts, conn, "0.8.10"),
			); err != nil {
				t.Fatal(err)
			}
			activePath := filepath.Join(dataDir, "active_connector.json")
			if tc.activeBody != nil {
				if err := os.WriteFile(activePath, tc.activeBody, 0o600); err != nil {
					t.Fatal(err)
				}
			}
			lockPath := filepath.Join(dataDir, "hook_contract_lock.json")
			priorLock, err := os.ReadFile(lockPath)
			if err != nil {
				t.Fatal(err)
			}
			registry := connector.NewRegistry()
			registry.RegisterBuiltin(conn)
			clearCalls := 0
			err = reconcileOrphanedConnectorRegistrations(
				context.Background(),
				registry,
				dataDir,
				[]string{"claudecode", "codex", "copilot", "cursor", "omnigent"},
				orphanConnectorReconcileOps{
					resolveOpts: func(connector.Connector) (connector.SetupOpts, error) { return opts, nil },
					clearLock: func(dataDir, name string) error {
						clearCalls++
						return connector.ClearHookContractLockEntry(dataDir, name)
					},
				},
			)
			if err == nil || !strings.Contains(err.Error(), "protected active connector") {
				t.Fatalf("reconciliation error = %v, want protected active-state failure", err)
			}
			if conn.teardownCalls != 0 || clearCalls != 0 {
				t.Fatalf("destructive calls = teardown %d clear %d, want zero", conn.teardownCalls, clearCalls)
			}
			if body, readErr := os.ReadFile(lockPath); readErr != nil || !reflect.DeepEqual(body, priorLock) {
				t.Fatalf("lock state = %q, %v; want exact prior bytes %q", body, readErr, priorLock)
			}
			if body, readErr := os.ReadFile(hookPath); readErr != nil || string(body) != hookBody {
				t.Fatalf("hook state = %q, %v; want exact prior bytes", body, readErr)
			}
			if tc.activeBody == nil {
				if _, statErr := os.Stat(activePath); !os.IsNotExist(statErr) {
					t.Fatalf("missing active state was mutated: %v", statErr)
				}
			} else if body, readErr := os.ReadFile(activePath); readErr != nil || !reflect.DeepEqual(body, tc.activeBody) {
				t.Fatalf("malformed active state = %q, %v; want exact bytes %q", body, readErr, tc.activeBody)
			}
		})
	}
}

func TestMultiConnectorPublicationFailureRestoresSuccessfullyRemovedConnector(t *testing.T) {
	s := multiBootSidecar(t)
	s.cfg.DataDir = testenv.PrivateTempDir(t)
	s.cfg.Guardrail.Enabled = true
	s.cfg.Guardrail.Mode = "observe"
	s.cfg.Guardrail.Connectors = map[string]config.PerConnectorGuardrailConfig{
		"claudecode": {Mode: "observe"},
	}
	s.health = NewSidecarHealth()
	removedArtifact := filepath.Join(testenv.PrivateTempDir(t), "removed-cursor-posture")
	removed := &registrationPostureConnector{bootStubConnector: bootStubConnector{
		stubConnector: stubConnector{name: "cursor"},
		artifactPath:  removedArtifact,
	}}
	survivor := &bootStubConnector{stubConnector: stubConnector{name: "claudecode"}}
	registry := connector.NewRegistry()
	registry.RegisterBuiltin(removed)
	registry.RegisterBuiltin(survivor)

	priorOpts := connector.SetupOpts{
		DataDir:        s.cfg.DataDir,
		GuardrailMode:  "action",
		HILTEnabled:    true,
		HookFailMode:   "closed",
		AgentVersion:   "cursor-agent 2026.07.23-e383d2b",
		HookContractID: "cursor-hooks-v1",
	}
	priorEntry := connector.NewHookContractLockEntry(priorOpts, removed, "prior-test-build")
	if err := connector.SaveHookContractLockEntry(s.cfg.DataDir, priorEntry); err != nil {
		t.Fatal(err)
	}
	if err := connector.SaveActiveConnectors(s.cfg.DataDir, []string{"cursor"}); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(removedArtifact, []byte("action|hilt=true\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	priorLockBytes, err := os.ReadFile(filepath.Join(s.cfg.DataDir, "hook_contract_lock.json"))
	if err != nil {
		t.Fatal(err)
	}
	priorActiveBytes, err := os.ReadFile(filepath.Join(s.cfg.DataDir, "active_connector.json"))
	if err != nil {
		t.Fatal(err)
	}
	activeState, err := connector.CaptureActiveConnectorStateSnapshot(s.cfg.DataDir)
	if err != nil {
		t.Fatal(err)
	}
	hookLockState, err := connector.CaptureHookContractLockSnapshot(s.cfg.DataDir)
	if err != nil {
		t.Fatal(err)
	}
	seed := multiConnectorSetupTransaction{activeState: activeState, hookLockState: hookLockState}
	candidates, unavailable := s.removedConnectorRollbackCandidates(
		registry, []string{"cursor"}, []string{"claudecode"},
		"synthetic gateway token", "127.0.0.1:0", "127.0.0.1:0", "synthetic master key",
		hookLockState,
	)
	if len(unavailable) != 0 || len(candidates) != 1 {
		t.Fatalf("removal candidates=%v unavailable=%v, want one rollback-authorized Cursor", candidates, unavailable)
	}
	seed.removed, unavailable = teardownRemovedConnectorCandidates(candidates, context.Background())
	if len(unavailable) != 0 || len(seed.removed) != 1 {
		t.Fatalf("removed=%v failed=%v, want successful transactional removal", seed.removed, unavailable)
	}
	if _, err := os.Stat(removedArtifact); !os.IsNotExist(err) {
		t.Fatalf("successful removal left Cursor runtime artifact: %v", err)
	}
	if lock := connector.LoadHookContractLockEntry(s.cfg.DataDir, "cursor"); lock.Connector != "" {
		t.Fatalf("successful removal left Cursor lock: %+v", lock)
	}

	transaction, err := s.setupConnectorsIsolatedTransaction(
		context.Background(), []connector.Connector{survivor},
		"synthetic gateway token", "127.0.0.1:0", "127.0.0.1:0", "synthetic master key",
		guardrail.NewRulePackCache(), seed,
	)
	if err != nil {
		t.Fatalf("survivor setup transaction: %v", err)
	}
	makeActiveConnectorPublicationUnsafe(t, s.cfg.DataDir)
	err = s.publishMultiConnectorReadyState(context.Background(), transaction, []string{"claudecode"}, nil)
	if err == nil || !strings.Contains(err.Error(), "restored applied connectors") {
		t.Fatalf("publication error = %v, want successful transaction rollback", err)
	}
	if removed.teardownCalls != 1 || removed.setupCalls != 1 {
		t.Fatalf("removed Cursor lifecycle = teardown %d setup %d, want one removal and one restoration", removed.teardownCalls, removed.setupCalls)
	}
	if !reflect.DeepEqual(removed.setupPostures, []string{"action|hilt=true"}) {
		t.Fatalf("restored Cursor posture = %v, want exact prior action/HILT posture", removed.setupPostures)
	}
	if body, readErr := os.ReadFile(removedArtifact); readErr != nil || string(body) != "action|hilt=true\n" {
		t.Fatalf("restored Cursor artifact = %q, %v", body, readErr)
	}
	if body, readErr := os.ReadFile(filepath.Join(s.cfg.DataDir, "hook_contract_lock.json")); readErr != nil || !reflect.DeepEqual(body, priorLockBytes) {
		t.Fatalf("restored lock = %q, %v; want exact prior bytes %q", body, readErr, priorLockBytes)
	}
	if body, readErr := os.ReadFile(filepath.Join(s.cfg.DataDir, "active_connector.json")); readErr != nil || !reflect.DeepEqual(body, priorActiveBytes) {
		t.Fatalf("restored roster = %q, %v; want exact prior bytes %q", body, readErr, priorActiveBytes)
	}
}

func TestSingleConnectorSwitchFailureRestoresExactPriorConnector(t *testing.T) {
	s := multiBootSidecar(t)
	s.cfg.DataDir = testenv.PrivateTempDir(t)
	s.cfg.Guardrail.Enabled = true
	s.cfg.Guardrail.Mode = "observe"
	s.cfg.Guardrail.Connector = "claudecode"
	s.cfg.Guardrail.Connectors = nil
	s.health = NewSidecarHealth()
	priorArtifact := filepath.Join(testenv.PrivateTempDir(t), "prior-cursor-posture")
	requestedArtifact := filepath.Join(testenv.PrivateTempDir(t), "requested-claude-posture")
	prior := &registrationPostureConnector{bootStubConnector: bootStubConnector{
		stubConnector: stubConnector{name: "cursor"},
		artifactPath:  priorArtifact,
	}}
	requested := &registrationPostureConnector{bootStubConnector: bootStubConnector{
		stubConnector: stubConnector{name: "claudecode"},
		artifactPath:  requestedArtifact,
	}}
	registry := connector.NewRegistry()
	registry.RegisterBuiltin(prior)
	registry.RegisterBuiltin(requested)

	priorOpts := connector.SetupOpts{
		DataDir:        s.cfg.DataDir,
		GuardrailMode:  "action",
		HILTEnabled:    true,
		HookFailMode:   "closed",
		AgentVersion:   "cursor-agent 2026.07.23-e383d2b",
		HookContractID: "cursor-hooks-v1",
	}
	priorEntry := connector.NewHookContractLockEntry(priorOpts, prior, "prior-test-build")
	if err := connector.SaveHookContractLockEntry(s.cfg.DataDir, priorEntry); err != nil {
		t.Fatal(err)
	}
	if err := connector.SaveActiveConnectors(s.cfg.DataDir, []string{"cursor"}); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(priorArtifact, []byte("action|hilt=true\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	priorLockBytes, err := os.ReadFile(filepath.Join(s.cfg.DataDir, "hook_contract_lock.json"))
	if err != nil {
		t.Fatal(err)
	}
	priorActiveBytes, err := os.ReadFile(filepath.Join(s.cfg.DataDir, "active_connector.json"))
	if err != nil {
		t.Fatal(err)
	}
	requestedOpts := mustConnectorSetupOpts(
		t, s, requested, "synthetic gateway token", "127.0.0.1:0", "127.0.0.1:0",
	)
	authority, err := captureSingleConnectorRollbackAuthority(requestedOpts, requested)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.teardownPreviousConnectorTransaction(
		context.Background(), registry, requested,
		"synthetic gateway token", "127.0.0.1:0", "127.0.0.1:0", "synthetic master key",
		&authority,
	); err != nil {
		t.Fatalf("transactional prior teardown: %v", err)
	}
	if len(authority.removed) != 1 || authority.removed[0].conn.Name() != "cursor" {
		t.Fatalf("captured removed authority = %+v, want prior Cursor", authority.removed)
	}
	if _, err := os.Stat(priorArtifact); !os.IsNotExist(err) {
		t.Fatalf("prior Cursor was not removed before requested setup: %v", err)
	}
	if lock := connector.LoadHookContractLockEntry(s.cfg.DataDir, "cursor"); lock.Connector != "" {
		t.Fatalf("prior Cursor lock remained after successful switch teardown: %+v", lock)
	}
	if err := requested.Setup(context.Background(), requestedOpts); err != nil {
		t.Fatal(err)
	}
	makeActiveConnectorPublicationUnsafe(t, s.cfg.DataDir)
	err = s.saveSingleConnectorReadyState(context.Background(), requestedOpts, requested, authority)
	if err == nil || !strings.Contains(err.Error(), "active state save failed") {
		t.Fatalf("requested publication error = %v, want active-state failure", err)
	}
	if prior.teardownCalls != 1 || prior.setupCalls != 1 {
		t.Fatalf("prior Cursor lifecycle = teardown %d setup %d, want one switch removal and one rollback reapply", prior.teardownCalls, prior.setupCalls)
	}
	if !reflect.DeepEqual(prior.setupPostures, []string{"action|hilt=true"}) {
		t.Fatalf("prior Cursor restored posture = %v, want exact action/HILT posture", prior.setupPostures)
	}
	if body, readErr := os.ReadFile(priorArtifact); readErr != nil || string(body) != "action|hilt=true\n" {
		t.Fatalf("restored prior artifact = %q, %v", body, readErr)
	}
	if _, err := os.Stat(requestedArtifact); !os.IsNotExist(err) {
		t.Fatalf("failed requested connector left runtime artifact: %v", err)
	}
	if body, readErr := os.ReadFile(filepath.Join(s.cfg.DataDir, "hook_contract_lock.json")); readErr != nil || !reflect.DeepEqual(body, priorLockBytes) {
		t.Fatalf("restored lock = %q, %v; want exact prior bytes %q", body, readErr, priorLockBytes)
	}
	if body, readErr := os.ReadFile(filepath.Join(s.cfg.DataDir, "active_connector.json")); readErr != nil || !reflect.DeepEqual(body, priorActiveBytes) {
		t.Fatalf("restored roster = %q, %v; want exact prior bytes %q", body, readErr, priorActiveBytes)
	}
}

func TestSingleConnectorSwitchOpenCodeSnapshotFailureLeavesPriorConnectorUntouched(t *testing.T) {
	s := multiBootSidecar(t)
	s.cfg.DataDir = testenv.PrivateTempDir(t)
	s.cfg.Guardrail.Enabled = true
	s.cfg.Guardrail.Mode = "observe"
	s.cfg.Guardrail.Connector = "opencode"
	s.cfg.Guardrail.Connectors = nil
	s.health = NewSidecarHealth()

	priorArtifact := filepath.Join(testenv.PrivateTempDir(t), "prior-cursor-posture")
	prior := &registrationPostureConnector{bootStubConnector: bootStubConnector{
		stubConnector: stubConnector{name: "cursor"},
		artifactPath:  priorArtifact,
	}}
	requested := &bootStubConnector{stubConnector: stubConnector{name: "opencode"}}
	registry := connector.NewRegistry()
	registry.RegisterBuiltin(prior)
	registry.RegisterBuiltin(requested)

	priorOpts := connector.SetupOpts{
		DataDir:        s.cfg.DataDir,
		GuardrailMode:  "action",
		HILTEnabled:    true,
		HookFailMode:   "closed",
		AgentVersion:   "cursor-agent 2026.07.23-e383d2b",
		HookContractID: "cursor-hooks-v1",
	}
	if err := connector.SaveHookContractLockEntry(
		s.cfg.DataDir, connector.NewHookContractLockEntry(priorOpts, prior, "prior-test-build"),
	); err != nil {
		t.Fatal(err)
	}
	if err := connector.SaveActiveConnectors(s.cfg.DataDir, []string{"cursor"}); err != nil {
		t.Fatal(err)
	}
	const priorArtifactBody = "action|hilt=true\n"
	if err := os.WriteFile(priorArtifact, []byte(priorArtifactBody), 0o600); err != nil {
		t.Fatal(err)
	}
	priorLockBytes, err := os.ReadFile(filepath.Join(s.cfg.DataDir, "hook_contract_lock.json"))
	if err != nil {
		t.Fatal(err)
	}
	priorActiveBytes, err := os.ReadFile(filepath.Join(s.cfg.DataDir, "active_connector.json"))
	if err != nil {
		t.Fatal(err)
	}

	unsafeTarget := filepath.Join(testenv.PrivateTempDir(t), "defenseclaw.js")
	if err := os.Mkdir(unsafeTarget, 0o700); err != nil {
		t.Fatal(err)
	}
	previousPluginPath := connector.OpenCodePluginPathOverride
	connector.OpenCodePluginPathOverride = unsafeTarget
	t.Cleanup(func() { connector.OpenCodePluginPathOverride = previousPluginPath })
	requestedOpts := connector.SetupOpts{
		DataDir:        s.cfg.DataDir,
		GuardrailMode:  "observe",
		HookFailMode:   "open",
		AgentVersion:   "1.18.11",
		HookContractID: "opencode-hooks-v1",
	}

	_, err = s.prepareSingleConnectorSetupTransaction(
		context.Background(), registry, requestedOpts, requested,
		"synthetic gateway token", "127.0.0.1:0", "127.0.0.1:0", "synthetic master key",
	)
	if err == nil || !strings.Contains(err.Error(), "connector opencode rollback snapshot failed before setup") {
		t.Fatalf("OpenCode snapshot preflight error = %v", err)
	}
	if prior.teardownCalls != 0 || prior.setupCalls != 0 {
		t.Fatalf("prior Cursor lifecycle = teardown %d setup %d, want no mutation before failed OpenCode snapshot", prior.teardownCalls, prior.setupCalls)
	}
	if requested.setupCalls != 0 || requested.teardownCalls != 0 {
		t.Fatalf("requested OpenCode lifecycle = setup %d teardown %d, want no mutation after failed snapshot", requested.setupCalls, requested.teardownCalls)
	}
	if body, readErr := os.ReadFile(priorArtifact); readErr != nil || string(body) != priorArtifactBody {
		t.Fatalf("prior Cursor artifact = %q, %v; want exact original", body, readErr)
	}
	if body, readErr := os.ReadFile(filepath.Join(s.cfg.DataDir, "hook_contract_lock.json")); readErr != nil || !reflect.DeepEqual(body, priorLockBytes) {
		t.Fatalf("lock after failed OpenCode snapshot = %q, %v; want exact prior bytes %q", body, readErr, priorLockBytes)
	}
	if body, readErr := os.ReadFile(filepath.Join(s.cfg.DataDir, "active_connector.json")); readErr != nil || !reflect.DeepEqual(body, priorActiveBytes) {
		t.Fatalf("roster after failed OpenCode snapshot = %q, %v; want exact prior bytes %q", body, readErr, priorActiveBytes)
	}
	if info, statErr := os.Stat(unsafeTarget); statErr != nil || !info.IsDir() {
		t.Fatalf("unsafe OpenCode target changed during snapshot preflight: %v, %+v", statErr, info)
	}
	if _, statErr := os.Stat(filepath.Join(s.cfg.DataDir, "connector_backups", "opencode", "config.json")); !os.IsNotExist(statErr) {
		t.Fatalf("failed OpenCode snapshot left custody receipt mutation: %v", statErr)
	}
}

// TestSetupConnectorsIsolated_DN1_MiddleFailsOthersSurvive is the DN1
// failure-isolation tripwire: with three connectors where the MIDDLE one fails
// Setup, the other two must still come up. A regression that aborted the loop
// on first failure (or let a panic cascade) would drop the survivors here.
func TestSetupConnectorsIsolated_DN1_MiddleFailsOthersSurvive(t *testing.T) {
	s := multiBootSidecar(t)
	first := &bootStubConnector{stubConnector: stubConnector{name: "codex"}}
	middle := &bootStubConnector{stubConnector: stubConnector{name: "claudecode"}, setupErr: errors.New("middle boom")}
	last := &bootStubConnector{stubConnector: stubConnector{name: "codex"}}

	got, err := s.setupConnectorsIsolated(
		context.Background(),
		[]connector.Connector{first, middle, last},
		"tok", "127.0.0.1:0", "127.0.0.1:0", "master",
		guardrail.NewRulePackCache(),
	)
	if err != nil {
		t.Fatalf("setupConnectorsIsolated: %v", err)
	}

	want := []string{"codex", "codex"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("survivors=%v, want %v (middle connector failure must not cascade)", got, want)
	}
	// Every connector's Setup must have been attempted — the failing one in
	// the middle must not short-circuit the connector after it.
	if first.setupCalls != 1 || middle.setupCalls != 1 || last.setupCalls != 1 {
		t.Errorf("setupCalls first(codex)=%d middle(claudecode)=%d last(codex)=%d, want 1/1/1",
			first.setupCalls, middle.setupCalls, last.setupCalls)
	}
	if middle.teardownCalls != 1 {
		t.Errorf("failed connector teardownCalls=%d, want 1 rollback", middle.teardownCalls)
	}
}

// TestSetupConnectorsIsolated_AllFailReturnsEmpty confirms that when every
// connector fails the result is empty (the caller turns this into a loud boot
// failure rather than idling on a gateway that protects nothing).
func TestSetupConnectorsIsolated_AllFailReturnsEmpty(t *testing.T) {
	s := multiBootSidecar(t)
	conns := []connector.Connector{
		&bootStubConnector{stubConnector: stubConnector{name: "codex"}, setupErr: errors.New("x")},
		&bootStubConnector{stubConnector: stubConnector{name: "cursor"}, setupErr: errors.New("y")},
	}
	got, err := s.setupConnectorsIsolated(context.Background(), conns, "tok", "127.0.0.1:0", "127.0.0.1:0", "master", guardrail.NewRulePackCache())
	if err != nil {
		t.Fatalf("setupConnectorsIsolated: %v", err)
	}
	if len(got) != 0 {
		t.Errorf("all-fail must yield empty survivor set, got %v", got)
	}
}

func TestSetupConnectorsIsolated_InvalidRulePackDoesNotBlockValidPeer(t *testing.T) {
	resetConnectorRuleCategories(t)
	mustApplyConnectorRulePack(t, "codex", secretOverridePack("STALE-CODEX", `stale_codex_token`))

	s := multiBootSidecar(t)
	s.cfg.Guardrail.Connectors = map[string]config.PerConnectorGuardrailConfig{
		"codex":      {RulePackDir: invalidRulePackDir(t)},
		"claudecode": {RulePackDir: ""},
	}
	invalid := &bootStubConnector{stubConnector: stubConnector{name: "codex"}}
	valid := &bootStubConnector{stubConnector: stubConnector{name: "claudecode"}}

	got, err := s.setupConnectorsIsolated(
		context.Background(),
		[]connector.Connector{invalid, valid},
		"tok", "127.0.0.1:0", "127.0.0.1:0", "master",
		guardrail.NewRulePackCache(),
	)
	if err != nil {
		t.Fatalf("setupConnectorsIsolated: %v", err)
	}
	if want := []string{"claudecode"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("survivors = %v, want %v", got, want)
	}
	if invalid.setupCalls != 0 || invalid.credsSet {
		t.Fatalf("invalid connector mutated before rejection: setup=%d credentials=%t", invalid.setupCalls, invalid.credsSet)
	}
	if valid.setupCalls != 1 || !valid.credsSet {
		t.Fatalf("valid connector did not activate: setup=%d credentials=%t", valid.setupCalls, valid.credsSet)
	}
	ruleCategoriesMu.RLock()
	_, invalidOverridePresent := connectorRuleCategories["codex"]
	_, validOverridePresent := connectorRuleCategories["claudecode"]
	ruleCategoriesMu.RUnlock()
	if invalidOverridePresent || !validOverridePresent {
		t.Fatalf(
			"connector overrides after isolated setup: invalid=%t valid=%t, want false/true",
			invalidOverridePresent,
			validOverridePresent,
		)
	}
}

func TestManagedMultiConnectorAllInvalidRulePacksReturnsErrorWithoutPanic(t *testing.T) {
	resetConnectorRuleCategories(t)
	mustApplyConnectorRulePack(t, "codex", secretOverridePack("STALE-CODEX", `stale_codex_token`))
	mustApplyConnectorRulePack(t, "claudecode", secretOverridePack("STALE-CLAUDE", `stale_claude_token`))

	s := multiBootSidecar(t)
	s.health = NewSidecarHealth()
	s.cfg.DeploymentMode = string(config.DeploymentModeManagedEnterprise)
	s.cfg.Guardrail.Enabled = true
	s.cfg.Guardrail.Connectors = map[string]config.PerConnectorGuardrailConfig{
		"codex":      {RulePackDir: invalidRulePackDir(t)},
		"claudecode": {RulePackDir: invalidRulePackDir(t)},
	}
	registry := connector.NewRegistry()
	first := &bootStubConnector{stubConnector: stubConnector{name: "codex"}}
	second := &bootStubConnector{stubConnector: stubConnector{name: "claudecode"}}
	registry.RegisterBuiltin(first)
	registry.RegisterBuiltin(second)

	err := s.runManagedEnterpriseMultiHookGuardrail(
		context.Background(),
		registry,
		[]connector.Connector{first, second},
		"gateway-token", "127.0.0.1:0", "127.0.0.1:0", "master",
	)
	if err == nil || !strings.Contains(err.Error(), "all 2 configured connectors") {
		t.Fatalf("managed all-invalid error = %v", err)
	}
	if first.credsSet || second.credsSet {
		t.Fatal("invalid managed connectors received credentials before policy preflight")
	}
	ruleCategoriesMu.RLock()
	_, firstOverridePresent := connectorRuleCategories["codex"]
	_, secondOverridePresent := connectorRuleCategories["claudecode"]
	ruleCategoriesMu.RUnlock()
	if firstOverridePresent || secondOverridePresent {
		t.Fatalf(
			"rejected managed connectors retained stale overrides: codex=%t claudecode=%t",
			firstOverridePresent,
			secondOverridePresent,
		)
	}
}

func TestSetupConnectorsIsolatedPreflightsAllScopedTokens(t *testing.T) {
	s := multiBootSidecar(t)
	s.cfg.DataDir = failingHookTokenDataDir(t)
	s.cfg.DeploymentMode = string(config.DeploymentModeManagedEnterprise)
	first := &bootStubConnector{stubConnector: stubConnector{name: "codex"}}
	second := &hookBootStubConnector{bootStubConnector: bootStubConnector{stubConnector: stubConnector{name: "cursor"}}}

	got, err := s.setupConnectorsIsolated(
		context.Background(), []connector.Connector{first, second}, "gateway-token", "a", "b", "master", guardrail.NewRulePackCache(),
	)
	if err == nil || !strings.Contains(err.Error(), "scoped hook token") {
		t.Fatalf("setupConnectorsIsolated error = %v, want scoped-token failure", err)
	}
	if len(got) != 0 {
		t.Fatalf("succeeded = %v, want none after preflight failure", got)
	}
	if first.setupCalls != 0 || second.setupCalls != 0 {
		t.Fatalf("setup calls = %d/%d, want none before every scoped token passes", first.setupCalls, second.setupCalls)
	}
	if first.credsSet || second.credsSet {
		t.Fatal("credentials were installed before every scoped token passed preflight")
	}
}

// TestConnectorSetupOpts_PerConnectorHookFailMode verifies the per-connector
// hook_fail_mode override flows into the SetupOpts via EffectiveHookFailModeFor
// — the global fail mode for connectors without an override, the override
// value for those that set one.
func TestConnectorSetupOpts_PerConnectorHookFailMode(t *testing.T) {
	s := multiBootSidecar(t)
	s.cfg.Guardrail.Mode = "action"
	s.cfg.Guardrail.HookFailMode = "open"
	s.cfg.Guardrail.Connectors = map[string]config.PerConnectorGuardrailConfig{
		"cursor":   {Mode: "action", HookFailMode: "closed"},
		"windsurf": {Mode: "observe", HookFailMode: "closed"},
	}

	codexOpts := mustConnectorSetupOpts(t, s, &bootStubConnector{stubConnector: stubConnector{name: "codex"}}, "tok", "a", "b")
	if codexOpts.HookFailMode != "open" {
		t.Errorf("codex HookFailMode=%q, want global %q", codexOpts.HookFailMode, "open")
	}
	cursorOpts := mustConnectorSetupOpts(t, s, &bootStubConnector{stubConnector: stubConnector{name: "cursor"}}, "tok", "a", "b")
	if cursorOpts.HookFailMode != "closed" {
		t.Errorf("cursor HookFailMode=%q, want override %q", cursorOpts.HookFailMode, "closed")
	}
	if cursorOpts.GuardrailMode != "action" {
		t.Errorf("cursor GuardrailMode=%q, want action", cursorOpts.GuardrailMode)
	}
	windsurfOpts := mustConnectorSetupOpts(t, s, &bootStubConnector{stubConnector: stubConnector{name: "windsurf"}}, "tok", "a", "b")
	if windsurfOpts.HookFailMode != "closed" {
		t.Errorf("windsurf HookFailMode=%q, want connector override independent of observe mode", windsurfOpts.HookFailMode)
	}
	if windsurfOpts.GuardrailMode != "observe" {
		t.Errorf("windsurf GuardrailMode=%q, want observe", windsurfOpts.GuardrailMode)
	}
}

func TestStartMultiHookConfigGuards_StartsOnePerSuccessfulConnector(t *testing.T) {
	s := multiBootSidecar(t)
	s.cfg.Guardrail.Enabled = true
	s.cfg.Guardrail.HookSelfHeal = true
	s.cfg.Guardrail.HookSelfHealDebounceMs = 1
	reg := connector.NewRegistry()
	reg.RegisterBuiltin(&bootStubConnector{stubConnector: stubConnector{name: "codex"}})
	reg.RegisterBuiltin(&bootStubConnector{stubConnector: stubConnector{name: "cursor"}})

	// Cancellation makes the long-running loop return immediately after its
	// synchronous bootstrap, so assertions inspect durable state without a
	// machine-speed-dependent readiness deadline.
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	guards, err := s.startMultiHookConfigGuards(ctx, reg, []string{"codex", "cursor"}, "tok", "127.0.0.1:0", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("startMultiHookConfigGuards: %v", err)
	}
	defer stopHookConfigGuards(guards)

	if len(guards) != 2 {
		t.Fatalf("guards=%d, want 2", len(guards))
	}
	got := []string{guards[0].conn.Name(), guards[1].conn.Name()}
	want := []string{"codex", "cursor"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("guard connectors=%v, want %v", got, want)
	}
}

func TestStartMultiHookConfigGuards_DisabledSelfHealStartsNone(t *testing.T) {
	s := multiBootSidecar(t)
	s.cfg.Guardrail.Enabled = true
	s.cfg.Guardrail.HookSelfHeal = false
	reg := connector.NewRegistry()
	reg.RegisterBuiltin(&bootStubConnector{stubConnector: stubConnector{name: "codex"}})

	guards, err := s.startMultiHookConfigGuards(context.Background(), reg, []string{"codex"}, "tok", "127.0.0.1:0", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("startMultiHookConfigGuards: %v", err)
	}
	if len(guards) != 0 {
		t.Fatalf("guards=%d, want 0", len(guards))
	}
}

func TestManagedMultiHookGuardrailFailsClosedWhenScopedTokenFails(t *testing.T) {
	conn := &hookBootStubConnector{bootStubConnector: bootStubConnector{stubConnector: stubConnector{name: "codex"}}}
	reg := connector.NewRegistry()
	reg.RegisterBuiltin(conn)
	s := &Sidecar{
		cfg: &config.Config{
			DataDir:        failingHookTokenDataDir(t),
			DeploymentMode: string(config.DeploymentModeManagedEnterprise),
			Guardrail:      config.GuardrailConfig{Enabled: true},
		},
		health: NewSidecarHealth(),
	}

	err := s.runManagedEnterpriseMultiHookGuardrail(context.Background(), reg, []connector.Connector{conn}, "gateway-token", "a", "b", "master")
	if err == nil || !strings.Contains(err.Error(), "scoped hook token") {
		t.Fatalf("runManagedEnterpriseMultiHookGuardrail error = %v, want scoped-token failure", err)
	}
	if conn.credsSet {
		t.Fatal("connector credentials were installed after scoped-token setup failed")
	}
	if state := s.health.Snapshot().Guardrail.State; state != StateError {
		t.Fatalf("guardrail health state = %s, want %s", state, StateError)
	}
}

func TestManagedMultiHookGuardrailPreflightsAllScopedTokens(t *testing.T) {
	first := &bootStubConnector{stubConnector: stubConnector{name: "codex"}}
	second := &hookBootStubConnector{bootStubConnector: bootStubConnector{stubConnector: stubConnector{name: "cursor"}}}
	reg := connector.NewRegistry()
	reg.RegisterBuiltin(first)
	reg.RegisterBuiltin(second)
	s := &Sidecar{
		cfg: &config.Config{
			DataDir:        failingHookTokenDataDir(t),
			DeploymentMode: string(config.DeploymentModeManagedEnterprise),
			Guardrail:      config.GuardrailConfig{Enabled: true},
		},
		health: NewSidecarHealth(),
	}

	err := s.runManagedEnterpriseMultiHookGuardrail(
		context.Background(), reg, []connector.Connector{first, second}, "gateway-token", "a", "b", "master",
	)
	if err == nil || !strings.Contains(err.Error(), "scoped hook token") {
		t.Fatalf("runManagedEnterpriseMultiHookGuardrail error = %v, want scoped-token failure", err)
	}
	if first.credsSet || second.credsSet {
		t.Fatal("connector credentials were installed before every scoped token passed preflight")
	}
	if state := s.health.Snapshot().Guardrail.State; state != StateError {
		t.Fatalf("guardrail health state = %s, want %s", state, StateError)
	}
}

func TestStartMultiHookConfigGuardsFailsClosedWhenScopedTokenFails(t *testing.T) {
	conn := &hookBootStubConnector{bootStubConnector: bootStubConnector{stubConnector: stubConnector{name: "codex"}}}
	reg := connector.NewRegistry()
	reg.RegisterBuiltin(conn)
	s := &Sidecar{
		cfg: &config.Config{
			DataDir:        failingHookTokenDataDir(t),
			DeploymentMode: string(config.DeploymentModeManagedEnterprise),
			Guardrail:      config.GuardrailConfig{Enabled: true, HookSelfHeal: true},
		},
	}

	guards, err := s.startMultiHookConfigGuards(context.Background(), reg, []string{"codex"}, "gateway-token", "a", "b")
	defer stopHookConfigGuards(guards)
	if err == nil || !strings.Contains(err.Error(), "scoped hook token") {
		t.Fatalf("startMultiHookConfigGuards error = %v, want scoped-token failure", err)
	}
	if len(guards) != 0 {
		t.Fatalf("guards = %d, want none after scoped-token failure", len(guards))
	}
}

func TestStartMultiHookConfigGuardsStopsEarlierGuardsOnLaterTokenFailure(t *testing.T) {
	first := &bootStubConnector{stubConnector: stubConnector{name: "codex"}}
	second := &hookBootStubConnector{bootStubConnector: bootStubConnector{stubConnector: stubConnector{name: "cursor"}}}
	reg := connector.NewRegistry()
	reg.RegisterBuiltin(first)
	reg.RegisterBuiltin(second)
	s := &Sidecar{
		cfg: &config.Config{
			DataDir:        failingHookTokenDataDir(t),
			DeploymentMode: string(config.DeploymentModeManagedEnterprise),
			Guardrail:      config.GuardrailConfig{Enabled: true, HookSelfHeal: true},
		},
	}
	originalFactory := newSidecarHookConfigGuard
	var created []*HookConfigGuard
	newSidecarHookConfigGuard = func(sidecar *Sidecar, debounce time.Duration) *HookConfigGuard {
		guard := originalFactory(sidecar, debounce)
		created = append(created, guard)
		return guard
	}
	t.Cleanup(func() {
		newSidecarHookConfigGuard = originalFactory
		stopHookConfigGuards(created)
	})

	guards, err := s.startMultiHookConfigGuards(
		context.Background(), reg, []string{"codex", "cursor"}, "gateway-token", "a", "b",
	)
	if err == nil || !strings.Contains(err.Error(), "scoped hook token") {
		t.Fatalf("startMultiHookConfigGuards error = %v, want scoped-token failure", err)
	}
	if len(guards) != 0 || len(created) != 1 {
		t.Fatalf("returned guards = %d, created guards = %d; want 0 returned and 1 rolled back", len(guards), len(created))
	}
	created[0].mu.Lock()
	started := created[0].started
	created[0].mu.Unlock()
	if started {
		t.Fatal("earlier hook guard remained started after a later scoped-token failure")
	}
}

func TestConnectorSetupTokensUnmanagedFallsBackToMasterToken(t *testing.T) {
	conn := &hookBootStubConnector{bootStubConnector: bootStubConnector{stubConnector: stubConnector{name: "codex"}}}
	tokens, err := connectorSetupTokensFor(failingHookTokenDataDir(t), conn, "gateway-token", false)
	if err != nil {
		t.Fatalf("connectorSetupTokensFor unmanaged fallback: %v", err)
	}
	if tokens.connectorToken != "gateway-token" || tokens.hookToken != "gateway-token" {
		t.Fatalf("fallback tokens = %+v, want master gateway token", tokens)
	}
	if tokens.hookTokenScoped {
		t.Fatal("unmanaged fallback mislabeled master token as connector-scoped")
	}
}

func TestConnectorSetupTokensAMPRefusesMasterTokenFallback(t *testing.T) {
	_, err := connectorSetupTokensFor(
		failingHookTokenDataDir(t),
		connector.NewAMPConnector(),
		"gateway-master",
		false,
	)
	if err == nil {
		t.Fatal("Amp setup accepted the gateway master token after scoped-token creation failed")
	}
}

func TestConnectorSetupTokensProxyKeepsMasterOutOfScopedSidecar(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("proxy connectors are unsupported on native Windows; platform gate coverage remains active")
	}
	tokens, err := connectorSetupTokensFor(t.TempDir(), connector.NewOpenClawConnector(), "gateway-master", false)
	if err != nil {
		t.Fatalf("connectorSetupTokensFor proxy: %v", err)
	}
	if tokens.connectorToken != "gateway-master" {
		t.Fatalf("proxy connector token = %q, want gateway master", tokens.connectorToken)
	}
	if !tokens.hookTokenScoped || tokens.hookToken == "" || tokens.hookToken == "gateway-master" {
		t.Fatalf("proxy hook token = %+v, want distinct connector-scoped credential", tokens)
	}
}

func TestConnectorSetupTokensOmnigentGetsScopedToken(t *testing.T) {
	tokens, err := connectorSetupTokensFor(testenv.PrivateTempDir(t), connector.NewOmnigentConnector(), "gateway-master", false)
	if err != nil {
		t.Fatalf("connectorSetupTokensFor omnigent: %v", err)
	}
	if !tokens.hookTokenScoped || tokens.connectorToken == "" || tokens.connectorToken == "gateway-master" {
		t.Fatalf("OmniGent tokens = %+v, want connector-scoped policy credential", tokens)
	}
}

// TestRunGuardrailMulti_FailFastProxyGuard verifies that a proxy-binding
// connector in a multi-connector set aborts boot with a clear error before any
// connector is set up. Multi-connector mode is hook-only: a single process can
// bind only one guardrail proxy port, so openclaw alongside codex is a config
// error we surface loudly.
func TestRunGuardrailMulti_FailFastProxyGuard(t *testing.T) {
	s := &Sidecar{
		cfg: &config.Config{
			DataDir: t.TempDir(),
			Guardrail: config.GuardrailConfig{
				Enabled: true,
				Connectors: map[string]config.PerConnectorGuardrailConfig{
					"codex":    {},
					"openclaw": {}, // proxy-binding — must trip the guard
				},
			},
		},
		health: NewSidecarHealth(),
		router: routerWithDefaultRulePack(t),
	}

	err := s.runGuardrailMulti(context.Background())
	if err == nil {
		t.Fatal("expected fail-fast proxy-guard error, got nil")
	}
	if want := "requires a proxy binding"; !strings.Contains(err.Error(), want) {
		t.Errorf("error %q does not mention %q", err.Error(), want)
	}
}

func TestRunGuardrailManagedEnterpriseSingleHookSkipsServiceHomeLifecycle(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("managed enterprise hook lifecycle is rejected on native Windows")
	}
	dir := t.TempDir()
	codexConfig := filepath.Join(t.TempDir(), ".codex", "config.toml")
	prevCodex := connector.CodexConfigPathOverride
	connector.CodexConfigPathOverride = codexConfig
	t.Cleanup(func() { connector.CodexConfigPathOverride = prevCodex })

	s := &Sidecar{
		cfg: &config.Config{
			DataDir:        dir,
			DeploymentMode: string(config.DeploymentModeManagedEnterprise),
			Gateway: config.GatewayConfig{
				APIPort: 18970,
			},
			Guardrail: config.GuardrailConfig{
				Enabled:      true,
				Connector:    "codex",
				Mode:         "observe",
				HookSelfHeal: true,
			},
		},
		health: NewSidecarHealth(),
		router: routerWithDefaultRulePack(t),
	}

	// Cancellation makes the long-running loop return immediately after its
	// synchronous bootstrap, so assertions inspect durable state without a
	// machine-speed-dependent readiness deadline.
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := s.runGuardrail(ctx); err != nil {
		t.Fatalf("runGuardrail: %v", err)
	}

	assertPathMissing(t, codexConfig)
	assertPathMissing(t, filepath.Join(dir, "hooks", "codex-hook.sh"))
	snap := s.health.Snapshot()
	if snap.Guardrail.State != StateStarting {
		t.Fatalf("guardrail state = %s, want %s", snap.Guardrail.State, StateStarting)
	}
	if got := snap.Guardrail.Details["lifecycle_manager"]; got != "enterprise_hook_guardian" {
		t.Fatalf("lifecycle_manager = %v, want enterprise_hook_guardian", got)
	}
}

func TestRunGuardrailMultiManagedEnterpriseSkipsServiceHomeLifecycle(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("managed enterprise hook lifecycle is rejected on native Windows")
	}
	dir := t.TempDir()
	codexConfig := filepath.Join(t.TempDir(), ".codex", "config.toml")
	claudeSettings := filepath.Join(t.TempDir(), ".claude", "settings.json")
	prevCodex := connector.CodexConfigPathOverride
	prevClaude := connector.ClaudeCodeSettingsPathOverride
	connector.CodexConfigPathOverride = codexConfig
	connector.ClaudeCodeSettingsPathOverride = claudeSettings
	t.Cleanup(func() {
		connector.CodexConfigPathOverride = prevCodex
		connector.ClaudeCodeSettingsPathOverride = prevClaude
	})

	s := &Sidecar{
		cfg: &config.Config{
			DataDir:        dir,
			DeploymentMode: string(config.DeploymentModeManagedEnterprise),
			Gateway: config.GatewayConfig{
				APIPort: 18971,
			},
			Guardrail: config.GuardrailConfig{
				Enabled: true,
				Mode:    "observe",
				Connectors: map[string]config.PerConnectorGuardrailConfig{
					"codex":      {},
					"claudecode": {},
				},
			},
		},
		health: NewSidecarHealth(),
		router: routerWithDefaultRulePack(t),
	}

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := s.runGuardrailMulti(ctx); err != nil {
		t.Fatalf("runGuardrailMulti: %v", err)
	}

	assertPathMissing(t, codexConfig)
	assertPathMissing(t, claudeSettings)
	assertPathMissing(t, filepath.Join(dir, "hooks", "codex-hook.sh"))
	assertPathMissing(t, filepath.Join(dir, "hooks", "claudecode-hook.sh"))
	snap := s.health.Snapshot()
	if snap.Guardrail.State != StateStarting {
		t.Fatalf("guardrail state = %s, want %s", snap.Guardrail.State, StateStarting)
	}
	if got := snap.Guardrail.Details["lifecycle_manager"]; got != "enterprise_hook_guardian" {
		t.Fatalf("lifecycle_manager = %v, want enterprise_hook_guardian", got)
	}
	if len(snap.Connectors) != 2 {
		t.Fatalf("registered connectors = %d, want 2", len(snap.Connectors))
	}
}

func TestManagedGuardianCoverageRequiresTrustedAuthorizationForEveryConnector(t *testing.T) {
	authorizationDir := t.TempDir()
	t.Setenv(managed.HookGuardianAuthorizationDirEnv, authorizationDir)
	oldValidate := validateManagedGuardianAuthorization
	validateManagedGuardianAuthorization = func(_, _ string) error { return nil }
	t.Cleanup(func() { validateManagedGuardianAuthorization = oldValidate })
	path := managed.HookGuardianAuthorizationPath(t.TempDir())
	data := []byte(`{"protected_targets":[{"connector":"codex","ok":true}]}`)
	if err := os.WriteFile(path, data, 0o644); err != nil {
		t.Fatalf("write authorization: %v", err)
	}

	if ok, reason := managedGuardianCoversConnectors("unused", []string{"codex"}); !ok {
		t.Fatalf("coverage = false: %s", reason)
	}
	if ok, _ := managedGuardianCoversConnectors("unused", []string{"codex", "claudecode"}); ok {
		t.Fatal("partial guardian authorization reported full connector coverage")
	}
}

func assertPathMissing(t *testing.T, path string) {
	t.Helper()
	if _, err := os.Stat(path); err == nil {
		t.Fatalf("path %s exists; managed enterprise gateway must not create service-account hook files", path)
	} else if !os.IsNotExist(err) {
		t.Fatalf("stat %s: %v", path, err)
	}
}

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
		router: NewEventRouter(nil, nil, nil, false),
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
	s.cfg.Guardrail.Mode = "action"
	s.cfg.Guardrail.Connectors = map[string]config.PerConnectorGuardrailConfig{
		"codex": {Mode: "action"},
	}

	discovery := map[string]any{
		"agents": map[string]any{
			"codex":      map[string]any{"version": "codex-cli 0.142.4"},
			"claudecode": map[string]any{"version": "Claude Code v2.1.144"},
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
	previous := connector.HookContractLockEntry{
		Connector:              "codex",
		RawAgentVersion:        "codex-cli 0.142.4",
		NormalizedAgentVersion: "0.142.4",
		ContractID:             "codex-hooks-v1",
		HookScriptDigests:      map[string]string{"codex-hook.sh": "sha256:previous-generated-build"},
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
	windsurfOpts := mustConnectorSetupOpts(t, s, &bootStubConnector{stubConnector: stubConnector{name: "windsurf"}}, "tok", "a", "b")
	if windsurfOpts.HookFailMode != "closed" {
		t.Errorf("windsurf HookFailMode=%q, want connector override independent of observe mode", windsurfOpts.HookFailMode)
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
	if runtime.GOOS == "windows" {
		t.Skip("OmniGent is unsupported on native Windows; platform gate coverage remains active")
	}
	tokens, err := connectorSetupTokensFor(t.TempDir(), connector.NewOmnigentConnector(), "gateway-master", false)
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
		router: &EventRouter{},
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
		router: NewEventRouter(nil, nil, nil, false),
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
		router: NewEventRouter(nil, nil, nil, false),
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

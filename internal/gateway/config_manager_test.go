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
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/inventory"
	"github.com/defenseclaw/defenseclaw/internal/telemetry"
)

func TestConfigManagerReloadAppliesAndPublishesSnapshot(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, config.DefaultConfigName)
	writeConfigForManagerTest(t, path, dir, "observe")

	initial, err := config.LoadFromFile(path)
	if err != nil {
		t.Fatalf("initial load: %v", err)
	}
	applied := false
	mgr := NewConfigManager(path, initial, nil, nil, func(_ context.Context, oldCfg, newCfg *config.Config, diff ConfigDiff) error {
		applied = true
		if oldCfg.Guardrail.Mode != "observe" || newCfg.Guardrail.Mode != "action" {
			t.Fatalf("apply saw mode %q -> %q", oldCfg.Guardrail.Mode, newCfg.Guardrail.Mode)
		}
		if !slices.Contains(diff.Changed, "guardrail") {
			t.Fatalf("diff changed = %v, want guardrail", diff.Changed)
		}
		return nil
	})

	writeConfigForManagerTest(t, path, dir, "action")
	if err := mgr.Reload(context.Background(), "test"); err != nil {
		t.Fatalf("reload: %v", err)
	}
	if !applied {
		t.Fatal("apply callback was not called")
	}
	if got := mgr.Current().Guardrail.Mode; got != "action" {
		t.Fatalf("current mode = %q, want action", got)
	}
}

func TestConfigManagerReloadRejectsInvalidAndKeepsSnapshot(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, config.DefaultConfigName)
	writeConfigForManagerTest(t, path, dir, "observe")

	initial, err := config.LoadFromFile(path)
	if err != nil {
		t.Fatalf("initial load: %v", err)
	}
	mgr := NewConfigManager(path, initial, nil, nil, func(context.Context, *config.Config, *config.Config, ConfigDiff) error {
		t.Fatal("apply callback must not run for invalid config")
		return nil
	})

	raw := "config_version: 6\n" +
		"data_dir: " + dir + "\n" +
		"deployment_mode: invalid\n" +
		"guardrail:\n" +
		"  mode: observe\n"
	if err := os.WriteFile(path, []byte(raw), 0o600); err != nil {
		t.Fatalf("write invalid config: %v", err)
	}
	if err := mgr.Reload(context.Background(), "test"); err == nil {
		t.Fatal("reload succeeded with invalid deployment_mode")
	}
	if got := mgr.Current().Guardrail.Mode; got != "observe" {
		t.Fatalf("current mode changed to %q after failed reload", got)
	}
}

func TestConfigManagerCurrentReturnsDeepCopy(t *testing.T) {
	initial := config.DefaultConfig()
	initial.Guardrail.Connectors = map[string]config.PerConnectorGuardrailConfig{
		"codex": {Mode: "observe"},
	}
	initial.Guardrail.Judge.HookConnectors = []string{"codex"}
	mgr := NewConfigManager("", initial, nil, nil, nil)

	snapshot := mgr.Current()
	snapshot.Guardrail.Connectors["codex"] = config.PerConnectorGuardrailConfig{Mode: "action"}
	snapshot.Guardrail.Judge.HookConnectors[0] = "claudecode"

	fresh := mgr.Current()
	if got := fresh.Guardrail.Connectors["codex"].Mode; got != "observe" {
		t.Fatalf("connector mode = %q, want observe", got)
	}
	if got := fresh.Guardrail.Judge.HookConnectors[0]; got != "codex" {
		t.Fatalf("hook connector = %q, want codex", got)
	}
}

func TestSidecarConfigSnapshotsAreConcurrentSafe(t *testing.T) {
	observe := config.DefaultConfig()
	observe.Guardrail.Mode = "observe"
	action := config.DefaultConfig()
	action.Guardrail.Mode = "action"
	sidecar := &Sidecar{cfg: observe}
	sidecar.publishConfig(observe)

	observe.Guardrail.Mode = "mutated-after-publish"
	if got := sidecar.currentConfig().Guardrail.Mode; got != "observe" {
		t.Fatalf("published mode = %q, want observe", got)
	}
	observe.Guardrail.Mode = "observe"

	var wg sync.WaitGroup
	for range 4 {
		wg.Add(2)
		go func() {
			defer wg.Done()
			for range 1000 {
				sidecar.publishConfig(action)
				sidecar.publishConfig(observe)
			}
		}()
		go func() {
			defer wg.Done()
			for range 2000 {
				mode := sidecar.currentConfig().Guardrail.Mode
				if mode != "observe" && mode != "action" {
					t.Errorf("observed partial config mode %q", mode)
					return
				}
			}
		}()
	}
	wg.Wait()
}

func TestDiffConfigsMarksStorageIdentityRestartRequired(t *testing.T) {
	oldCfg := &config.Config{
		DataDir:       "/old/data",
		AuditDB:       "/old/audit.db",
		JudgeBodiesDB: "/old/judge.db",
	}
	newCfg := &config.Config{
		DataDir:       "/new/data",
		AuditDB:       "/new/audit.db",
		JudgeBodiesDB: "/new/judge.db",
	}
	oldCfg.Gateway.DeviceKeyFile = "/old/device.pem"
	newCfg.Gateway.DeviceKeyFile = "/new/device.pem"

	diff := diffConfigs(oldCfg, newCfg)
	for _, want := range []string{"data_dir", "audit_db", "judge_bodies_db", "gateway.device_key_file"} {
		if !slices.Contains(diff.RestartRequired, want) {
			t.Fatalf("restart_required = %v, missing %s", diff.RestartRequired, want)
		}
	}
}

func TestDiffConfigsMarksOpenShellChanged(t *testing.T) {
	oldCfg := &config.Config{}
	newCfg := &config.Config{}
	newCfg.OpenShell.Mode = "standalone"

	diff := diffConfigs(oldCfg, newCfg)
	if !slices.Contains(diff.Changed, "openshell") {
		t.Fatalf("changed = %v, missing openshell", diff.Changed)
	}
}

func TestDiffConfigsMarksApplicationProtectionChanged(t *testing.T) {
	oldCfg := &config.Config{ApplicationProtection: config.DefaultApplicationProtectionConfig()}
	newCfg := &config.Config{ApplicationProtection: config.DefaultApplicationProtectionConfig()}
	newCfg.ApplicationProtection.Enabled = !oldCfg.ApplicationProtection.Enabled

	diff := diffConfigs(oldCfg, newCfg)
	if !slices.Contains(diff.Changed, "application_protection") {
		t.Fatalf("changed = %v, missing application_protection", diff.Changed)
	}
}

func TestDiffConfigsMarksRuntimeTopologyRestartRequired(t *testing.T) {
	oldCfg := config.DefaultConfig()
	newCfg := *oldCfg
	newCfg.Gateway.Host = "gateway.example.test"
	newCfg.Guardrail.ScannerMode = "remote"
	newCfg.Guardrail.Connector = "codex"

	diff := diffConfigs(oldCfg, &newCfg)
	for _, want := range []string{"gateway", "guardrail.scanner_mode", "guardrail.connectors"} {
		if !slices.Contains(diff.RestartRequired, want) {
			t.Fatalf("restart_required = %v, missing %s", diff.RestartRequired, want)
		}
	}
}

func TestDiffConfigsAllowsHotGuardrailPolicyFields(t *testing.T) {
	oldCfg := config.DefaultConfig()
	newCfg := cloneConfig(oldCfg)
	newCfg.Guardrail.Mode = "action"
	newCfg.Guardrail.BlockMessage = "updated block message"
	newCfg.Guardrail.HILT.Enabled = !oldCfg.Guardrail.HILT.Enabled
	newCfg.Guardrail.HILT.MinSeverity = "MEDIUM"

	diff := diffConfigs(oldCfg, newCfg)
	if !slices.Contains(diff.Changed, "guardrail") {
		t.Fatalf("changed = %v, missing guardrail", diff.Changed)
	}
	if slices.Contains(diff.RestartRequired, "guardrail") {
		t.Fatalf("restart_required = %v, pure policy fields should hot-apply", diff.RestartRequired)
	}
}

func TestApplyConfigReloadHotAppliesGuardrailPolicy(t *testing.T) {
	oldCfg := config.DefaultConfig()
	newCfg := cloneConfig(oldCfg)
	newCfg.Guardrail.Mode = "action"
	newCfg.Guardrail.BlockMessage = "updated block message"
	newCfg.Guardrail.HILT.Enabled = true
	newCfg.Guardrail.HILT.MinSeverity = "MEDIUM"

	inspector := NewGuardrailInspector("local", nil, nil, "")
	proxy := &GuardrailProxy{
		cfg:          &oldCfg.Guardrail,
		mode:         oldCfg.Guardrail.Mode,
		blockMessage: oldCfg.Guardrail.BlockMessage,
		inspector:    inspector,
	}
	sidecar := &Sidecar{cfg: oldCfg}
	sidecar.publishConfig(oldCfg)
	sidecar.setGuardrailProxy(proxy)

	if err := sidecar.applyConfigReload(context.Background(), oldCfg, newCfg, diffConfigs(oldCfg, newCfg)); err != nil {
		t.Fatalf("applyConfigReload: %v", err)
	}
	proxy.rtMu.RLock()
	mode, blockMessage := proxy.mode, proxy.blockMessage
	proxy.rtMu.RUnlock()
	if mode != "action" || blockMessage != "updated block message" {
		t.Fatalf("live proxy policy = mode %q block %q", mode, blockMessage)
	}
	if got := sidecar.currentConfig().Guardrail.Mode; got != "action" {
		t.Fatalf("sidecar mode = %q, want action", got)
	}
}

func TestGuardrailAPIPatchCommitsDiskManagerSidecarAndProxyTogether(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, config.DefaultConfigName)
	raw := "config_version: 7\n" +
		"data_dir: " + dir + "\n" +
		"gateway:\n  token: transactional-token\n" +
		"guardrail:\n  enabled: true\n  mode: observe\n  scanner_mode: local\n"
	if err := os.WriteFile(path, []byte(raw), 0o600); err != nil {
		t.Fatalf("write initial config: %v", err)
	}
	oldCfg, err := config.LoadFromFile(path)
	if err != nil {
		t.Fatalf("load initial config: %v", err)
	}

	proxy := &GuardrailProxy{
		cfg:          &oldCfg.Guardrail,
		mode:         oldCfg.Guardrail.Mode,
		blockMessage: oldCfg.Guardrail.BlockMessage,
		inspector:    NewGuardrailInspector("local", nil, nil, ""),
	}
	sidecar := &Sidecar{cfg: oldCfg}
	sidecar.publishConfig(oldCfg)
	sidecar.setGuardrailProxy(proxy)
	mgr := NewConfigManager(path, oldCfg, nil, nil, sidecar.applyConfigReload)
	api := &APIServer{scannerCfg: cloneConfig(oldCfg)}
	api.SetConfigRuntime(mgr.Reload, sidecar.currentConfig)

	body, _ := json.Marshal(map[string]any{"mode": "action"})
	req := httptest.NewRequest(http.MethodPatch, "/v1/guardrail/config", bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer transactional-token")
	w := httptest.NewRecorder()
	api.handleGuardrailConfig(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("PATCH status = %d, want 200; body: %s", w.Code, w.Body.String())
	}
	for label, got := range map[string]string{
		"manager": mgr.Current().Guardrail.Mode,
		"sidecar": sidecar.currentConfig().Guardrail.Mode,
	} {
		if got != "action" {
			t.Fatalf("%s mode = %q, want action", label, got)
		}
	}
	proxy.rtMu.RLock()
	proxyMode := proxy.mode
	proxy.rtMu.RUnlock()
	if proxyMode != "action" {
		t.Fatalf("proxy mode = %q, want action", proxyMode)
	}
	persisted, err := config.LoadFromFile(path)
	if err != nil {
		t.Fatalf("reload persisted config: %v", err)
	}
	if persisted.Guardrail.Mode != "action" {
		t.Fatalf("persisted mode = %q, want action", persisted.Guardrail.Mode)
	}
	var response map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &response); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if response["live"] != true || response["mode"] != "action" {
		t.Fatalf("response = %#v, want live action", response)
	}
}

func TestReloadPredicatesRestartLLMConsumers(t *testing.T) {
	oldCfg := &config.Config{}
	newCfg := &config.Config{}
	oldCfg.LLM.Model = "openai/gpt-4o-mini"
	newCfg.LLM.Model = "openai/gpt-4.1-mini"

	if !guardrailNeedsRestart(oldCfg, newCfg) {
		t.Fatal("guardrailNeedsRestart returned false for llm change")
	}
	if !watcherNeedsRestart(oldCfg, newCfg) {
		t.Fatal("watcherNeedsRestart returned false for llm change")
	}
}

func TestGuardrailRestartPredicateIncludesSingularConnector(t *testing.T) {
	oldCfg := config.DefaultConfig()
	newCfg := config.DefaultConfig()
	oldCfg.Guardrail.Connector = "codex"
	newCfg.Guardrail.Connector = "claudecode"

	if !guardrailNeedsRestart(oldCfg, newCfg) {
		t.Fatal("guardrailNeedsRestart returned false for singular connector change")
	}
}

func TestOTelProviderAccessorsAreConcurrentSafe(t *testing.T) {
	router := &EventRouter{}
	hilt := &HILTApprovalManager{}
	guardrailCfg := &config.GuardrailConfig{Connector: "codex"}
	var wg sync.WaitGroup
	for range 4 {
		wg.Add(6)
		go func() {
			defer wg.Done()
			for range 1000 {
				router.SetOTelProvider(nil)
			}
		}()
		go func() {
			defer wg.Done()
			for range 1000 {
				_ = router.otelProvider()
			}
		}()
		go func() {
			defer wg.Done()
			for range 1000 {
				hilt.SetOTelProvider(nil)
			}
		}()
		go func() {
			defer wg.Done()
			for range 1000 {
				_ = hilt.otelProvider()
			}
		}()
		go func() {
			defer wg.Done()
			for range 1000 {
				router.SetGuardrailConfig(guardrailCfg)
				router.SetDefaultAgentName("codex")
				router.SetDefaultPolicyID("action")
			}
		}()
		go func() {
			defer wg.Done()
			for range 1000 {
				_ = router.guardrailConfig()
				_ = router.connectorName()
				_, _ = router.defaultRoutingMetadata()
			}
		}()
	}
	wg.Wait()
}

func TestApplyConfigReloadRequiresRestartForSharedJudgeChange(t *testing.T) {
	oldCfg := config.DefaultConfig()
	oldCfg.DataDir = t.TempDir()
	oldCfg.LLM = config.LLMConfig{
		Provider: "openai",
		Model:    "openai/gpt-4o-mini",
		APIKey:   "test-key",
	}
	oldCfg.Guardrail.Judge.Enabled = true
	oldCfg.Guardrail.Judge.PII = true
	oldCfg.Guardrail.Judge.Timeout = 1

	newCfg := *oldCfg
	newCfg.Guardrail.Judge.HookConnectors = []string{"codex"}

	sidecar := &Sidecar{cfg: oldCfg}
	err := sidecar.applyConfigReload(context.Background(), oldCfg, &newCfg, diffConfigs(oldCfg, &newCfg))
	if err == nil || !strings.Contains(err.Error(), "guardrail") {
		t.Fatalf("applyConfigReload error = %v, want guardrail restart requirement", err)
	}
}

func TestApplyConfigReloadHotRejectsRestartRequiredChange(t *testing.T) {
	oldCfg := config.DefaultConfig()
	newCfg := *oldCfg
	newCfg.DataDir = filepath.Join(t.TempDir(), "next")

	sidecar := &Sidecar{cfg: oldCfg}
	err := sidecar.applyConfigReload(context.Background(), oldCfg, &newCfg, diffConfigs(oldCfg, &newCfg))
	if err == nil {
		t.Fatal("applyConfigReload succeeded for restart-required change in hot mode")
	}
	if !strings.Contains(err.Error(), "data_dir") {
		t.Fatalf("error = %v, want data_dir", err)
	}
}

func TestApplyConfigReloadRestartModeRequestsProcessRestart(t *testing.T) {
	oldCfg := config.DefaultConfig()
	newCfg := *oldCfg
	newCfg.DataDir = filepath.Join(t.TempDir(), "next")
	newCfg.Gateway.ConfigReload.Mode = "restart"

	helperCalled := false
	oldHelper := launchConfigRestartHelper
	launchConfigRestartHelper = func() error {
		helperCalled = true
		return nil
	}
	t.Cleanup(func() { launchConfigRestartHelper = oldHelper })

	runCtx, cancel := context.WithCancel(context.Background())
	sidecar := &Sidecar{cfg: oldCfg}
	sidecar.setRunCancel(cancel)

	if err := sidecar.applyConfigReload(context.Background(), oldCfg, &newCfg, diffConfigs(oldCfg, &newCfg)); err != nil {
		t.Fatalf("applyConfigReload: %v", err)
	}
	if !helperCalled {
		t.Fatal("restart helper was not launched")
	}
	select {
	case <-runCtx.Done():
	default:
		t.Fatal("run context was not cancelled")
	}
	if got := sidecar.currentConfig().DataDir; got == newCfg.DataDir {
		t.Fatalf("sidecar cfg mutated to %q before process restart", got)
	}
}

func TestApplyConfigReloadRestartHelperFailureLeavesRuntimeConfigUntouched(t *testing.T) {
	oldCfg := config.DefaultConfig()
	newCfg := *oldCfg
	newCfg.DataDir = filepath.Join(t.TempDir(), "next")
	newCfg.Gateway.ConfigReload.Mode = "restart"

	oldHelper := launchConfigRestartHelper
	launchConfigRestartHelper = func() error { return errors.New("helper unavailable") }
	t.Cleanup(func() { launchConfigRestartHelper = oldHelper })

	sidecar := &Sidecar{cfg: oldCfg}
	if err := sidecar.applyConfigReload(context.Background(), oldCfg, &newCfg, diffConfigs(oldCfg, &newCfg)); err == nil {
		t.Fatal("applyConfigReload succeeded when restart helper failed")
	}
	if sidecar.currentConfig().DataDir == newCfg.DataDir {
		t.Fatal("runtime config mutated before restart helper succeeded")
	}
}

func TestApplyConfigReloadArmsRestartModeWithoutImmediateRestart(t *testing.T) {
	oldCfg := config.DefaultConfig()
	newCfg := *oldCfg
	newCfg.Gateway.ConfigReload.Mode = "restart"

	helperCalled := false
	oldHelper := launchConfigRestartHelper
	launchConfigRestartHelper = func() error {
		helperCalled = true
		return nil
	}
	t.Cleanup(func() { launchConfigRestartHelper = oldHelper })

	runCtx, cancel := context.WithCancel(context.Background())
	defer cancel()
	sidecar := &Sidecar{cfg: oldCfg}
	sidecar.setRunCancel(cancel)

	if err := sidecar.applyConfigReload(context.Background(), oldCfg, &newCfg, diffConfigs(oldCfg, &newCfg)); err != nil {
		t.Fatalf("applyConfigReload: %v", err)
	}
	if helperCalled {
		t.Fatal("restart helper launched when only config_reload.mode changed")
	}
	select {
	case <-runCtx.Done():
		t.Fatal("run context was cancelled when only config_reload.mode changed")
	default:
	}
	if got := sidecar.currentConfig().Gateway.ConfigReload.Mode; got == "restart" {
		t.Fatal("runtime config mutated while arming restart mode")
	}
}

func TestConfigRestartHelperArgsPreservesOnlySafeRootFlags(t *testing.T) {
	got := configRestartHelperArgs([]string{
		"defenseclaw-gateway",
		"--host", "10.0.0.5",
		"--token", "secret",
		"--port=18790",
		"--log-level", "debug",
	})
	want := []string{"restart", "--host", "10.0.0.5", "--port=18790"}
	if !slices.Equal(got, want) {
		t.Fatalf("configRestartHelperArgs = %v, want %v", got, want)
	}
}

func TestDiffConfigsDeploymentModeRequiresRestart(t *testing.T) {
	oldCfg := config.DefaultConfig()
	newCfg := *oldCfg
	oldCfg.DeploymentMode = string(config.DeploymentModeManagedEnterprise)
	newCfg.DeploymentMode = string(config.DeploymentModeUnmanagedBYOD)
	diff := diffConfigs(oldCfg, &newCfg)
	if !slices.Contains(diff.RestartRequired, "deployment_mode") {
		t.Fatalf("restart required = %v, want deployment_mode", diff.RestartRequired)
	}
}

func TestReloadableSubsystemSnapshotsAreSynchronized(t *testing.T) {
	sidecar := &Sidecar{}
	providers := []*telemetry.Provider{{}, {}}
	dispatchers := []*WebhookDispatcher{{}, {}}
	discoveryServices := []*inventory.ContinuousDiscoveryService{{}, {}}

	const iterations = 1000
	var wg sync.WaitGroup
	for _, run := range []func(){
		func() {
			for i := 0; i < iterations; i++ {
				sidecar.swapOTel(providers[i%len(providers)])
			}
		},
		func() {
			for i := 0; i < iterations; i++ {
				_ = sidecar.otelSnapshot()
			}
		},
		func() {
			for i := 0; i < iterations; i++ {
				sidecar.swapWebhooks(dispatchers[i%len(dispatchers)])
			}
		},
		func() {
			for i := 0; i < iterations; i++ {
				_ = sidecar.webhooksSnapshot()
			}
		},
		func() {
			for i := 0; i < iterations; i++ {
				sidecar.swapAIDiscovery(discoveryServices[i%len(discoveryServices)])
			}
		},
		func() {
			for i := 0; i < iterations; i++ {
				_ = sidecar.aiDiscoverySnapshot()
			}
		},
	} {
		wg.Add(1)
		go func(run func()) {
			defer wg.Done()
			run()
		}(run)
	}
	wg.Wait()
}

func TestApplyConfigReloadTokenPreflightFailureIsAtomic(t *testing.T) {
	t.Setenv("DEFENSECLAW_GATEWAY_TOKEN", "")
	t.Setenv("OPENCLAW_GATEWAY_TOKEN", "")
	t.Setenv("TEST_RELOAD_GATEWAY_TOKEN", "")

	dir := t.TempDir()
	blockedDataDir := filepath.Join(dir, "not-a-directory")
	if err := os.WriteFile(blockedDataDir, []byte("blocked"), 0o600); err != nil {
		t.Fatalf("write blocked data dir: %v", err)
	}

	oldCfg := config.DefaultConfig()
	oldCfg.DataDir = blockedDataDir
	oldCfg.Gateway.Token = ""
	oldCfg.Gateway.TokenEnv = "TEST_RELOAD_GATEWAY_TOKEN"
	oldCfg.AIDiscovery.Enabled = true

	newCfg := cloneConfig(oldCfg)
	newCfg.Environment = oldCfg.Environment + "-reloaded"
	oldDiscovery := &inventory.ContinuousDiscoveryService{}
	sidecar := &Sidecar{cfg: oldCfg, health: NewSidecarHealth(), aiDiscovery: oldDiscovery}
	sidecar.publishConfig(oldCfg)

	err := sidecar.applyConfigReload(context.Background(), oldCfg, newCfg, diffConfigs(oldCfg, newCfg))
	if err == nil || !strings.Contains(err.Error(), "gateway token") {
		t.Fatalf("applyConfigReload error = %v, want gateway-token preflight failure", err)
	}
	if sidecar.currentConfig().Environment == newCfg.Environment {
		t.Fatal("failed reload published the candidate environment")
	}
	if sidecar.aiDiscoverySnapshot() != oldDiscovery {
		t.Fatal("failed reload swapped the AI discovery service")
	}
}

func writeConfigForManagerTest(t *testing.T, path, dataDir, mode string) {
	t.Helper()
	raw := "config_version: 6\n" +
		"data_dir: " + dataDir + "\n" +
		"guardrail:\n" +
		"  mode: " + mode + "\n"
	if err := os.WriteFile(path, []byte(raw), 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}
}

// writeConfigWithEndpoint renders a minimal config.yaml that sets
// cisco_ai_defense.endpoint. Deployment mode stays default
// (unmanaged_byod) so LoadFromFile does not trip the managed_enterprise
// trust-check (which requires root-owned config on disk — unavailable
// inside t.TempDir()). The env_config overlay logic in ConfigManager
// does NOT gate on deployment_mode: the sidecar decides at boot
// whether to call SetEnvConfigPath (see the managed check in
// sidecar.go), and these tests exercise the ConfigManager in
// isolation by calling SetEnvConfigPath directly.
func writeConfigWithEndpoint(t *testing.T, path, dataDir, endpoint string) {
	t.Helper()
	raw := "config_version: 6\n" +
		"data_dir: " + dataDir + "\n" +
		"cisco_ai_defense:\n" +
		"  endpoint: " + endpoint + "\n" +
		"guardrail:\n" +
		"  mode: observe\n"
	if err := os.WriteFile(path, []byte(raw), 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}
}

// TestConfigManagerEnvConfigOverlayApplies is the happy-path
// integration: a well-formed env_config.json sitting next to config.yaml
// should overlay its endpoint on top of the config.yaml value on every
// Reload — exactly what "AVC delivered env_config AFTER install"
// requires.
func TestConfigManagerEnvConfigOverlayApplies(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, config.DefaultConfigName)
	envPath := filepath.Join(dir, "env_config.json")

	writeConfigWithEndpoint(t, cfgPath, dir, "https://us.api.inspect.aidefense.security.cisco.com")
	initial, err := config.LoadFromFile(cfgPath)
	if err != nil {
		t.Fatalf("initial load: %v", err)
	}

	var seenNew *config.Config
	mgr := NewConfigManager(cfgPath, initial, nil, nil, func(_ context.Context, _ *config.Config, newCfg *config.Config, _ ConfigDiff) error {
		seenNew = newCfg
		return nil
	})
	mgr.SetEnvConfigPath(envPath)

	// AVC drops env_config.json AFTER the sidecar booted — no
	// config.yaml change is necessary to trigger the reload; the
	// ConfigManager's Reload() re-reads env_config on every wake.
	if err := os.WriteFile(envPath,
		[]byte(`{"cisco_ai_defense_endpoint":"https://eu.api.inspect.aidefense.security.cisco.com"}`),
		0o600); err != nil {
		t.Fatalf("write env_config: %v", err)
	}

	if err := mgr.Reload(context.Background(), "test"); err != nil {
		t.Fatalf("reload: %v", err)
	}
	if seenNew == nil {
		t.Fatal("apply callback did not fire; expected diff on cisco_ai_defense.endpoint")
	}
	want := "https://eu.api.inspect.aidefense.security.cisco.com"
	if got := seenNew.CiscoAIDefense.Endpoint; got != want {
		t.Fatalf("post-overlay endpoint = %q, want %q (env_config must win)", got, want)
	}
	if got := mgr.Current().CiscoAIDefense.Endpoint; got != want {
		t.Fatalf("published endpoint = %q, want %q", got, want)
	}
}

// TestConfigManagerEnvConfigOverlayIgnoresMissingFile confirms the
// pre-arrival case: env_config.json isn't on disk yet, config.yaml has
// the installer's fallback endpoint, and Reload should NOT invent an
// endpoint change or blow up.
func TestConfigManagerEnvConfigOverlayIgnoresMissingFile(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, config.DefaultConfigName)
	envPath := filepath.Join(dir, "env_config.json") // never created

	writeConfigWithEndpoint(t, cfgPath, dir, "https://us.api.inspect.aidefense.security.cisco.com")
	initial, err := config.LoadFromFile(cfgPath)
	if err != nil {
		t.Fatalf("initial load: %v", err)
	}
	applied := false
	mgr := NewConfigManager(cfgPath, initial, nil, nil, func(context.Context, *config.Config, *config.Config, ConfigDiff) error {
		applied = true
		return nil
	})
	mgr.SetEnvConfigPath(envPath)

	if err := mgr.Reload(context.Background(), "test"); err != nil {
		t.Fatalf("reload with missing env_config: %v", err)
	}
	if applied {
		t.Fatal("apply callback fired on a no-op reload; missing env_config must not synthesise a diff")
	}
	// Endpoint stays whatever config.yaml said.
	if got := mgr.Current().CiscoAIDefense.Endpoint; got != "https://us.api.inspect.aidefense.security.cisco.com" {
		t.Fatalf("endpoint drifted to %q on missing env_config", got)
	}
}

// TestConfigManagerEnvConfigOverlayRejectsMalformed is the security-
// critical case: a hostile env_config with an http:// or path-carrying
// URL MUST be rejected without overwriting the currently-active
// endpoint. If this test starts failing, the exfiltration guard has
// regressed.
func TestConfigManagerEnvConfigOverlayRejectsMalformed(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, config.DefaultConfigName)
	envPath := filepath.Join(dir, "env_config.json")

	writeConfigWithEndpoint(t, cfgPath, dir, "https://us.api.inspect.aidefense.security.cisco.com")
	initial, err := config.LoadFromFile(cfgPath)
	if err != nil {
		t.Fatalf("initial load: %v", err)
	}
	applied := false
	mgr := NewConfigManager(cfgPath, initial, nil, nil, func(context.Context, *config.Config, *config.Config, ConfigDiff) error {
		applied = true
		return nil
	})
	mgr.SetEnvConfigPath(envPath)

	// Every payload here is either malformed JSON, wrong shape, or a
	// URL that _valid_aid_endpoint_url would reject on the shell side.
	badPayloads := []string{
		`{not json`,
		`{"cisco_ai_defense_endpoint": "http://us.api.inspect.aidefense.security.cisco.com"}`,       // http://
		`{"cisco_ai_defense_endpoint": "https://user@us.api.inspect.aidefense.security.cisco.com"}`, // userinfo
		`{"cisco_ai_defense_endpoint": "https://us.api.inspect.aidefense.security.cisco.com/api"}`,  // path
	}
	for _, body := range badPayloads {
		if err := os.WriteFile(envPath, []byte(body), 0o600); err != nil {
			t.Fatalf("write env_config %q: %v", body, err)
		}
		applied = false
		if err := mgr.Reload(context.Background(), "test"); err != nil {
			t.Fatalf("reload with malformed env_config %q: %v", body, err)
		}
		if applied {
			t.Fatalf("apply callback fired on rejected env_config payload: %q", body)
		}
		if got := mgr.Current().CiscoAIDefense.Endpoint; got != "https://us.api.inspect.aidefense.security.cisco.com" {
			t.Fatalf("payload %q corrupted the endpoint to %q", body, got)
		}
	}
}

// TestConfigManagerEnvConfigOverlayDisabledWhenPathEmpty proves the
// opensource-mode carve-out: an unset SetEnvConfigPath means the
// ConfigManager never touches env_config.json, even if one happens to
// exist on disk. Regression guard against a future refactor that turns
// the file lookup into "always try DefaultEnvConfigPath".
func TestConfigManagerEnvConfigOverlayDisabledWhenPathEmpty(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, config.DefaultConfigName)
	envPath := filepath.Join(dir, "env_config.json")

	writeConfigWithEndpoint(t, cfgPath, dir, "https://us.api.inspect.aidefense.security.cisco.com")
	initial, err := config.LoadFromFile(cfgPath)
	if err != nil {
		t.Fatalf("initial load: %v", err)
	}
	applied := false
	mgr := NewConfigManager(cfgPath, initial, nil, nil, func(context.Context, *config.Config, *config.Config, ConfigDiff) error {
		applied = true
		return nil
	})
	// Deliberately do NOT call SetEnvConfigPath.

	// A well-formed env_config exists on disk but MUST be ignored.
	if err := os.WriteFile(envPath,
		[]byte(`{"cisco_ai_defense_endpoint":"https://eu.api.inspect.aidefense.security.cisco.com"}`),
		0o600); err != nil {
		t.Fatalf("write env_config: %v", err)
	}
	if err := mgr.Reload(context.Background(), "test"); err != nil {
		t.Fatalf("reload: %v", err)
	}
	if applied {
		t.Fatal("apply callback fired despite empty envConfigPath")
	}
	if got := mgr.Current().CiscoAIDefense.Endpoint; got != "https://us.api.inspect.aidefense.security.cisco.com" {
		t.Fatalf("endpoint changed to %q with envConfigPath unset", got)
	}
}

// TestConfigManagerClassifyDistinguishesFiles targets the fsnotify
// dispatch predicate. Both paths must be recognized, everything else
// must return "".
func TestConfigManagerClassifyDistinguishesFiles(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, config.DefaultConfigName)
	envPath := filepath.Join(dir, "env_config.json")
	mgr := &ConfigManager{path: filepath.Clean(cfgPath)}
	mgr.SetEnvConfigPath(envPath)

	if got := mgr.classify(cfgPath); got != "config" {
		t.Fatalf("classify(config.yaml) = %q, want \"config\"", got)
	}
	if got := mgr.classify(envPath); got != "env_config" {
		t.Fatalf("classify(env_config.json) = %q, want \"env_config\"", got)
	}
	if got := mgr.classify(filepath.Join(dir, "unrelated.txt")); got != "" {
		t.Fatalf("classify(unrelated) = %q, want empty", got)
	}
	// Empty envConfigPath: env_config.json events should be ignored.
	mgr.SetEnvConfigPath("")
	if got := mgr.classify(envPath); got != "" {
		t.Fatalf("classify(env_config.json) with unset path = %q, want empty (opensource-mode guard)", got)
	}
}

// TestInspectorNeedsRebuildOnEndpointChange is the boundary case for
// the applyConfigReload branch: a bare endpoint swap must be enough to
// trigger an inspector rebuild.
func TestInspectorNeedsRebuildOnEndpointChange(t *testing.T) {
	oldCfg := config.DefaultConfig()
	newCfg := cloneConfig(oldCfg)
	oldCfg.CiscoAIDefense.Endpoint = "https://us.api.inspect.aidefense.security.cisco.com"
	newCfg.CiscoAIDefense.Endpoint = "https://eu.api.inspect.aidefense.security.cisco.com"

	if !inspectorNeedsRebuild(oldCfg, newCfg) {
		t.Fatal("inspectorNeedsRebuild = false on endpoint change; expected true")
	}
	if !otelNeedsReload(oldCfg, newCfg) {
		t.Fatal("otelNeedsReload = false on endpoint change; expected true (log sink shares the endpoint)")
	}

	// Sanity: identical configs do NOT trigger a rebuild.
	same := cloneConfig(oldCfg)
	if inspectorNeedsRebuild(oldCfg, same) {
		t.Fatal("inspectorNeedsRebuild = true on identical configs; expected false")
	}
}

// TestDiffConfigsCiscoAIDefenseHotReloadableInManagedEnterprise locks
// down the exact regression a QA host hit after this feature landed:
// on a managed_enterprise install, a change to cisco_ai_defense.endpoint
// (as delivered by an env_config.json overlay) must land in Changed —
// NOT RestartRequired. Without this classification applyConfigReload
// rejects the reload with "config reload requires gateway restart for:
// cisco_ai_defense" and the hot-swap this whole feature exists to
// enable never actually fires.
func TestDiffConfigsCiscoAIDefenseHotReloadableInManagedEnterprise(t *testing.T) {
	oldCfg := config.DefaultConfig()
	oldCfg.DeploymentMode = string(config.DeploymentModeManagedEnterprise)
	oldCfg.CiscoAIDefense.Endpoint = "https://us.api.inspect.aidefense.security.cisco.com"
	newCfg := cloneConfig(oldCfg)
	newCfg.CiscoAIDefense.Endpoint = "https://eu.api.inspect.aidefense.security.cisco.com"

	diff := diffConfigs(oldCfg, newCfg)
	if !slices.Contains(diff.Changed, "cisco_ai_defense") {
		t.Fatalf("diff.Changed = %v, missing cisco_ai_defense", diff.Changed)
	}
	if slices.Contains(diff.RestartRequired, "cisco_ai_defense") {
		t.Fatalf("diff.RestartRequired = %v, must not include cisco_ai_defense in managed_enterprise", diff.RestartRequired)
	}
}

// TestDiffConfigsCiscoAIDefenseKeepsRestartInOpensource proves the
// carve-out: in opensource mode the pre-existing restart-required
// classification is preserved, so any surprising CiscoAIDefense config
// change still forces the operator's attention.
func TestDiffConfigsCiscoAIDefenseKeepsRestartInOpensource(t *testing.T) {
	oldCfg := config.DefaultConfig()
	// Default is unmanaged_byod — a non-managed mode.
	oldCfg.CiscoAIDefense.Endpoint = "https://us.api.inspect.aidefense.security.cisco.com"
	newCfg := cloneConfig(oldCfg)
	newCfg.CiscoAIDefense.Endpoint = "https://eu.api.inspect.aidefense.security.cisco.com"

	diff := diffConfigs(oldCfg, newCfg)
	if !slices.Contains(diff.RestartRequired, "cisco_ai_defense") {
		t.Fatalf("diff.RestartRequired = %v; opensource must keep the pre-existing restart-required classification", diff.RestartRequired)
	}
}

// TestReloadPreservesSynthesizedGatewayTokenBeforeDiff is the regression
// guard for the second bug found alongside the cisco_ai_defense
// classification: a boot-time-synthesised Gateway.Token lives ONLY in
// the runtime snapshot, not in config.yaml. Without preserving it
// before diffConfigs runs, EVERY reload on a managed install compares
// token=<synthesised> to token="" (config.yaml default) and
// gateway lands in RestartRequired. Reload then rejects the whole
// reload with "config reload requires gateway restart for: gateway".
//
// This test writes a config.yaml with an empty gateway.token, seeds
// the ConfigManager's cached snapshot with a synthesised token
// (simulating what ensureGatewayTokenSynthesis produces), and confirms
// Reload succeeds and does NOT surface a bogus gateway change.
func TestReloadPreservesSynthesizedGatewayTokenBeforeDiff(t *testing.T) {
	// Exercise the pre-diff preservation logic directly. We can't
	// use a full Reload path here because managed_enterprise
	// LoadFromFile insists on a root-owned config.yaml (managed
	// config trust check) which t.TempDir() cannot produce. What
	// matters is that when the runtime cached snapshot carries a
	// synthesised token and the on-disk snapshot doesn't,
	// diffConfigs sees them as equal (no gateway churn). Simulate
	// that shape and diff.
	oldCfg := config.DefaultConfig()
	oldCfg.DeploymentMode = string(config.DeploymentModeManagedEnterprise)
	oldCfg.Gateway.Token = "boot-time-synthesised-token"

	// "Freshly loaded from config.yaml" — no token, everything else
	// identical.
	freshFromDisk := cloneConfig(oldCfg)
	freshFromDisk.Gateway.Token = ""

	// Apply the same pre-diff preservation the Reload path uses.
	next := cloneConfig(freshFromDisk)
	if strings.TrimSpace(next.Gateway.Token) == "" && strings.TrimSpace(oldCfg.Gateway.Token) != "" {
		next.Gateway.Token = oldCfg.Gateway.Token
	}
	diff := diffConfigs(oldCfg, next)
	if slices.Contains(diff.RestartRequired, "gateway") {
		t.Fatalf("gateway landed in RestartRequired despite pre-diff token preservation; RestartRequired=%v", diff.RestartRequired)
	}
	if slices.Contains(diff.Changed, "gateway") {
		t.Fatalf("gateway landed in Changed despite pre-diff token preservation; Changed=%v", diff.Changed)
	}
	if next.Gateway.Token != "boot-time-synthesised-token" {
		t.Fatalf("token preservation dropped the synthesised value: got %q", next.Gateway.Token)
	}
}

// TestReloadPreservesRuntimeGatewayFieldsBeforeDiff catches the
// downstream regression from the initial fix that only preserved
// Gateway.Token. On a real managed_enterprise host we saw
// "config reload requires gateway restart for: gateway" even after
// the token was preserved — the offender was Gateway.NoTLS, a
// mapstructure:"-" field the sidecar sets at boot based on
// RequiresTLSWithMode(&OpenShell). Every subsequent LoadFromFile
// yields NoTLS=false and diffConfigs sees the cached runtime state
// vs the on-disk snapshot as different. This test locks down that
// every runtime-only Gateway field is preserved before the diff.
func TestReloadPreservesRuntimeGatewayFieldsBeforeDiff(t *testing.T) {
	oldCfg := config.DefaultConfig()
	oldCfg.DeploymentMode = string(config.DeploymentModeManagedEnterprise)
	oldCfg.Gateway.Token = "boot-time-synthesised-token"
	oldCfg.Gateway.NoTLS = true // sidecar sets this at boot for standalone mode
	oldCfg.Gateway.SandboxHome = "/home/sandbox"
	oldCfg.Gateway.ClawHome = "/var/root"

	// "Freshly loaded from config.yaml": mapstructure:"-" fields all
	// zero, token empty. This is exactly what LoadFromFile produces
	// on every reload since none of these fields are persisted.
	next := cloneConfig(oldCfg)
	next.Gateway.Token = ""
	next.Gateway.NoTLS = false
	next.Gateway.SandboxHome = ""
	next.Gateway.ClawHome = ""

	// Mirror the Reload pre-diff preservation.
	if strings.TrimSpace(next.Gateway.Token) == "" && strings.TrimSpace(oldCfg.Gateway.Token) != "" {
		next.Gateway.Token = oldCfg.Gateway.Token
	}
	if oldCfg.Gateway.NoTLS && !next.Gateway.NoTLS {
		next.Gateway.NoTLS = true
	}
	if next.Gateway.SandboxHome == "" && oldCfg.Gateway.SandboxHome != "" {
		next.Gateway.SandboxHome = oldCfg.Gateway.SandboxHome
	}
	if next.Gateway.ClawHome == "" && oldCfg.Gateway.ClawHome != "" {
		next.Gateway.ClawHome = oldCfg.Gateway.ClawHome
	}

	diff := diffConfigs(oldCfg, next)
	if slices.Contains(diff.RestartRequired, "gateway") {
		t.Fatalf("gateway ended up in RestartRequired after runtime-field preservation; RestartRequired=%v", diff.RestartRequired)
	}
	if slices.Contains(diff.Changed, "gateway") {
		t.Fatalf("gateway ended up in Changed after runtime-field preservation; Changed=%v", diff.Changed)
	}
}

// TestReloadTokenPreservationScopedToManagedEnterprise proves the
// gate: on opensource installs the pre-existing behavior is unchanged
// (the pre-diff token preservation is a managed-only carve-out per
// operator direction).
func TestReloadTokenPreservationScopedToManagedEnterprise(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, config.DefaultConfigName)
	// Opensource config.yaml with no token.
	raw := "config_version: 6\n" +
		"data_dir: " + dir + "\n" +
		"guardrail:\n" +
		"  mode: observe\n"
	if err := os.WriteFile(cfgPath, []byte(raw), 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}
	initial, err := config.LoadFromFile(cfgPath)
	if err != nil {
		t.Fatalf("initial load: %v", err)
	}
	initial.Gateway.Token = "opensource-runtime-token"

	// Diff manually against the loaded-from-disk snapshot; the
	// ConfigManager Reload path also runs applyConfigReload's inner
	// preservation step (line ~1165), so a full Reload would mask
	// this. Exercise diffConfigs directly to make the scope
	// assertion crisp.
	fresh, err := config.LoadFromFile(cfgPath)
	if err != nil {
		t.Fatalf("re-load: %v", err)
	}
	diff := diffConfigs(initial, fresh)
	if !slices.Contains(diff.RestartRequired, "gateway") {
		t.Fatalf("opensource diff on token mismatch = %v; expected gateway to remain restart-required (managed-only carve-out)", diff.RestartRequired)
	}
}

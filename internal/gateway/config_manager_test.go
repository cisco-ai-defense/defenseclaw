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

func TestDiffConfigsRequiresRestartForAgentControlRawSpoolChange(t *testing.T) {
	oldCfg := config.DefaultConfig()
	newCfg := cloneConfig(oldCfg)
	newCfg.AgentControl.Enabled = true
	newCfg.AgentControl.Observability.Enabled = true
	newCfg.AgentControl.Observability.IncludeContent = true

	diff := diffConfigs(oldCfg, newCfg)
	if !slices.Contains(diff.Changed, "agent_control.observability") {
		t.Fatalf("changed = %v, missing agent_control.observability", diff.Changed)
	}
	if !slices.Contains(diff.RestartRequired, "agent_control.observability") {
		t.Fatalf("restart_required = %v, missing agent_control.observability", diff.RestartRequired)
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

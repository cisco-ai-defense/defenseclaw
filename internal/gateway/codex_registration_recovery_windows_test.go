// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package gateway

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/gateway/connector"
	"github.com/defenseclaw/defenseclaw/internal/guardrail"
	"github.com/defenseclaw/defenseclaw/internal/testenv"
	"github.com/fsnotify/fsnotify"
	"github.com/pelletier/go-toml/v2"
)

type codexRegistrationAcceptanceConnector struct {
	stubConnector
	managedPath string
	setupCalls  atomic.Int32
	blockMu     sync.Mutex
	setupStart  chan<- struct{}
	setupWait   <-chan struct{}
	skipWrite   atomic.Bool
}

func newCodexRegistrationAcceptanceConnector(managedPath string) *codexRegistrationAcceptanceConnector {
	return &codexRegistrationAcceptanceConnector{
		stubConnector: stubConnector{name: "codex"},
		managedPath:   managedPath,
	}
}

func (c *codexRegistrationAcceptanceConnector) Setup(context.Context, connector.SetupOpts) error {
	c.setupCalls.Add(1)
	c.blockMu.Lock()
	started := c.setupStart
	wait := c.setupWait
	c.blockMu.Unlock()
	if started != nil {
		select {
		case started <- struct{}{}:
		default:
		}
	}
	if wait != nil {
		<-wait
	}
	if c.skipWrite.Load() {
		return nil
	}
	raw, err := os.ReadFile(c.managedPath)
	if err != nil && !os.IsNotExist(err) {
		return err
	}
	doc := map[string]interface{}{}
	if len(raw) > 0 {
		if err := toml.Unmarshal(raw, &doc); err != nil {
			return err
		}
	}
	doc["defenseclaw_registration"] = map[string]interface{}{
		"command": "defenseclaw-owned-runtime",
		"event":   "SessionStart",
	}
	out, err := toml.Marshal(doc)
	if err != nil {
		return err
	}
	return os.WriteFile(c.managedPath, out, 0o600)
}

func (c *codexRegistrationAcceptanceConnector) Teardown(context.Context, connector.SetupOpts) error {
	raw, err := os.ReadFile(c.managedPath)
	if err != nil {
		return err
	}
	doc := map[string]interface{}{}
	if err := toml.Unmarshal(raw, &doc); err != nil {
		return err
	}
	delete(doc, "defenseclaw_registration")
	out, err := toml.Marshal(doc)
	if err != nil {
		return err
	}
	return os.WriteFile(c.managedPath, out, 0o600)
}

func (c *codexRegistrationAcceptanceConnector) HookCapabilities(connector.SetupOpts) connector.HookCapability {
	return connector.HookCapability{ConfigPath: c.managedPath}
}

func (*codexRegistrationAcceptanceConnector) HookConfigReferenceNeedles(connector.SetupOpts) []string {
	return []string{"defenseclaw-owned-runtime"}
}

func (*codexRegistrationAcceptanceConnector) HookAPIPath() string {
	return "/api/v1/codex/hook"
}

func TestCodexRegistrationRecoversOnAuthenticatedSessionStartAfterReadditionAndRestart(t *testing.T) {
	root := testenv.PrivateTempDir(t)
	dataDir := filepath.Join(root, "defenseclaw-home")
	codexHome := filepath.Join(root, "codex-home")
	foreignHome := filepath.Join(root, "foreign-codex-home")
	runtimeHome := filepath.Join(root, "runtime-home")
	configPath := filepath.Join(codexHome, "config.toml")
	managedPath := filepath.Join(codexHome, "managed_config.toml")
	foreignPath := filepath.Join(foreignHome, "managed_config.toml")
	launcherDir := filepath.Join(runtimeHome, ".local", "bin")
	for _, dir := range []string{dataDir, codexHome, foreignHome, launcherDir} {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	testenv.SetHome(t, runtimeHome)
	trustConfig, err := json.Marshal(map[string]interface{}{
		"ai_discovery": map[string]interface{}{
			"require_trusted_binary_paths": true,
			"trusted_binary_prefixes":      []string{dataDir},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dataDir, "config.yaml"), append(trustConfig, '\n'), 0o600); err != nil {
		t.Fatalf("write isolated trusted-executable fixture config: %v", err)
	}
	operatorConfig := []byte("model = \"operator-model\"\n[operator_preferences]\ntelemetry = \"minimal\"\n")
	operatorManaged := []byte("[operator_policy]\nmode = \"strict\"\n\n[[hooks.PreToolUse]]\nmatcher = \"^OperatorTool$\"\n\n[[hooks.PreToolUse.hooks]]\ntype = \"command\"\ncommand = \"D:/operator-owned/foreign-hook.exe\"\ntimeout = 7\n")
	foreignManaged := []byte("[foreign_profile]\nowner = \"operator\"\n")
	if err := os.WriteFile(configPath, operatorConfig, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(managedPath, operatorManaged, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(foreignPath, foreignManaged, 0o600); err != nil {
		t.Fatal(err)
	}
	previousConfigPath := connector.CodexConfigPathOverride
	connector.CodexConfigPathOverride = configPath
	t.Cleanup(func() { connector.CodexConfigPathOverride = previousConfigPath })
	t.Setenv("CODEX_HOME", codexHome)

	const gatewayToken = "non-secret-gateway-fixture"
	hookToken, err := connector.EnsureHookAPIToken(dataDir, "codex")
	if err != nil {
		t.Fatalf("create scoped Codex hook token: %v", err)
	}
	conn := connector.NewCodexConnector()
	opts := connector.SetupOpts{
		DataDir:            dataDir,
		APIAddr:            "127.0.0.1:18970",
		APIToken:           hookToken,
		HookAPIToken:       hookToken,
		HookAPITokenScoped: true,
		HookFailMode:       "open",
	}
	prepareCodexSetupPolicyFixture(t, dataDir, &opts)
	if err := os.Link(
		opts.AgentExecutable,
		filepath.Join(launcherDir, "defenseclaw-hook.exe"),
	); err != nil {
		t.Fatalf("link isolated native hook launcher fixture: %v", err)
	}
	cfg := &config.Config{
		DataDir: dataDir,
		Gateway: config.GatewayConfig{Token: gatewayToken},
		Guardrail: config.GuardrailConfig{
			Enabled:                true,
			Connector:              "codex",
			Mode:                   "observe",
			HookFailMode:           "open",
			HookSelfHeal:           true,
			HookSelfHealDebounceMs: 60_000,
			Connectors: map[string]config.PerConnectorGuardrailConfig{
				"codex": {Mode: "observe", HookFailMode: "open"},
			},
		},
	}
	setupSidecar := &Sidecar{cfg: cfg, health: NewSidecarHealth()}
	if err := setupSidecar.setupOneConnector(
		context.Background(), conn, opts, gatewayToken, guardrail.NewRulePackCache(),
	); err != nil {
		t.Fatalf("initial Codex setup: %v", err)
	}
	if err := conn.Teardown(context.Background(), opts); err != nil {
		t.Fatalf("Codex teardown: %v", err)
	}
	if err := connector.ClearHookContractLockEntry(dataDir, "codex"); err != nil {
		t.Fatalf("clear Codex contract after teardown: %v", err)
	}
	if restored, err := os.ReadFile(managedPath); err != nil || !managedConfigMatchesOperatorSeed(restored) {
		t.Fatalf("teardown did not restore operator managed config semantically: err=%v\n%s", err, restored)
	}
	// A real CLI re-add resolves the current Codex executable and publishes a
	// fresh protected selection receipt before the gateway applies connector
	// Setup. Model that authority boundary after the full teardown cleared the
	// prior connector lock/runtime record.
	publishCodexSetupSelectionFixture(t, dataDir, opts)
	if err := setupSidecar.setupOneConnector(
		context.Background(), conn, opts, gatewayToken, guardrail.NewRulePackCache(),
	); err != nil {
		t.Fatalf("Codex re-addition: %v", err)
	}
	if present, err := connector.OwnedHooksPresent(conn, opts); err != nil || !present {
		t.Fatalf("Codex re-addition did not publish registration: present=%v err=%v", present, err)
	}
	locked := connector.LoadHookContractLockEntry(dataDir, "codex")
	if locked.Connector != "codex" || locked.HookFailMode != "open" {
		t.Fatalf("Codex re-addition did not publish its hook-contract lock: %+v", locked)
	}

	// Model the exact observed late stale teardown after successful re-addition.
	// Connector.Teardown restores the operator's managed_config.toml and leaves
	// the already-published contract lock/shared runtime state behind. A stale
	// connector-flat runtime record models the captured partial teardown state:
	// status still resolves windows-sidecar=open from the shared JSON, but the
	// real managed hook matrix is registration-missing.
	if err := conn.Teardown(context.Background(), opts); err != nil {
		t.Fatalf("late stale Codex teardown: %v", err)
	}
	if err := os.WriteFile(
		filepath.Join(dataDir, "hooks", ".hookcfg.codex"),
		[]byte("DEFENSECLAW_CONNECTOR=codex\nDEFENSECLAW_FAIL_MODE=closed\n"),
		0o600,
	); err != nil {
		t.Fatalf("stage stale connector runtime record: %v", err)
	}
	if present, err := connector.OwnedHooksPresent(conn, opts); err != nil || present {
		t.Fatalf("late teardown did not remove managed registration: present=%v err=%v", present, err)
	}
	if got := connector.LoadHookContractLockEntry(dataDir, "codex"); got.Connector != "codex" || got.HookFailMode != "open" {
		t.Fatalf("late teardown unexpectedly removed Codex lock evidence: %+v", got)
	}
	sharedRuntime, err := os.ReadFile(filepath.Join(dataDir, "hooks", ".hookcfg"))
	if err != nil || !bytes.Contains(sharedRuntime, []byte(`"codex": "open"`)) {
		t.Fatalf("late teardown unexpectedly removed shared Codex runtime mode: err=%v body=%q", err, sharedRuntime)
	}

	// Replacement gateway resolves its connector options only from protected
	// persisted authority, just like a real process restart.
	sidecar := &Sidecar{cfg: cfg, health: NewSidecarHealth()}
	restartOpts, err := sidecar.connectorSetupOptsChecked(conn, gatewayToken, "127.0.0.1:4000", "127.0.0.1:18970")
	if err != nil {
		t.Fatalf("replacement gateway resolve Codex setup options: %v", err)
	}
	if restartOpts.AgentExecutable == "" || restartOpts.AgentVersion == "" {
		t.Fatal("replacement gateway did not consume protected setup-selection authority")
	}
	registry := connector.NewRegistry()
	registry.RegisterBuiltin(conn)
	api := NewAPIServer("127.0.0.1:18970", sidecar.health, nil, nil, nil, cfg)
	api.SetConnectorRegistry(registry)
	sidecar.setAPIServer(api)
	defer sidecar.setAPIServer(nil)

	body, err := json.Marshal(map[string]interface{}{
		"hook_event_name": "SessionStart",
		"session_id":      "registration-recovery-session",
		"source":          "startup",
	})
	if err != nil {
		t.Fatal(err)
	}
	unauthorized := httptest.NewRequest(http.MethodPost, "http://127.0.0.1:18970/api/v1/codex/hook", bytes.NewReader(body))
	unauthorized.RemoteAddr = "127.0.0.1:49151"
	unauthorized.Header.Set("Authorization", "Bearer non-secret-wrong-fixture")
	unauthorizedRecorder := httptest.NewRecorder()
	api.tokenAuth(api.handleAgentHook("codex")).ServeHTTP(unauthorizedRecorder, unauthorized)
	if unauthorizedRecorder.Code != http.StatusUnauthorized {
		t.Fatalf("unauthenticated Codex SessionStart status=%d, want 401", unauthorizedRecorder.Code)
	}
	if got := connector.LoadHookContractLockEntry(dataDir, "codex"); got.UpdatedAt != locked.UpdatedAt {
		t.Fatalf("unauthenticated SessionStart refreshed contract evidence: before=%q after=%q", locked.UpdatedAt, got.UpdatedAt)
	}
	if present, err := connector.OwnedHooksPresent(conn, restartOpts); err != nil || present {
		t.Fatalf("unauthenticated SessionStart changed managed registration: present=%v err=%v", present, err)
	}

	req := httptest.NewRequest(http.MethodPost, "http://127.0.0.1:18970/api/v1/codex/hook", bytes.NewReader(body))
	req.RemoteAddr = "127.0.0.1:49152"
	req.Header.Set("Authorization", "Bearer "+hookToken)
	recorder := httptest.NewRecorder()
	requestDone := make(chan struct{})
	go func() {
		api.tokenAuth(api.handleAgentHook("codex")).ServeHTTP(recorder, req)
		close(requestDone)
	}()
	select {
	case <-requestDone:
		t.Fatalf("authenticated SessionStart completed before its startup registration owner was ready: status=%d body=%s", recorder.Code, recorder.Body.String())
	case <-time.After(50 * time.Millisecond):
	}

	// The API listener becomes healthy before the multi-connector guardrail
	// lane finishes Setup and registers its exact hook guard. An authenticated
	// SessionStart arriving in that bounded startup window must hand off to the
	// subsequently registered current owner instead of returning an internal
	// 503 that Codex's fail-open UI renders as a successful hook.
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	replacementGuard := NewHookConfigGuard(nil, nil, time.Hour)
	if !replacementGuard.Start(ctx, conn, restartOpts) {
		t.Fatal("start replacement gateway hook guard")
	}
	sidecar.registerHookConfigGuard(replacementGuard)
	defer func() {
		sidecar.unregisterHookConfigGuard(replacementGuard)
		replacementGuard.Stop()
	}()
	select {
	case <-requestDone:
	case <-time.After(3 * time.Second):
		t.Fatal("authenticated SessionStart did not hand off to the startup registration owner")
	}
	if recorder.Code != http.StatusOK {
		t.Fatalf("authenticated Codex SessionStart status=%d body=%s", recorder.Code, recorder.Body.String())
	}
	if present, err := connector.OwnedHooksPresent(conn, restartOpts); err != nil || !present {
		t.Fatalf("registration-missing persisted after authenticated SessionStart: present=%v err=%v", present, err)
	}
	repairedLock := connector.LoadHookContractLockEntry(dataDir, "codex")
	if repairedLock.Connector != "codex" || repairedLock.HookFailMode != "open" {
		t.Fatalf("authenticated SessionStart did not republish Codex contract evidence: %+v", repairedLock)
	}
	if repairedLock.UpdatedAt == locked.UpdatedAt {
		t.Fatalf("authenticated SessionStart did not refresh Codex contract evidence timestamp %q", repairedLock.UpdatedAt)
	}
	runtimeBody, err := os.ReadFile(filepath.Join(dataDir, "hooks", ".hookcfg.codex"))
	if err != nil || !bytes.Contains(runtimeBody, []byte("DEFENSECLAW_CONNECTOR=codex")) ||
		!bytes.Contains(runtimeBody, []byte("DEFENSECLAW_FAIL_MODE=open")) {
		t.Fatalf("authenticated SessionStart did not republish Codex runtime evidence: err=%v body=%q", err, runtimeBody)
	}

	// Runtime evidence is independently authoritative: even when every
	// agent-visible managed hook remains intact, deleting the protected ready
	// lock must make the next authenticated SessionStart republish it. This
	// prevents status from retaining registration-missing solely because the
	// managed TOML happened to survive a partial teardown/reconciliation race.
	if err := os.Remove(filepath.Join(dataDir, "hook_contract_lock.json")); err != nil {
		t.Fatalf("remove ready lock while managed registration remains: %v", err)
	}
	if present, err := connector.OwnedHooksPresent(conn, restartOpts); err != nil || !present {
		t.Fatalf("managed registration changed while staging missing ready lock: present=%v err=%v", present, err)
	}
	if current, err := connector.HookRuntimeRegistrationCurrent(restartOpts, conn, "test-build"); err != nil || current {
		t.Fatalf("missing ready lock was not detected independently: current=%v err=%v", current, err)
	}
	replacementGuard.mu.Lock()
	replacementGuard.suppressUntil = time.Time{}
	replacementGuard.mu.Unlock()
	lockRepairRequest := httptest.NewRequest(
		http.MethodPost,
		"http://127.0.0.1:18970/api/v1/codex/hook",
		bytes.NewReader(body),
	)
	lockRepairRequest.RemoteAddr = "127.0.0.1:49153"
	lockRepairRequest.Header.Set("Authorization", "Bearer "+hookToken)
	lockRepairRecorder := httptest.NewRecorder()
	api.tokenAuth(api.handleAgentHook("codex")).ServeHTTP(lockRepairRecorder, lockRepairRequest)
	if lockRepairRecorder.Code != http.StatusOK {
		t.Fatalf("authenticated SessionStart did not repair missing ready lock: status=%d body=%s", lockRepairRecorder.Code, lockRepairRecorder.Body.String())
	}
	if got := connector.LoadHookContractLockEntry(dataDir, "codex"); got.Connector != "codex" || got.HookFailMode != "open" {
		t.Fatalf("authenticated SessionStart did not republish missing ready lock: %+v", got)
	}

	assertOperatorCodexStatePreserved(t, configPath, managedPath, foreignPath, operatorManaged, foreignManaged)
	assertPythonGuardrailStatusHasNoCodexRegistrationDrift(t, codexHome, dataDir)
}

func managedConfigMatchesOperatorSeed(raw []byte) bool {
	doc := map[string]interface{}{}
	if toml.Unmarshal(raw, &doc) != nil {
		return false
	}
	policy, _ := doc["operator_policy"].(map[string]interface{})
	return policy["mode"] == "strict" && bytes.Contains(raw, []byte("D:/operator-owned/foreign-hook.exe"))
}

func assertOperatorCodexStatePreserved(
	t *testing.T,
	configPath, managedPath, foreignPath string,
	operatorManaged, foreignManaged []byte,
) {
	t.Helper()
	configRaw, err := os.ReadFile(configPath)
	if err != nil {
		t.Fatal(err)
	}
	configDoc := map[string]interface{}{}
	if err := toml.Unmarshal(configRaw, &configDoc); err != nil {
		t.Fatal(err)
	}
	if configDoc["model"] != "operator-model" {
		t.Fatalf("operator-owned config.toml content changed: %#v", configDoc)
	}
	preferences, _ := configDoc["operator_preferences"].(map[string]interface{})
	if preferences["telemetry"] != "minimal" {
		t.Fatalf("operator-owned telemetry preference changed: %#v", configDoc)
	}

	managedRaw, err := os.ReadFile(managedPath)
	if err != nil {
		t.Fatal(err)
	}
	managedDoc := map[string]interface{}{}
	if err := toml.Unmarshal(managedRaw, &managedDoc); err != nil {
		t.Fatal(err)
	}
	policy, _ := managedDoc["operator_policy"].(map[string]interface{})
	if policy["mode"] != "strict" || !bytes.Contains(managedRaw, []byte("D:/operator-owned/foreign-hook.exe")) {
		t.Fatalf("repair changed operator-owned managed entries:\n%s\npreimage:\n%s", managedRaw, operatorManaged)
	}

	foreignRaw, err := os.ReadFile(foreignPath)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(foreignRaw, foreignManaged) {
		t.Fatalf("repair touched unrelated Codex profile:\n%s", foreignRaw)
	}
}

func TestAuthenticatedSessionStartRejectsUnsafeRuntimeEvidenceWithoutMutation(t *testing.T) {
	// Deliberately use the ordinary shared test temp tree rather than
	// testenv.PrivateTempDir. The protected runtime reader must reject its
	// inherited broad ACL and return before the guard can call Codex Setup.
	root := t.TempDir()
	dataDir := filepath.Join(root, "defenseclaw-home")
	codexHome := filepath.Join(root, "codex-home")
	foreignHome := filepath.Join(root, "foreign-codex-home")
	hookDir := filepath.Join(dataDir, "hooks")
	for _, dir := range []string{hookDir, codexHome, foreignHome} {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			t.Fatal(err)
		}
	}

	configPath := filepath.Join(codexHome, "config.toml")
	managedPath := filepath.Join(codexHome, "managed_config.toml")
	foreignPath := filepath.Join(foreignHome, "managed_config.toml")
	sharedPath := filepath.Join(hookDir, ".hookcfg")
	operatorConfig := []byte("model = \"operator-model\"\n[operator_preferences]\ntelemetry = \"minimal\"\n")
	operatorManaged := []byte("[operator_policy]\nmode = \"strict\"\n")
	foreignManaged := []byte("[foreign_profile]\nowner = \"operator\"\n")
	unsafeEvidence := []byte(`{"version":2,"gateway":"127.0.0.1:18970","fail_modes":{"codex":"open"},"managed":false}`)
	for path, body := range map[string][]byte{
		configPath:  operatorConfig,
		managedPath: operatorManaged,
		foreignPath: foreignManaged,
		sharedPath:  unsafeEvidence,
	} {
		if err := os.WriteFile(path, body, 0o600); err != nil {
			t.Fatalf("seed %s: %v", path, err)
		}
	}

	previousConfigPath := connector.CodexConfigPathOverride
	connector.CodexConfigPathOverride = configPath
	t.Cleanup(func() { connector.CodexConfigPathOverride = previousConfigPath })
	t.Setenv("CODEX_HOME", codexHome)

	conn := connector.NewCodexConnector()
	opts := connector.SetupOpts{
		DataDir:      dataDir,
		APIAddr:      "127.0.0.1:18970",
		HookFailMode: "open",
	}
	present, err := connector.OwnedHooksPresent(conn, opts)
	if err != nil {
		t.Fatalf("inspect missing managed registration: %v", err)
	}
	if present {
		t.Fatal("operator seed unexpectedly contains a DefenseClaw Codex registration")
	}

	guard := NewHookConfigGuard(nil, nil, time.Hour)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	if !guard.Start(ctx, conn, opts) {
		t.Fatal("start Codex registration guard")
	}
	defer guard.Stop()

	err = guard.EnsurePresent(
		context.Background(),
		"codex",
		dataDir,
		"authenticated SessionStart",
	)
	if err == nil || !strings.Contains(err.Error(), "protected state is unsafe or changed while reading") {
		t.Fatalf("unsafe SessionStart registration evidence error=%v, want fail-closed refusal", err)
	}

	for path, want := range map[string][]byte{
		configPath:  operatorConfig,
		managedPath: operatorManaged,
		foreignPath: foreignManaged,
		sharedPath:  unsafeEvidence,
	} {
		got, readErr := os.ReadFile(path)
		if readErr != nil {
			t.Fatalf("read preserved %s: %v", path, readErr)
		}
		if !bytes.Equal(got, want) {
			t.Fatalf("unsafe evidence refusal mutated %s:\n%s\nwant exact preimage:\n%s", path, got, want)
		}
	}
	entries, err := os.ReadDir(hookDir)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 || entries[0].Name() != ".hookcfg" {
		t.Fatalf("unsafe evidence refusal published hook artifacts: %v", entries)
	}
	if _, err := os.Lstat(filepath.Join(dataDir, "hook_contract_lock.json")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("unsafe evidence refusal published a contract lock: %v", err)
	}
}

func assertPythonGuardrailStatusHasNoCodexRegistrationDrift(t *testing.T, codexHome, dataDir string) {
	t.Helper()
	python, err := exec.LookPath("python.exe")
	if err != nil {
		python, err = exec.LookPath("python")
	}
	if err != nil {
		t.Fatalf("Python runtime required for guardrail-status acceptance: %v", err)
	}
	workingDir, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	pythonPath := filepath.Clean(filepath.Join(workingDir, "..", "..", "cli"))
	const script = `
import json
import os
import sys
import types
from types import SimpleNamespace

# The Go-only Windows lane does not install PyYAML. The isolated fixture writes
# its trust block as JSON (a YAML subset), so the standard-library parser is
# sufficient; all path, ACL, digest, product, contract, app-server, and
# managed-hook validation remains production code.
yaml_fixture = types.ModuleType("yaml")
yaml_fixture.safe_load = json.load
sys.modules["yaml"] = yaml_fixture

from click.testing import CliRunner
from defenseclaw import config as dcconfig
from defenseclaw.commands import cmd_guardrail
from defenseclaw.context import AppContext
guardrail = dcconfig.GuardrailConfig()
guardrail.enabled = True
guardrail.mode = "observe"
guardrail.hook_fail_mode = "open"
guardrail.connectors = {"codex": dcconfig.PerConnectorGuardrailConfig(mode="observe", hook_fail_mode="open")}
cfg = SimpleNamespace(
    data_dir=os.environ["DC_ACCEPTANCE_DATA_DIR"],
    guardrail=guardrail,
    gateway=SimpleNamespace(host="127.0.0.1", port=18789),
)
cfg.active_connector = lambda: "codex"
cfg.active_connectors = lambda: ["codex"]
cfg.has_connector_configured = lambda: True
cfg.connector_workspace_dir = lambda: ""
app = AppContext()
app.cfg = cfg
app.logger = None
result = CliRunner().invoke(cmd_guardrail.status_cmd, [], obj=app)
print(result.output)
if result.exit_code != 0:
    raise SystemExit(result.exit_code)
if not all(expected in result.output for expected in ("Codex", "codex", "open")):
    raise SystemExit("Codex open runtime row is missing from guardrail status")
if "registration-missing" in result.output or "runtime fail-mode drift" in result.output:
    raise SystemExit("Codex guardrail status still reports registration drift")
`
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, python, "-c", script)
	overrides := map[string]string{
		"PYTHONPATH":             pythonPath,
		"PYTHONUTF8":             "1",
		"CODEX_HOME":             codexHome,
		"DC_ACCEPTANCE_DATA_DIR": dataDir,
	}
	env := make([]string, 0, len(os.Environ())+len(overrides))
	for _, item := range os.Environ() {
		key, _, _ := strings.Cut(item, "=")
		if _, replaced := overrides[strings.ToUpper(key)]; replaced || strings.EqualFold(key, "DEFENSECLAW_FAIL_MODE") {
			continue
		}
		env = append(env, item)
	}
	for key, value := range overrides {
		env = append(env, key+"="+value)
	}
	cmd.Env = env
	output, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("Python guardrail status acceptance failed: %v\n%s", err, output)
	}
	if !bytes.Contains(output, []byte("Codex")) ||
		!bytes.Contains(output, []byte("codex")) ||
		!bytes.Contains(output, []byte("open")) {
		t.Fatalf("Python guardrail status omitted the Codex open runtime row:\n%s", output)
	}
	if bytes.Contains(output, []byte("registration-missing")) || bytes.Contains(output, []byte("runtime fail-mode drift")) {
		t.Fatalf("Python guardrail status retained Codex registration drift:\n%s", output)
	}
}

func newStartedCodexRegistrationGuard(
	t *testing.T,
) (*HookConfigGuard, *codexRegistrationAcceptanceConnector, connector.SetupOpts, string, []byte) {
	t.Helper()
	root := t.TempDir()
	dataDir := filepath.Join(root, "data")
	managedPath := filepath.Join(root, "codex", "managed_config.toml")
	if err := os.MkdirAll(filepath.Dir(managedPath), 0o700); err != nil {
		t.Fatal(err)
	}
	seed := []byte("[operator_policy]\nmode = \"strict\"\n")
	if err := os.WriteFile(managedPath, seed, 0o600); err != nil {
		t.Fatal(err)
	}
	conn := newCodexRegistrationAcceptanceConnector(managedPath)
	opts := connector.SetupOpts{DataDir: dataDir}
	if err := conn.Setup(context.Background(), opts); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	guard := NewHookConfigGuard(nil, nil, time.Hour)
	if !guard.Start(ctx, conn, opts) {
		cancel()
		t.Fatal("hook registration guard did not start")
	}
	t.Cleanup(func() {
		guard.Stop()
		cancel()
	})
	return guard, conn, opts, managedPath, seed
}

func TestHookConfigGuardEnsurePresentCoalescesConcurrentSessionStarts(t *testing.T) {
	guard, conn, opts, managedPath, seed := newStartedCodexRegistrationGuard(t)
	if err := os.WriteFile(managedPath, seed, 0o600); err != nil {
		t.Fatal(err)
	}
	started := make(chan struct{}, 1)
	release := make(chan struct{})
	conn.blockMu.Lock()
	conn.setupStart = started
	conn.setupWait = release
	conn.blockMu.Unlock()
	before := conn.setupCalls.Load()

	results := make(chan error, 2)
	go func() {
		results <- guard.EnsurePresent(context.Background(), "codex", opts.DataDir, "SessionStart one")
	}()
	select {
	case <-started:
	case <-time.After(3 * time.Second):
		t.Fatal("first SessionStart repair did not enter Setup")
	}
	go func() {
		results <- guard.EnsurePresent(context.Background(), "codex", opts.DataDir, "SessionStart two")
	}()
	close(release)
	for range 2 {
		if err := <-results; err != nil {
			t.Fatalf("coalesced SessionStart repair: %v", err)
		}
	}
	if got := conn.setupCalls.Load() - before; got != 1 {
		t.Fatalf("concurrent SessionStarts ran Setup %d times, want 1", got)
	}
}

func TestHookConfigGuardStopWaitsForStartedRepairAndRejectsQueuedSessionStart(t *testing.T) {
	guard, conn, opts, managedPath, seed := newStartedCodexRegistrationGuard(t)
	if err := os.WriteFile(managedPath, seed, 0o600); err != nil {
		t.Fatal(err)
	}
	started := make(chan struct{}, 1)
	release := make(chan struct{})
	conn.blockMu.Lock()
	conn.setupStart = started
	conn.setupWait = release
	conn.blockMu.Unlock()
	before := conn.setupCalls.Load()

	requestCtx, cancelRequest := context.WithCancel(context.Background())
	first := make(chan error, 1)
	go func() { first <- guard.EnsurePresent(requestCtx, "codex", opts.DataDir, "SessionStart active") }()
	select {
	case <-started:
	case <-time.After(3 * time.Second):
		t.Fatal("active SessionStart repair did not enter Setup")
	}
	cancelRequest()
	stopped := make(chan struct{})
	go func() {
		guard.Stop()
		close(stopped)
	}()
	deadline := time.Now().Add(3 * time.Second)
	for guard.MatchesActiveConnector("codex", opts.DataDir) && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if guard.MatchesActiveConnector("codex", opts.DataDir) {
		t.Fatal("retiring guard remained selectable")
	}
	if err := guard.EnsurePresent(context.Background(), "codex", opts.DataDir, "SessionStart queued"); err == nil {
		t.Fatal("queued SessionStart repaired through a retiring guard")
	}
	select {
	case <-stopped:
		t.Fatal("Stop returned before the active atomic repair completed")
	case <-time.After(50 * time.Millisecond):
	}
	close(release)
	if err := <-first; err != nil {
		t.Fatalf("active repair did not reach an atomic terminal state after client cancellation: %v", err)
	}
	select {
	case <-stopped:
	case <-time.After(3 * time.Second):
		t.Fatal("Stop did not finish after active repair completed")
	}
	if got := conn.setupCalls.Load() - before; got != 1 {
		t.Fatalf("retirement race ran Setup %d times, want only the already-started repair", got)
	}
}

func TestHookConfigGuardExitAndLateNotifierCannotLeaveStaleOwner(t *testing.T) {
	guard, _, opts, _, _ := newStartedCodexRegistrationGuard(t)
	guard.mu.Lock()
	cancel := guard.cancel
	guard.mu.Unlock()
	if cancel == nil {
		t.Fatal("guard cancellation unavailable")
	}
	cancel()
	deactivated := make(chan struct{}, 1)
	go guard.SetDeactivationNotifier(func(*HookConfigGuard) { deactivated <- struct{}{} })
	select {
	case <-deactivated:
	case <-time.After(3 * time.Second):
		t.Fatal("late deactivation notifier was lost during guard exit")
	}
	select {
	case <-guard.done:
	case <-time.After(3 * time.Second):
		t.Fatal("guard did not exit")
	}
	if guard.MatchesActiveConnector("codex", opts.DataDir) {
		t.Fatal("exited guard still reports active ownership")
	}
}

func TestHookConfigGuardWatcherFailureRetainsAuthenticatedRepairOwner(t *testing.T) {
	root := t.TempDir()
	dataDir := filepath.Join(root, "data")
	managedPath := filepath.Join(root, "codex", "managed_config.toml")
	if err := os.MkdirAll(filepath.Dir(managedPath), 0o700); err != nil {
		t.Fatal(err)
	}
	seed := []byte("[operator_policy]\nmode = \"strict\"\n")
	if err := os.WriteFile(managedPath, seed, 0o600); err != nil {
		t.Fatal(err)
	}
	conn := newCodexRegistrationAcceptanceConnector(managedPath)
	opts := connector.SetupOpts{DataDir: dataDir}
	if err := conn.Setup(context.Background(), opts); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(managedPath, seed, 0o600); err != nil {
		t.Fatal(err)
	}

	originalFactory := newHookConfigFSWatcher
	newHookConfigFSWatcher = func() (*fsnotify.Watcher, error) {
		return nil, errors.New("fixture watcher unavailable")
	}
	t.Cleanup(func() { newHookConfigFSWatcher = originalFactory })
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	guard := NewHookConfigGuard(nil, nil, time.Hour)
	guard.policyAudit = 20 * time.Millisecond
	if !guard.Start(ctx, conn, opts) {
		t.Fatal("watcher failure removed the authenticated registration repair owner")
	}
	defer guard.Stop()
	if err := guard.EnsurePresent(context.Background(), "codex", opts.DataDir, "authenticated SessionStart"); err != nil {
		t.Fatalf("request-only registration repair after watcher failure: %v", err)
	}
	if present, err := connector.OwnedHooksPresent(conn, opts); err != nil || !present {
		t.Fatalf("watcher-failure fallback did not restore registration: present=%v err=%v", present, err)
	}
	healed := make(chan []string, 1)
	guard.SetHealNotifier(func(_ string, changed []string) { healed <- changed })
	guard.mu.Lock()
	guard.suppressUntil = time.Time{}
	guard.mu.Unlock()
	if err := os.WriteFile(managedPath, seed, 0o600); err != nil {
		t.Fatal(err)
	}
	select {
	case changed := <-healed:
		if len(changed) != 1 || changed[0] != "periodic registration audit" {
			t.Fatalf("watcher-failure periodic repair reason=%v", changed)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("watcher-failure fallback lost periodic Codex registration audit")
	}
}

func TestHookConfigGuardPeriodicCodexRegistrationAuditRepairsWithoutFileEvent(t *testing.T) {
	root := t.TempDir()
	dataDir := filepath.Join(root, "data")
	managedPath := filepath.Join(root, "codex", "managed_config.toml")
	if err := os.MkdirAll(filepath.Dir(managedPath), 0o700); err != nil {
		t.Fatal(err)
	}
	seed := []byte("[operator_policy]\nmode = \"strict\"\n")
	if err := os.WriteFile(managedPath, seed, 0o600); err != nil {
		t.Fatal(err)
	}
	conn := newCodexRegistrationAcceptanceConnector(managedPath)
	opts := connector.SetupOpts{DataDir: dataDir}
	if err := conn.Setup(context.Background(), opts); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	guard := NewHookConfigGuard(nil, nil, time.Hour)
	guard.policyAudit = 20 * time.Millisecond
	healed := make(chan []string, 1)
	guard.SetHealNotifier(func(_ string, changed []string) { healed <- changed })
	if !guard.Start(ctx, conn, opts) {
		t.Fatal("Codex registration audit guard did not start")
	}
	defer guard.Stop()
	// Replace the file before the audit fires. The one-hour debounce proves
	// repair does not depend on ordinary fsnotify processing.
	if err := os.WriteFile(managedPath, seed, 0o600); err != nil {
		t.Fatal(err)
	}
	select {
	case changed := <-healed:
		if len(changed) != 1 || changed[0] != "periodic registration audit" {
			t.Fatalf("Codex periodic repair reason=%v", changed)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("Codex no-event registration audit did not repair the missing registration")
	}
}

func TestSidecarRefusesAmbiguousHookRegistrationOwners(t *testing.T) {
	first, _, opts, _, _ := newStartedCodexRegistrationGuard(t)
	second, _, _, _, _ := newStartedCodexRegistrationGuard(t)
	// Repoint the second fixture to the same connector/data-home identity; the
	// Sidecar must fail closed instead of selecting map iteration order.
	first.mu.Lock()
	conn := first.conn
	first.mu.Unlock()
	second.Repoint(conn, opts)
	sidecar := &Sidecar{cfg: &config.Config{
		DataDir: opts.DataDir,
		Guardrail: config.GuardrailConfig{
			Enabled:      true,
			Connector:    "codex",
			HookSelfHeal: true,
		},
	}}
	sidecar.registerHookConfigGuard(first)
	sidecar.registerHookConfigGuard(second)
	t.Cleanup(func() {
		sidecar.unregisterHookConfigGuard(first)
		sidecar.unregisterHookConfigGuard(second)
	})
	if err := sidecar.ensureActiveHookRegistration(context.Background(), "codex"); err == nil || !strings.Contains(err.Error(), "multiple active") {
		t.Fatalf("ambiguous guard ownership error=%v, want fail-closed ambiguity", err)
	}
}

func TestSidecarWaitsForCurrentHookRegistrationOwnerDuringStartup(t *testing.T) {
	root := t.TempDir()
	dataDir := filepath.Join(root, "data")
	managedPath := filepath.Join(root, "codex", "managed_config.toml")
	if err := os.MkdirAll(filepath.Dir(managedPath), 0o700); err != nil {
		t.Fatal(err)
	}
	seed := []byte("[operator_policy]\nmode = \"strict\"\n")
	if err := os.WriteFile(managedPath, seed, 0o600); err != nil {
		t.Fatal(err)
	}
	conn := newCodexRegistrationAcceptanceConnector(managedPath)
	opts := connector.SetupOpts{DataDir: dataDir}
	if err := conn.Setup(context.Background(), opts); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(managedPath, seed, 0o600); err != nil {
		t.Fatal(err)
	}

	sidecar := &Sidecar{cfg: &config.Config{
		DataDir: dataDir,
		Guardrail: config.GuardrailConfig{
			Enabled:      true,
			Connector:    "codex",
			HookSelfHeal: true,
		},
	}}
	result := make(chan error, 1)
	go func() {
		result <- sidecar.ensureActiveHookRegistration(context.Background(), "codex")
	}()
	select {
	case err := <-result:
		t.Fatalf("startup SessionStart returned before the current guard registered: %v", err)
	case <-time.After(50 * time.Millisecond):
	}

	ctx, cancel := context.WithCancel(context.Background())
	guard := NewHookConfigGuard(nil, nil, time.Hour)
	if !guard.Start(ctx, conn, opts) {
		cancel()
		t.Fatal("current Codex guard did not start")
	}
	sidecar.registerHookConfigGuard(guard)
	defer func() {
		sidecar.unregisterHookConfigGuard(guard)
		guard.Stop()
		cancel()
	}()
	select {
	case err := <-result:
		if err != nil {
			t.Fatalf("startup SessionStart handoff: %v", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("startup SessionStart did not hand off to the current guard")
	}
	if present, err := connector.OwnedHooksPresent(conn, opts); err != nil || !present {
		t.Fatalf("startup owner did not repair registration: present=%v err=%v", present, err)
	}
}

func TestSidecarStartupOwnerWaitRejectsForeignAndExplicitlyInactiveRequestsImmediately(t *testing.T) {
	dataDir := filepath.Join(t.TempDir(), "data")
	if err := os.MkdirAll(dataDir, 0o700); err != nil {
		t.Fatal(err)
	}
	sidecar := &Sidecar{cfg: &config.Config{
		DataDir: dataDir,
		Guardrail: config.GuardrailConfig{
			Enabled:      true,
			Connector:    "codex",
			HookSelfHeal: true,
		},
	}}
	started := time.Now()
	if err := sidecar.ensureActiveHookRegistration(context.Background(), "claudecode"); err == nil ||
		!strings.Contains(err.Error(), "unsupported") {
		t.Fatalf("foreign owner request error=%v, want immediate unsupported refusal", err)
	}
	if elapsed := time.Since(started); elapsed >= 250*time.Millisecond {
		t.Fatalf("foreign owner request waited for a Codex guard: %v", elapsed)
	}
	if err := os.WriteFile(
		filepath.Join(dataDir, "active_connector.json"),
		[]byte("{\"version\":3,\"inactive_names\":[\"codex\"]}\n"),
		0o600,
	); err != nil {
		t.Fatalf("write explicit Codex inactive fixture: %v", err)
	}
	started = time.Now()
	if err := sidecar.ensureActiveHookRegistration(context.Background(), "codex"); err == nil ||
		!strings.Contains(err.Error(), "explicitly inactive") {
		t.Fatalf("explicitly inactive owner request error=%v, want immediate refusal", err)
	}
	if elapsed := time.Since(started); elapsed >= 250*time.Millisecond {
		t.Fatalf("explicitly inactive owner request waited for a guard: %v", elapsed)
	}
}

func TestSetupOneConnectorRefusesMissingEffectiveRegistration(t *testing.T) {
	root := t.TempDir()
	managedPath := filepath.Join(root, "codex", "managed_config.toml")
	if err := os.MkdirAll(filepath.Dir(managedPath), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(managedPath, []byte("[operator_policy]\nmode = \"strict\"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	conn := newCodexRegistrationAcceptanceConnector(managedPath)
	conn.skipWrite.Store(true)
	sidecar := &Sidecar{cfg: &config.Config{DataDir: filepath.Join(root, "data")}}
	opts := connector.SetupOpts{DataDir: sidecar.cfg.DataDir}
	err := sidecar.setupOneConnector(context.Background(), conn, opts, "non-secret-master-fixture", guardrail.NewRulePackCache())
	if err == nil || !strings.Contains(err.Error(), "registration verification failed") {
		t.Fatalf("setupOneConnector error=%v, want effective-registration refusal", err)
	}
}

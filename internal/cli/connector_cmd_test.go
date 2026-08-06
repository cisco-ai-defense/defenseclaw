// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/pelletier/go-toml/v2"
	"github.com/spf13/cobra"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/gateway/connector"
	"github.com/defenseclaw/defenseclaw/internal/testenv"
)

func TestMain(m *testing.M) {
	if len(os.Args) >= 3 && os.Args[1] == "app-server" && os.Args[2] == "--stdio" {
		serveCodexPolicyFixture()
		os.Exit(0)
	}
	os.Exit(m.Run())
}

// serveCodexPolicyFixture makes a copied native Go test image behave like the
// narrow Codex app-server surface exercised by connector reconciliation. The
// fixture is selected only through a protected, short-lived setup receipt, so
// the command tests traverse the same executable validation path as Windows.
func serveCodexPolicyFixture() {
	decoder := json.NewDecoder(os.Stdin)
	encoder := json.NewEncoder(os.Stdout)
	for {
		var request struct {
			Method string `json:"method"`
			ID     int    `json:"id"`
		}
		if err := decoder.Decode(&request); err != nil {
			os.Exit(31)
		}
		switch request.Method {
		case "initialize":
			if err := encoder.Encode(map[string]any{
				"id": request.ID, "result": map[string]any{"codexHome": "fixture"},
			}); err != nil {
				os.Exit(32)
			}
		case "initialized":
			// Notification; no response is required.
		case "configRequirements/read":
			if err := encoder.Encode(map[string]any{
				"id": request.ID,
				"result": map[string]any{
					"requirements": map[string]any{"allowManagedHooksOnly": false},
				},
			}); err != nil {
				os.Exit(33)
			}
			return
		default:
			os.Exit(34)
		}
	}
}

func seedCodexSelectionForTest(t *testing.T, dataDir string) {
	t.Helper()
	if runtime.GOOS != "windows" {
		return
	}

	sourcePath, err := os.Executable()
	if err != nil {
		t.Fatalf("resolve native test executable: %v", err)
	}
	source, err := os.Open(sourcePath)
	if err != nil {
		t.Fatalf("open native test executable: %v", err)
	}
	defer source.Close()

	executable := filepath.Join(dataDir, "codex.exe")
	destination, err := os.OpenFile(executable, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o700)
	if err != nil {
		t.Fatalf("create native Codex fixture: %v", err)
	}
	hasher := sha256.New()
	if _, err := io.Copy(io.MultiWriter(destination, hasher), source); err != nil {
		_ = destination.Close()
		t.Fatalf("copy native Codex fixture: %v", err)
	}
	if err := destination.Sync(); err != nil {
		_ = destination.Close()
		t.Fatalf("flush native Codex fixture: %v", err)
	}
	if err := destination.Close(); err != nil {
		t.Fatalf("close native Codex fixture: %v", err)
	}

	now := time.Now().UTC().Truncate(time.Second)
	receipt := map[string]any{
		"schema_version": 1,
		"updated_at":     now.Format(time.RFC3339),
		"selections": map[string]any{
			"codex": map[string]any{
				"connector":          "codex",
				"source":             "setup-selected",
				"executable":         executable,
				"raw_version":        "codex 0.144.3",
				"normalized_version": "0.144.3",
				"sha256":             fmt.Sprintf("%x", hasher.Sum(nil)),
				"selected_at":        now.Format(time.RFC3339),
				"expires_at":         now.Add(15 * time.Minute).Format(time.RFC3339),
			},
		},
	}
	body, err := json.Marshal(receipt)
	if err != nil {
		t.Fatalf("encode Codex selection fixture: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dataDir, "agent_selection.json"), body, 0o600); err != nil {
		t.Fatalf("write Codex selection fixture: %v", err)
	}
}

type testHookContractLock struct {
	Version                 int                                        `json:"version"`
	SharedHookScriptDigests map[string]string                          `json:"shared_hook_script_digests"`
	Connectors              map[string]connector.HookContractLockEntry `json:"connectors"`
}

func readTestHookContractLock(t *testing.T, dataDir string) testHookContractLock {
	t.Helper()
	body, err := os.ReadFile(filepath.Join(dataDir, "hook_contract_lock.json"))
	if err != nil {
		t.Fatalf("read hook contract lock: %v", err)
	}
	var lock testHookContractLock
	if err := json.Unmarshal(body, &lock); err != nil {
		t.Fatalf("parse hook contract lock: %v", err)
	}
	return lock
}

func fileDigest(t *testing.T, path string) string {
	t.Helper()
	body, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read digest target %s: %v", path, err)
	}
	sum := sha256.Sum256(body)
	return fmt.Sprintf("sha256:%x", sum[:])
}

func assertMixedHookContractsCurrent(t *testing.T, dataDir, home string) testHookContractLock {
	t.Helper()
	lock := readTestHookContractLock(t, dataDir)
	if lock.Version != 2 || len(lock.SharedHookScriptDigests) == 0 {
		t.Fatalf("shared contract schema not current: %+v", lock)
	}
	for name, expected := range lock.SharedHookScriptDigests {
		if actual := fileDigest(t, filepath.Join(dataDir, "hooks", name)); actual != expected {
			t.Fatalf("shared digest %s=%s want %s", name, actual, expected)
		}
	}
	for _, name := range []string{"claudecode", "codex"} {
		entry, ok := lock.Connectors[name]
		if !ok {
			t.Fatalf("missing %s contract entry", name)
		}
		for artifact, expected := range entry.HookScriptDigests {
			path := filepath.Join(dataDir, "hooks", artifact)
			if runtime.GOOS == "windows" && strings.EqualFold(artifact, "defenseclaw-hook.exe") {
				path = filepath.Join(home, ".local", "bin", "defenseclaw-hook.exe")
			}
			if actual := fileDigest(t, path); actual != expected {
				t.Fatalf("%s artifact %s digest=%s want %s", name, artifact, actual, expected)
			}
		}
	}
	return lock
}

// withConnectorState swaps cfg/flags into a known state for one test and
// restores the originals on teardown. The package-level globals are how
// the cobra commands talk to the rest of the binary, so tests have to
// drive them just like rootCmd.PersistentPreRunE would in production.
func withConnectorState(t *testing.T, dataDir string, conn string) func() {
	t.Helper()
	origCfg := cfg
	origName := connectorFlagName
	origJSON := connectorFlagJSON
	origDir := connectorFlagDataDir
	origConfigHome := connectorFlagConfigHome
	origExit := connectorExit

	cfg = &config.Config{
		DataDir: dataDir,
	}
	cfg.Guardrail.Connector = conn
	cfg.Gateway.APIPort = 18970
	cfg.Guardrail.Port = 4000

	connectorFlagName = ""
	connectorFlagJSON = false
	connectorFlagDataDir = dataDir
	connectorFlagConfigHome = ""

	return func() {
		cfg = origCfg
		connectorFlagName = origName
		connectorFlagJSON = origJSON
		connectorFlagDataDir = origDir
		connectorFlagConfigHome = origConfigHome
		connectorExit = origExit
	}
}

// runConnectorCmd dispatches one of the connector subcommands directly
// (via its RunE function) with stdout/stderr swapped to in-memory
// buffers and the exit-code sentinel intercepted. Going through the
// package-level rootCmd would re-trigger PersistentPreRunE (audit DB +
// OTel exporter), which is both irrelevant to these unit tests and adds
// 10s per case while OTLP retries time out.
func runConnectorCmd(t *testing.T, args ...string) (stdout, stderr string, exitCode int) {
	t.Helper()
	exitCode = 0
	connectorExit = func(code int) { exitCode = code }

	if len(args) == 0 {
		t.Fatal("runConnectorCmd: no subcommand specified")
	}
	sub := args[0]
	tail := args[1:]

	for _, candidate := range []string{"--connector", "--data-dir", "--config-home"} {
		for i, a := range tail {
			if a == candidate && i+1 < len(tail) {
				switch candidate {
				case "--connector":
					connectorFlagName = tail[i+1]
				case "--data-dir":
					connectorFlagDataDir = tail[i+1]
				case "--config-home":
					connectorFlagConfigHome = tail[i+1]
				}
			}
		}
	}
	for _, a := range tail {
		if a == "--json" {
			connectorFlagJSON = true
		}
	}

	var out, errb bytes.Buffer
	cmd := &cobra.Command{Use: sub}
	cmd.SetOut(&out)
	cmd.SetErr(&errb)
	cmd.SetContext(context.Background())

	var err error
	switch sub {
	case "list-backups":
		err = runConnectorListBackups(cmd, nil)
	case "teardown":
		err = runConnectorTeardown(cmd, nil)
	case "verify":
		err = runConnectorVerify(cmd, nil)
	case "reconcile":
		err = runConnectorReconcile(cmd, nil)
	default:
		t.Fatalf("unknown subcommand for harness: %s", sub)
	}
	if err != nil {
		fmt.Fprintln(&errb, err.Error())
	}
	return out.String(), errb.String(), exitCode
}

func assertConnectorReconcileStderr(t *testing.T, name, stderr string) {
	t.Helper()
	warning, err := connector.CheckPlatformSupport(name, runtime.GOOS)
	if err != nil {
		t.Fatalf("platform support for %s: %v", name, err)
	}
	expected := ""
	if warning != "" {
		expected = fmt.Sprintf("connector reconcile %s: warning: %s\n", name, warning)
	}
	if stderr != expected {
		t.Fatalf("%s reconcile stderr = %q, want %q", name, stderr, expected)
	}
}

func TestConnectorReconcileCompatibilityDriftLeavesClaudeSettingsByteExact(t *testing.T) {
	dataDir := testenv.PrivateTempDir(t)
	home := testenv.PrivateTempDir(t)
	settingsPath := filepath.Join(home, "settings.json")
	before := []byte(`{"operator":{"sentinel":"private-fixture"},"hooks":{"Stop":[]}}`)
	if err := os.WriteFile(settingsPath, before, 0o600); err != nil {
		t.Fatal(err)
	}
	originalPath := connector.ClaudeCodeSettingsPathOverride
	connector.ClaudeCodeSettingsPathOverride = settingsPath
	t.Cleanup(func() { connector.ClaudeCodeSettingsPathOverride = originalPath })

	lock := testHookContractLock{
		Version: 1,
		Connectors: map[string]connector.HookContractLockEntry{
			"claudecode": {
				Connector:              "claudecode",
				RawAgentVersion:        "Claude Code 2.1.218",
				NormalizedAgentVersion: "2.1.218",
				ContractID:             "claudecode-hooks-v1",
			},
		},
	}
	lockBody, err := json.Marshal(lock)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dataDir, "hook_contract_lock.json"), lockBody, 0o600); err != nil {
		t.Fatal(err)
	}
	discovery := []byte(`{"agents":{"claudecode":{"version":"Claude Code 2.1.219"}}}`)
	if err := os.WriteFile(filepath.Join(dataDir, "agent_discovery.json"), discovery, 0o600); err != nil {
		t.Fatal(err)
	}

	defer withConnectorState(t, dataDir, "claudecode")()
	connectorFlagConfigHome = home
	cfg.Guardrail.Enabled = true
	cfg.Guardrail.Mode = "action"
	cfg.Guardrail.Connectors = map[string]config.PerConnectorGuardrailConfig{
		"claudecode": {Mode: "action"},
	}

	_, stderr, _ := runConnectorCmd(t, "reconcile", "--connector", "claudecode", "--data-dir", dataDir, "--config-home", home)
	if !strings.Contains(stderr, "hook contract compatibility drift") {
		t.Fatalf("reconcile stderr = %q, want compatibility drift", stderr)
	}
	after, err := os.ReadFile(settingsPath)
	if err != nil {
		t.Fatal(err)
	}
	beforeHash := sha256.Sum256(before)
	afterHash := sha256.Sum256(after)
	if beforeHash != afterHash || !bytes.Equal(before, after) {
		t.Fatalf("failed reconcile changed protected fixture: before=%x after=%x", beforeHash, afterHash)
	}
}

func TestConnectorReconcileRefreshesOnlySelectedRegistration(t *testing.T) {
	dataDir := testenv.PrivateTempDir(t)
	seedCodexSelectionForTest(t, dataDir)
	home := testenv.PrivateTempDir(t)
	codexPath := filepath.Join(home, ".codex", "config.toml")
	if err := os.MkdirAll(filepath.Dir(codexPath), 0o700); err != nil {
		t.Fatal(err)
	}
	claudePath := filepath.Join(home, ".claude", "settings.json")
	if err := os.MkdirAll(filepath.Dir(claudePath), 0o700); err != nil {
		t.Fatal(err)
	}
	claudeBefore := []byte(`{"sentinel":"peer-registration"}`)
	if err := os.WriteFile(claudePath, claudeBefore, 0o600); err != nil {
		t.Fatal(err)
	}
	originalCodexPath := connector.CodexConfigPathOverride
	connector.CodexConfigPathOverride = codexPath
	t.Cleanup(func() { connector.CodexConfigPathOverride = originalCodexPath })

	defer withConnectorState(t, dataDir, "codex")()
	hookToken, err := connector.EnsureHookAPIToken(dataDir, "codex")
	if err != nil {
		t.Fatal(err)
	}
	cfg.Gateway.Token = "master-token-must-not-be-registered"
	cfg.Environment = "windows"
	cfg.Guardrail.Enabled = true
	cfg.Guardrail.HookFailMode = "open"
	cfg.Guardrail.Connectors = map[string]config.PerConnectorGuardrailConfig{
		"codex":      {HookFailMode: "closed"},
		"claudecode": {HookFailMode: "open"},
	}
	stdout, stderr, _ := runConnectorCmd(t, "reconcile", "--connector", "codex", "--json")
	assertConnectorReconcileStderr(t, "codex", stderr)
	if !strings.Contains(stdout, `"fail_mode":"closed"`) {
		t.Fatalf("reconcile output = %s", stdout)
	}
	if _, err := os.Stat(codexPath); err != nil {
		t.Fatalf("selected Codex registration missing: %v", err)
	}
	codexRegistration, err := os.ReadFile(codexPath)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(codexRegistration, []byte(cfg.Gateway.Token)) {
		t.Fatal("selected registration contains the gateway master token")
	}
	if bytes.Contains(codexRegistration, []byte(hookToken)) {
		t.Fatal("selected registration exposes the connector-scoped hook token")
	}
	var codexConfig map[string]interface{}
	if err := toml.Unmarshal(codexRegistration, &codexConfig); err != nil {
		t.Fatalf("parse reconciled Codex config: %v", err)
	}
	otel, ok := codexConfig["otel"].(map[string]interface{})
	if !ok || otel["environment"] != cfg.Environment {
		t.Fatalf("reconciled Codex OTel environment = %#v; want %q", otel["environment"], cfg.Environment)
	}
	otlpToken, err := connector.LoadOTLPPathToken(dataDir, connector.OTLPScopeCodex)
	if err != nil || otlpToken == "" {
		t.Fatalf("load connector-scoped OTLP token = %q, %v", otlpToken, err)
	}
	if !bytes.Contains(codexRegistration, []byte(otlpToken)) {
		t.Fatal("selected registration does not contain the connector-scoped OTLP path token")
	}
	claudeAfter, err := os.ReadFile(claudePath)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(claudeAfter, claudeBefore) {
		t.Fatalf("peer Claude registration changed: %s", claudeAfter)
	}
	lock := connector.LoadHookContractLockEntry(dataDir, "codex")
	if lock.HookFailMode != "closed" {
		t.Fatalf("lock fail mode = %q, want closed", lock.HookFailMode)
	}
}

func TestConnectorReconcilePreservesClaudeCustodyAcrossPeerSetupAndRosterRefresh(t *testing.T) {
	dataDir := testenv.PrivateTempDir(t)
	seedCodexSelectionForTest(t, dataDir)
	home := testenv.PrivateTempDir(t)
	testenv.SetHome(t, home)
	claudePath := filepath.Join(home, ".claude", "settings.json")
	codexPath := filepath.Join(home, ".codex", "config.toml")
	for _, path := range []string{claudePath, codexPath} {
		if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(
		claudePath,
		[]byte(`{"env":{"OPERATOR_SENTINEL":"preserve"}}`),
		0o600,
	); err != nil {
		t.Fatal(err)
	}
	launcher := filepath.Join(home, ".local", "bin", "defenseclaw-hook.exe")
	if runtime.GOOS == "windows" {
		if err := os.MkdirAll(filepath.Dir(launcher), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(launcher, []byte("MZ-native-hook-fixture"), 0o700); err != nil {
			t.Fatal(err)
		}
	}

	previousClaudePath := connector.ClaudeCodeSettingsPathOverride
	previousCodexPath := connector.CodexConfigPathOverride
	connector.ClaudeCodeSettingsPathOverride = claudePath
	connector.CodexConfigPathOverride = codexPath
	t.Cleanup(func() {
		connector.ClaudeCodeSettingsPathOverride = previousClaudePath
		connector.CodexConfigPathOverride = previousCodexPath
	})
	defer withConnectorState(t, dataDir, "claudecode")()
	cfg.Guardrail.Enabled = true
	cfg.Guardrail.HookFailMode = "open"
	cfg.Guardrail.Connectors = map[string]config.PerConnectorGuardrailConfig{
		"claudecode": {HookFailMode: "open"},
		"codex":      {HookFailMode: "open"},
	}
	for _, name := range []string{"claudecode", "codex"} {
		if _, err := connector.EnsureHookAPIToken(dataDir, name); err != nil {
			t.Fatalf("ensure %s token: %v", name, err)
		}
	}
	if err := connector.SaveActiveConnectors(dataDir, []string{"claudecode", "codex"}); err != nil {
		t.Fatalf("save active connector roster: %v", err)
	}

	_, stderr, _ := runConnectorCmd(t, "reconcile", "--connector", "claudecode", "--json")
	assertConnectorReconcileStderr(t, "claudecode", stderr)

	claudeFiles := []string{
		claudePath,
		filepath.Join(dataDir, "connector_backups", "claudecode", "settings.json.json"),
		filepath.Join(dataDir, "claudecode_backup.json"),
		filepath.Join(dataDir, "hooks", ".hookcfg.claudecode"),
		filepath.Join(dataDir, "active_connector.json"),
	}
	claudeBefore := make(map[string][]byte, len(claudeFiles))
	for _, path := range claudeFiles {
		body, err := os.ReadFile(path)
		if err != nil {
			t.Fatalf("read Claude custody file %s: %v", path, err)
		}
		claudeBefore[path] = body
	}
	lockBefore := readTestHookContractLock(t, dataDir).Connectors["claudecode"]
	if lockBefore.Connector != "claudecode" {
		t.Fatalf("Claude lock entry missing before peer setup: %+v", lockBefore)
	}
	cloneDigests := func(source map[string]string) map[string]string {
		cloned := make(map[string]string, len(source))
		for name, digest := range source {
			cloned[name] = digest
		}
		return cloned
	}

	assertClaudeCustody := func(stage string) {
		t.Helper()
		for path, before := range claudeBefore {
			after, err := os.ReadFile(path)
			if err != nil {
				t.Fatalf("%s removed Claude custody file %s: %v", stage, path, err)
			}
			if !bytes.Equal(after, before) {
				t.Fatalf("%s changed Claude custody file %s", stage, path)
			}
		}
		lockAfter := readTestHookContractLock(t, dataDir).Connectors["claudecode"]
		beforeOwned := lockBefore
		afterOwned := lockAfter
		beforeOwned.HookScriptDigests = cloneDigests(lockBefore.HookScriptDigests)
		afterOwned.HookScriptDigests = cloneDigests(lockAfter.HookScriptDigests)
		// The native launcher is shared. A peer Setup may legitimately replace
		// it and atomically advance every connector's digest; all Claude-owned
		// contract fields and its private artifacts must remain unchanged.
		delete(beforeOwned.HookScriptDigests, "defenseclaw-hook.exe")
		delete(afterOwned.HookScriptDigests, "defenseclaw-hook.exe")
		if !reflect.DeepEqual(afterOwned, beforeOwned) {
			t.Fatalf("%s changed Claude lock ownership: before=%+v after=%+v", stage, lockBefore, lockAfter)
		}
		if got := connector.LoadActiveConnectors(dataDir); !reflect.DeepEqual(got, []string{"claudecode", "codex"}) {
			t.Fatalf("%s changed active connector roster: %v", stage, got)
		}

		settingsBody, err := os.ReadFile(claudePath)
		if err != nil {
			t.Fatalf("%s read Claude settings: %v", stage, err)
		}
		var settings map[string]interface{}
		if err := json.Unmarshal(settingsBody, &settings); err != nil {
			t.Fatalf("%s parse Claude settings: %v", stage, err)
		}
		env, ok := settings["env"].(map[string]interface{})
		if !ok || env["OPERATOR_SENTINEL"] != "preserve" || env["CLAUDE_CODE_ENABLE_TELEMETRY"] != "1" {
			t.Fatalf("%s lost Claude operator or managed environment state", stage)
		}
		if hooks, ok := settings["hooks"].(map[string]interface{}); !ok || len(hooks) == 0 {
			t.Fatalf("%s lost Claude hook registration", stage)
		}

		var runtimeState struct {
			Version   int               `json:"version"`
			FailModes map[string]string `json:"fail_modes"`
		}
		runtimeBody, err := os.ReadFile(filepath.Join(dataDir, "hooks", ".hookcfg"))
		if err != nil {
			t.Fatalf("%s read shared runtime state: %v", stage, err)
		}
		if err := json.Unmarshal(runtimeBody, &runtimeState); err != nil {
			t.Fatalf("%s parse shared runtime state: %v", stage, err)
		}
		if runtimeState.Version != 2 ||
			runtimeState.FailModes["claudecode"] != "open" ||
			runtimeState.FailModes["codex"] != "open" {
			t.Fatalf("%s lost Claude runtime state: %+v", stage, runtimeState)
		}
		assertMixedHookContractsCurrent(t, dataDir, home)
	}

	_, stderr, _ = runConnectorCmd(t, "reconcile", "--connector", "codex", "--json")
	assertConnectorReconcileStderr(t, "codex", stderr)
	assertClaudeCustody("unrelated Codex setup")

	// Shared restart maintenance walks the preserved roster through the same
	// selected reconciliation primitive. Exercise the complete roster and keep
	// Claude's configuration, recovery metadata, and runtime ownership exact.
	for _, name := range connector.LoadActiveConnectors(dataDir) {
		_, stderr, _ = runConnectorCmd(t, "reconcile", "--connector", name, "--json")
		assertConnectorReconcileStderr(t, name, stderr)
	}
	assertClaudeCustody("preserved roster reconciliation")
}

func TestConnectorReconcileOpenCodePublishesCompleteActivation(t *testing.T) {
	dataDir := testenv.PrivateTempDir(t)
	home := testenv.PrivateTempDir(t)
	t.Setenv("OPENCODE_CONFIG_DIR", home)
	defer withConnectorState(t, dataDir, "opencode")()
	connectorFlagConfigHome = home
	cfg.Guardrail.Enabled = true
	cfg.Guardrail.HookFailMode = "closed"

	stdout, stderr, _ := runConnectorCmd(t, "reconcile", "--connector", "opencode", "--json")
	assertConnectorReconcileStderr(t, "opencode", stderr)
	if !strings.Contains(stdout, `"connector":"opencode"`) {
		t.Fatalf("OpenCode reconcile output = %q", stdout)
	}
	pluginPath := filepath.Join(home, "plugins", "defenseclaw.js")
	if _, err := os.Stat(pluginPath); err != nil {
		t.Fatalf("OpenCode plugin missing after reconcile: %v", err)
	}
	backupPath := filepath.Join(dataDir, "connector_backups", "opencode", "config.json")
	if _, err := os.Stat(backupPath); err != nil {
		t.Fatalf("OpenCode custody receipt missing after reconcile: %v", err)
	}
	lock := connector.LoadHookContractLockEntry(dataDir, "opencode")
	if lock.Connector != "opencode" || lock.ContractID != "opencode-hooks-v1" {
		t.Fatalf("OpenCode contract lock = %+v", lock)
	}
	if got := connector.LoadActiveConnector(dataDir); got != "opencode" {
		t.Fatalf("active connector = %q, want opencode", got)
	}
	token, err := connector.LoadHookAPIToken(dataDir, "opencode")
	if err != nil || token == "" {
		t.Fatalf("OpenCode scoped token = %q, %v", token, err)
	}
	current, err := connector.OpenCodeRegistrationCurrent(connector.SetupOpts{
		DataDir:      dataDir,
		APIAddr:      "127.0.0.1:18970",
		APIToken:     token,
		HookFailMode: "closed",
	})
	if err != nil || !current {
		t.Fatalf("OpenCode registration current = %v, %v", current, err)
	}
}

func TestConnectorReconcileOpenCodeRollsBackAllStateWhenActivationPublishFails(t *testing.T) {
	dataDir := testenv.PrivateTempDir(t)
	home := testenv.PrivateTempDir(t)
	defer withConnectorState(t, dataDir, "opencode")()
	connectorFlagConfigHome = home
	cfg.Guardrail.Enabled = true
	cfg.Guardrail.HookFailMode = "closed"

	previousSave := connectorSaveOpenCodeActive
	connectorSaveOpenCodeActive = func(dataDir string, names []string) error {
		if err := previousSave(dataDir, names); err != nil {
			return err
		}
		return errors.New("injected active-state publication failure")
	}
	t.Cleanup(func() { connectorSaveOpenCodeActive = previousSave })

	_, stderr, _ := runConnectorCmd(t, "reconcile", "--connector", "opencode", "--json")
	if !strings.Contains(stderr, "injected active-state publication failure") {
		t.Fatalf("OpenCode reconcile stderr = %q, want injected publication failure", stderr)
	}
	pluginPath := filepath.Join(home, "plugins", "defenseclaw.js")
	if _, err := os.Stat(pluginPath); !os.IsNotExist(err) {
		t.Fatalf("failed reconcile left OpenCode plugin: %v", err)
	}
	backupPath := filepath.Join(dataDir, "connector_backups", "opencode", "config.json")
	if _, err := os.Stat(backupPath); !os.IsNotExist(err) {
		t.Fatalf("failed reconcile left OpenCode custody receipt: %v", err)
	}
	if lock := connector.LoadHookContractLockEntry(dataDir, "opencode"); lock.Connector != "" {
		t.Fatalf("failed reconcile left OpenCode contract lock: %+v", lock)
	}
	if token, err := connector.LoadHookAPIToken(dataDir, "opencode"); err != nil || token != "" {
		t.Fatalf("failed reconcile left OpenCode scoped token = %q, %v", token, err)
	}
	if got := connector.LoadActiveConnector(dataDir); got != "" {
		t.Fatalf("failed reconcile left active connector %q", got)
	}
}

func TestConnectorReconcileOpenCodeRemovesAmbiguouslyPublishedNewToken(t *testing.T) {
	dataDir := testenv.PrivateTempDir(t)
	home := testenv.PrivateTempDir(t)
	defer withConnectorState(t, dataDir, "opencode")()
	connectorFlagConfigHome = home
	cfg.Guardrail.Enabled = true

	previousEnsure := connectorEnsureHookAPIToken
	connectorEnsureHookAPIToken = func(dataDir, name string) (string, error) {
		if _, err := previousEnsure(dataDir, name); err != nil {
			return "", err
		}
		return "", errors.New("injected late token publication failure")
	}
	t.Cleanup(func() { connectorEnsureHookAPIToken = previousEnsure })

	_, stderr, _ := runConnectorCmd(t, "reconcile", "--connector", "opencode", "--json")
	if !strings.Contains(stderr, "injected late token publication failure") {
		t.Fatalf("OpenCode reconcile stderr = %q, want late token failure", stderr)
	}
	if token, err := connector.LoadHookAPIToken(dataDir, "opencode"); err != nil || token != "" {
		t.Fatalf("failed token publication left scoped token = %q, %v", token, err)
	}
	if _, err := os.Stat(filepath.Join(home, "plugins", "defenseclaw.js")); !os.IsNotExist(err) {
		t.Fatalf("token failure reached plugin publication: %v", err)
	}
}

func TestConnectorReconcileOpenCodeRollsBackLateContractLockFailure(t *testing.T) {
	dataDir := testenv.PrivateTempDir(t)
	home := testenv.PrivateTempDir(t)
	defer withConnectorState(t, dataDir, "opencode")()
	connectorFlagConfigHome = home
	cfg.Guardrail.Enabled = true
	cfg.Guardrail.HookFailMode = "closed"

	previousSave := connectorSaveOpenCodeLock
	connectorSaveOpenCodeLock = func(dataDir string, entry connector.HookContractLockEntry) error {
		if err := previousSave(dataDir, entry); err != nil {
			return err
		}
		return errors.New("injected late contract-lock publication failure")
	}
	t.Cleanup(func() { connectorSaveOpenCodeLock = previousSave })

	_, stderr, _ := runConnectorCmd(t, "reconcile", "--connector", "opencode", "--json")
	if !strings.Contains(stderr, "injected late contract-lock publication failure") {
		t.Fatalf("OpenCode reconcile stderr = %q, want late lock failure", stderr)
	}
	if lock := connector.LoadHookContractLockEntry(dataDir, "opencode"); lock.Connector != "" {
		t.Fatalf("late lock failure left OpenCode contract lock: %+v", lock)
	}
	if token, err := connector.LoadHookAPIToken(dataDir, "opencode"); err != nil || token != "" {
		t.Fatalf("late lock failure left scoped token = %q, %v", token, err)
	}
	if got := connector.LoadActiveConnector(dataDir); got != "" {
		t.Fatalf("late lock failure left active connector %q", got)
	}
	for _, path := range []string{
		filepath.Join(home, "plugins", "defenseclaw.js"),
		filepath.Join(dataDir, "connector_backups", "opencode", "config.json"),
	} {
		if _, err := os.Stat(path); !os.IsNotExist(err) {
			t.Fatalf("late lock failure left publication %s: %v", path, err)
		}
	}
}

func TestConnectorReconcileOpenCodeRollbackPreservesExistingRegistration(t *testing.T) {
	dataDir := testenv.PrivateTempDir(t)
	home := testenv.PrivateTempDir(t)
	t.Setenv("OPENCODE_CONFIG_DIR", home)
	defer withConnectorState(t, dataDir, "opencode")()
	connectorFlagConfigHome = home
	cfg.Guardrail.Enabled = true
	cfg.Guardrail.HookFailMode = "open"

	_, stderr, _ := runConnectorCmd(t, "reconcile", "--connector", "opencode", "--json")
	assertConnectorReconcileStderr(t, "opencode", stderr)
	pluginPath := filepath.Join(home, "plugins", "defenseclaw.js")
	backupPath := filepath.Join(dataDir, "connector_backups", "opencode", "config.json")
	pluginBefore, err := os.ReadFile(pluginPath)
	if err != nil {
		t.Fatal(err)
	}
	backupBefore, err := os.ReadFile(backupPath)
	if err != nil {
		t.Fatal(err)
	}
	lockBefore := connector.LoadHookContractLockEntry(dataDir, "opencode")
	tokenBefore, err := connector.LoadHookAPIToken(dataDir, "opencode")
	if err != nil || tokenBefore == "" {
		t.Fatalf("initial scoped token = %q, %v", tokenBefore, err)
	}

	cfg.Guardrail.HookFailMode = "closed"
	previousSave := connectorSaveOpenCodeActive
	connectorSaveOpenCodeActive = func(string, []string) error {
		return errors.New("injected refresh publication failure")
	}
	t.Cleanup(func() { connectorSaveOpenCodeActive = previousSave })
	_, stderr, _ = runConnectorCmd(t, "reconcile", "--connector", "opencode", "--json")
	if !strings.Contains(stderr, "injected refresh publication failure") {
		t.Fatalf("OpenCode refresh stderr = %q, want injected failure", stderr)
	}

	pluginAfter, err := os.ReadFile(pluginPath)
	if err != nil || !bytes.Equal(pluginAfter, pluginBefore) {
		t.Fatalf("plugin was not restored byte-for-byte: equal=%v err=%v", bytes.Equal(pluginAfter, pluginBefore), err)
	}
	backupAfter, err := os.ReadFile(backupPath)
	if err != nil || !bytes.Equal(backupAfter, backupBefore) {
		t.Fatalf("custody receipt was not restored byte-for-byte: equal=%v err=%v", bytes.Equal(backupAfter, backupBefore), err)
	}
	lockAfter := connector.LoadHookContractLockEntry(dataDir, "opencode")
	// Re-publishing the previous entry refreshes only its evidence timestamp;
	// every contract and location field must remain identical.
	lockAfter.UpdatedAt = lockBefore.UpdatedAt
	if !reflect.DeepEqual(lockAfter, lockBefore) {
		t.Fatalf("contract lock was not semantically restored: before=%+v after=%+v", lockBefore, lockAfter)
	}
	if got := connector.LoadActiveConnector(dataDir); got != "opencode" {
		t.Fatalf("active connector after rollback = %q, want opencode", got)
	}
	if tokenAfter, err := connector.LoadHookAPIToken(dataDir, "opencode"); err != nil || tokenAfter != tokenBefore {
		t.Fatalf("scoped token after rollback = %q, %v; want existing token", tokenAfter, err)
	}
	current, err := connector.OpenCodeRegistrationCurrent(connector.SetupOpts{
		DataDir:      dataDir,
		APIAddr:      "127.0.0.1:18970",
		APIToken:     tokenBefore,
		HookFailMode: "open",
	})
	if err != nil || !current {
		t.Fatalf("existing OpenCode registration after rollback = %v, %v", current, err)
	}
}

func TestConnectorReconcileCopilotSupportsOrdinaryPath(t *testing.T) {
	if runtime.GOOS != "windows" {
		t.Skip("native Windows Setup maintenance contract")
	}
	dataDir := testenv.PrivateTempDir(t)
	home := filepath.Join(testenv.PrivateTempDir(t), ".copilot")
	if err := os.MkdirAll(home, 0o700); err != nil {
		t.Fatal(err)
	}
	defer withConnectorState(t, dataDir, "copilot")()
	connectorFlagConfigHome = home
	cfg.Guardrail.Enabled = true
	cfg.Guardrail.Connectors = map[string]config.PerConnectorGuardrailConfig{
		"copilot": {HookFailMode: "open"},
	}

	stdout, stderr, exitCode := runConnectorCmd(t, "reconcile", "--connector", "copilot", "--json")
	if stderr != "" || exitCode != 0 || !strings.Contains(stdout, `"connector":"copilot"`) {
		t.Fatalf("ordinary Copilot reconcile failed: exit=%d stdout=%q stderr=%q", exitCode, stdout, stderr)
	}
	hookConfig := filepath.Join(home, "hooks", "defenseclaw.json")
	if _, err := os.Stat(hookConfig); err != nil {
		t.Fatalf("bound Copilot reconcile did not publish hook config: %v", err)
	}

	_, stderr, exitCode = runConnectorCmd(t, "teardown", "--connector", "copilot")
	if stderr != "" || exitCode != 0 {
		t.Fatalf("Copilot teardown failed: exit=%d stderr=%q", exitCode, stderr)
	}
	_, stderr, exitCode = runConnectorCmd(t, "verify", "--connector", "copilot", "--json")
	if stderr != "" || exitCode != 0 {
		t.Fatalf("Copilot verify failed: exit=%d stderr=%q", exitCode, stderr)
	}
}

func TestConnectorReconcileMixedModesKeepsBothContractsCurrent(t *testing.T) {
	dataDir := testenv.PrivateTempDir(t)
	seedCodexSelectionForTest(t, dataDir)
	home := testenv.PrivateTempDir(t)
	testenv.SetHome(t, home)
	claudePath := filepath.Join(home, ".claude", "settings.json")
	codexPath := filepath.Join(home, ".codex", "config.toml")
	if err := os.MkdirAll(filepath.Dir(claudePath), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Dir(codexPath), 0o700); err != nil {
		t.Fatal(err)
	}
	launcher := filepath.Join(home, ".local", "bin", "defenseclaw-hook.exe")
	if runtime.GOOS == "windows" {
		if err := os.MkdirAll(filepath.Dir(launcher), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(launcher, []byte("MZ-native-hook-fixture"), 0o700); err != nil {
			t.Fatal(err)
		}
	}
	previousClaudePath := connector.ClaudeCodeSettingsPathOverride
	previousCodexPath := connector.CodexConfigPathOverride
	connector.ClaudeCodeSettingsPathOverride = claudePath
	connector.CodexConfigPathOverride = codexPath
	t.Cleanup(func() {
		connector.ClaudeCodeSettingsPathOverride = previousClaudePath
		connector.CodexConfigPathOverride = previousCodexPath
	})
	defer withConnectorState(t, dataDir, "claudecode")()
	cfg.Guardrail.Enabled = true
	cfg.Guardrail.HookFailMode = "open"
	cfg.Guardrail.Connectors = map[string]config.PerConnectorGuardrailConfig{
		"claudecode": {HookFailMode: "open"},
		"codex":      {HookFailMode: "open"},
	}
	for _, name := range []string{"claudecode", "codex"} {
		if _, err := connector.EnsureHookAPIToken(dataDir, name); err != nil {
			t.Fatalf("ensure %s token: %v", name, err)
		}
		_, stderr, _ := runConnectorCmd(t, "reconcile", "--connector", name, "--json")
		assertConnectorReconcileStderr(t, name, stderr)
	}
	initial := assertMixedHookContractsCurrent(t, dataDir, home)
	codexBefore, err := os.ReadFile(codexPath)
	if err != nil {
		t.Fatal(err)
	}
	codexOwnedBefore := initial.Connectors["codex"].HookScriptDigests["codex-hook.sh"]

	claudeMode := cfg.Guardrail.Connectors["claudecode"]
	claudeMode.HookFailMode = "closed"
	cfg.Guardrail.Connectors["claudecode"] = claudeMode
	_, stderr, _ := runConnectorCmd(t, "reconcile", "--connector", "claudecode", "--json")
	assertConnectorReconcileStderr(t, "claudecode", stderr)
	closed := assertMixedHookContractsCurrent(t, dataDir, home)
	if closed.Connectors["claudecode"].HookFailMode != "closed" || closed.Connectors["codex"].HookFailMode != "open" {
		t.Fatalf("mixed lock modes are wrong: Claude=%q Codex=%q", closed.Connectors["claudecode"].HookFailMode, closed.Connectors["codex"].HookFailMode)
	}
	codexAfter, err := os.ReadFile(codexPath)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(codexAfter, codexBefore) || closed.Connectors["codex"].HookScriptDigests["codex-hook.sh"] != codexOwnedBefore {
		t.Fatal("Claude-only reconciliation changed Codex registration or owned contract")
	}

	// Seed the exact legacy failure: every connector claims a different hash
	// for the same shared paths, while disk can match only one.  The normal
	// selected reconcile must render canonical bytes and migrate atomically.
	legacyPath := filepath.Join(dataDir, "hook_contract_lock.json")
	legacyDoc := map[string]interface{}{}
	legacyBody, err := os.ReadFile(legacyPath)
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(legacyBody, &legacyDoc); err != nil {
		t.Fatal(err)
	}
	shared, _ := legacyDoc["shared_hook_script_digests"].(map[string]interface{})
	delete(legacyDoc, "shared_hook_script_digests")
	legacyDoc["version"] = float64(1)
	entries, _ := legacyDoc["connectors"].(map[string]interface{})
	for connectorName, rawEntry := range entries {
		entry, _ := rawEntry.(map[string]interface{})
		digests, _ := entry["hook_script_digests"].(map[string]interface{})
		for artifact, digest := range shared {
			if connectorName == "claudecode" {
				digests[artifact] = "sha256:legacy-claude-divergent"
			} else {
				digests[artifact] = digest
			}
		}
	}
	legacyBody, err = json.MarshalIndent(legacyDoc, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(legacyPath, append(legacyBody, '\n'), 0o600); err != nil {
		t.Fatal(err)
	}
	_, stderr, _ = runConnectorCmd(t, "reconcile", "--connector", "claudecode", "--json")
	assertConnectorReconcileStderr(t, "claudecode", stderr)
	assertMixedHookContractsCurrent(t, dataDir, home)

	// Reverse the mixed state and repeatedly switch one connector.  Every
	// intermediate lock must validate both registrations simultaneously.
	claudeMode = cfg.Guardrail.Connectors["claudecode"]
	claudeMode.HookFailMode = "open"
	cfg.Guardrail.Connectors["claudecode"] = claudeMode
	_, stderr, _ = runConnectorCmd(t, "reconcile", "--connector", "claudecode", "--json")
	assertConnectorReconcileStderr(t, "claudecode", stderr)
	codexMode := cfg.Guardrail.Connectors["codex"]
	codexMode.HookFailMode = "closed"
	cfg.Guardrail.Connectors["codex"] = codexMode
	_, stderr, _ = runConnectorCmd(t, "reconcile", "--connector", "codex", "--json")
	assertConnectorReconcileStderr(t, "codex", stderr)
	reverse := assertMixedHookContractsCurrent(t, dataDir, home)
	if reverse.Connectors["claudecode"].HookFailMode != "open" || reverse.Connectors["codex"].HookFailMode != "closed" {
		t.Fatalf("reverse mixed modes are wrong: %+v", reverse.Connectors)
	}
	for _, mode := range []string{"closed", "open", "closed", "open"} {
		claudeMode = cfg.Guardrail.Connectors["claudecode"]
		claudeMode.HookFailMode = mode
		cfg.Guardrail.Connectors["claudecode"] = claudeMode
		_, stderr, _ = runConnectorCmd(t, "reconcile", "--connector", "claudecode", "--json")
		assertConnectorReconcileStderr(t, "claudecode", stderr)
		assertMixedHookContractsCurrent(t, dataDir, home)
	}
}

func TestResolveActiveConnectorName_FlagWins(t *testing.T) {
	dir := t.TempDir()
	defer withConnectorState(t, dir, "openclaw")()
	connectorFlagName = "Codex"
	if got := resolveActiveConnectorName(dir); got != "codex" {
		t.Fatalf("flag should win and lowercase: got %q", got)
	}
}

func TestResolveActiveConnectorName_StateFileFallback(t *testing.T) {
	dir := testenv.PrivateTempDir(t)
	defer withConnectorState(t, dir, "")()
	if err := connector.SaveActiveConnector(dir, "claudecode"); err != nil {
		t.Fatal(err)
	}
	if got := resolveActiveConnectorName(dir); got != "claudecode" {
		t.Fatalf("state file should be used: got %q", got)
	}
}

func TestResolveActiveConnectorName_GuardrailFallback(t *testing.T) {
	dir := t.TempDir()
	defer withConnectorState(t, dir, "zeptoclaw")()
	if got := resolveActiveConnectorName(dir); got != "zeptoclaw" {
		t.Fatalf("guardrail config should be used: got %q", got)
	}
}

func TestResolveActiveConnectorName_ClawModeFallback(t *testing.T) {
	dir := t.TempDir()
	defer withConnectorState(t, dir, "")()
	cfg.Claw.Mode = "Codex"
	if got := resolveActiveConnectorName(dir); got != "codex" {
		t.Fatalf("claw.mode should be used when guardrail.connector is empty: got %q", got)
	}
}

func TestResolveActiveConnectorName_LegacyDefault(t *testing.T) {
	dir := t.TempDir()
	defer withConnectorState(t, dir, "")()
	cfg.Claw.Mode = ""
	if got := resolveActiveConnectorName(dir); got != "openclaw" {
		t.Fatalf("expected legacy default openclaw: got %q", got)
	}
}

func TestConnectorListBackups_EmptyDir(t *testing.T) {
	dir := t.TempDir()
	defer withConnectorState(t, dir, "openclaw")()
	stdout, _, exitCode := runConnectorCmd(t, "list-backups")
	if exitCode != 0 {
		t.Fatalf("expected exit 0, got %d", exitCode)
	}
	if !strings.Contains(stdout, "no connector backups found") {
		t.Fatalf("expected empty-dir message; got: %s", stdout)
	}
}

func TestConnectorListBackups_FindsAllKnownNames(t *testing.T) {
	dir := t.TempDir()
	defer withConnectorState(t, dir, "openclaw")()

	for _, name := range []string{"zeptoclaw_backup.json", "claudecode_backup.json", "codex_backup.json"} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(`{"a":1}`), 0o600); err != nil {
			t.Fatal(err)
		}
	}

	stdout, _, exitCode := runConnectorCmd(t, "list-backups")
	if exitCode != 0 {
		t.Fatalf("expected exit 0, got %d", exitCode)
	}
	for _, want := range []string{"zeptoclaw", "claudecode", "codex"} {
		if !strings.Contains(stdout, want) {
			t.Fatalf("expected %s in output, got: %s", want, stdout)
		}
	}
}

func TestConnectorListBackups_FindsManagedBackups(t *testing.T) {
	dir := t.TempDir()
	defer withConnectorState(t, dir, "openclaw")()

	for rel, body := range map[string]string{
		filepath.Join("codex", "config.toml.json"):     `{"version":1}`,
		filepath.Join("geminicli", "settings.json"):    `{"connector":"geminicli"}`,
		filepath.Join("copilot", "defenseclaw.json"):   `{"connector":"copilot"}`,
		filepath.Join("cursor", "hooks.json.backup"):   `{"connector":"cursor"}`,
		filepath.Join("windsurf", "hooks.json.backup"): `{"connector":"windsurf"}`,
		filepath.Join("hermes", "config.yaml.managed"): `{"connector":"hermes"}`,
	} {
		path := filepath.Join(dir, "connector_backups", rel)
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}

	stdout, _, exitCode := runConnectorCmd(t, "list-backups")
	if exitCode != 0 {
		t.Fatalf("expected exit 0, got %d", exitCode)
	}
	for _, want := range []string{"codex", "geminicli", "copilot", "cursor", "windsurf", "hermes", "connector_backups"} {
		if !strings.Contains(stdout, want) {
			t.Fatalf("expected %s in managed backup output, got: %s", want, stdout)
		}
	}
}

func TestConnectorListBackups_FindsOpenClawPristine(t *testing.T) {
	dir := t.TempDir()
	clawCfg := filepath.Join(dir, "claw.config.json")
	pristine := clawCfg + ".pristine"
	if err := os.WriteFile(pristine, []byte(`{"x":1}`), 0o600); err != nil {
		t.Fatal(err)
	}

	defer withConnectorState(t, dir, "openclaw")()
	cfg.Claw.ConfigFile = clawCfg

	stdout, _, exitCode := runConnectorCmd(t, "list-backups")
	if exitCode != 0 {
		t.Fatalf("expected exit 0, got %d", exitCode)
	}
	if !strings.Contains(stdout, "openclaw") || !strings.Contains(stdout, ".pristine") {
		t.Fatalf("expected openclaw + .pristine in output, got: %s", stdout)
	}
}

func TestConnectorListBackups_JSONShape(t *testing.T) {
	dir := t.TempDir()
	defer withConnectorState(t, dir, "openclaw")()

	if err := os.WriteFile(filepath.Join(dir, "codex_backup.json"), []byte(`{"a":1}`), 0o600); err != nil {
		t.Fatal(err)
	}

	stdout, _, exitCode := runConnectorCmd(t, "list-backups", "--json")
	if exitCode != 0 {
		t.Fatalf("expected exit 0, got %d", exitCode)
	}
	var payload struct {
		DataDir string `json:"data_dir"`
		Count   int    `json:"count"`
		Backups []struct {
			Connector string `json:"connector"`
			Filename  string `json:"filename"`
			SizeBytes int64  `json:"size_bytes"`
		} `json:"backups"`
	}
	if err := json.Unmarshal([]byte(stdout), &payload); err != nil {
		t.Fatalf("invalid JSON: %v\n%s", err, stdout)
	}
	if payload.Count != 1 || len(payload.Backups) != 1 || payload.Backups[0].Connector != "codex" {
		t.Fatalf("unexpected payload: %+v", payload)
	}
	if payload.Backups[0].SizeBytes <= 0 {
		t.Fatalf("size_bytes should be positive, got %d", payload.Backups[0].SizeBytes)
	}
}

func TestConnectorListBackups_NoDataDir(t *testing.T) {
	defer withConnectorState(t, "", "openclaw")()
	connectorFlagDataDir = ""
	cfg.DataDir = ""

	_, _, exitCode := runConnectorCmd(t, "list-backups")
	if exitCode != 0 {
		// list-backups returns RunE error → cobra prints "Error:" and
		// exits 1; our test harness doesn't run the real os.Exit, so
		// the connectorExit sentinel stays at 0 and the error surfaces
		// via stderr instead.
		t.Fatalf("RunE error path should not call connectorExit; got %d", exitCode)
	}
}

func TestConnectorTeardown_UnknownConnector(t *testing.T) {
	dir := t.TempDir()
	defer withConnectorState(t, dir, "")()
	connectorFlagName = "definitely-not-a-real-connector"

	_, _, exitCode := runConnectorCmd(t, "teardown", "--connector", "definitely-not-a-real-connector")
	// runE returns an error → cobra exit handling, connectorExit
	// untouched. Behavioural assertion: we must not panic and must not
	// exit with a non-zero code via the sentinel.
	if exitCode != 0 {
		t.Fatalf("expected sentinel untouched (RunE error path), got %d", exitCode)
	}
}

func TestConnectorTeardownMarksConnectorInactiveBeforeRemoval(t *testing.T) {
	dir := testenv.PrivateTempDir(t)
	defer withConnectorState(t, dir, "cursor")()

	cfgPath := filepath.Join(testenv.PrivateTempDir(t), "hooks.json")
	previous := connector.CursorHooksPathOverride
	connector.CursorHooksPathOverride = cfgPath
	t.Cleanup(func() { connector.CursorHooksPathOverride = previous })

	conn := connector.NewCursorConnector()
	opts := connector.SetupOpts{DataDir: dir, APIAddr: "127.0.0.1:18970", APIToken: "test-token"}
	if err := conn.Setup(context.Background(), opts); err != nil {
		t.Fatalf("cursor setup: %v", err)
	}
	if err := connector.SaveActiveConnectors(dir, []string{"codex", "cursor"}); err != nil {
		t.Fatalf("save active connectors: %v", err)
	}

	stdout, stderr, exitCode := runConnectorCmd(t, "teardown", "--connector", "cursor")
	if exitCode != 0 || !strings.Contains(stdout, "teardown complete") {
		t.Fatalf("teardown failed: exit=%d stdout=%q stderr=%q", exitCode, stdout, stderr)
	}
	if !connector.ConnectorExplicitlyInactive(dir, "cursor") {
		t.Fatal("cursor was not marked explicitly inactive")
	}
	if got := connector.LoadActiveConnectors(dir); !reflect.DeepEqual(got, []string{"codex"}) {
		t.Fatalf("active connectors after teardown = %v, want [codex]", got)
	}
	if err := conn.VerifyClean(opts); err != nil {
		t.Fatalf("cursor residue after teardown: %v", err)
	}
}

func TestConnectorTeardownFailureRestoresActiveState(t *testing.T) {
	dir := testenv.PrivateTempDir(t)
	defer withConnectorState(t, dir, "cursor")()

	cfgPath := filepath.Join(testenv.PrivateTempDir(t), "hooks.json")
	previous := connector.CursorHooksPathOverride
	connector.CursorHooksPathOverride = cfgPath
	t.Cleanup(func() { connector.CursorHooksPathOverride = previous })

	conn := connector.NewCursorConnector()
	opts := connector.SetupOpts{DataDir: dir, APIAddr: "127.0.0.1:18970", APIToken: "test-token"}
	if err := conn.Setup(context.Background(), opts); err != nil {
		t.Fatalf("cursor setup: %v", err)
	}
	if err := connector.SaveActiveConnector(dir, "cursor"); err != nil {
		t.Fatalf("save active connector: %v", err)
	}
	backup := filepath.Join(dir, "connector_backups", "cursor", "config.json")
	if err := os.WriteFile(backup, []byte("not-json"), 0o600); err != nil {
		t.Fatalf("corrupt managed backup: %v", err)
	}

	_, stderr, _ := runConnectorCmd(t, "teardown", "--connector", "cursor")
	if !strings.Contains(stderr, "restore config backup") {
		t.Fatalf("teardown did not surface backup failure: %q", stderr)
	}
	if connector.ConnectorExplicitlyInactive(dir, "cursor") {
		t.Fatal("failed teardown left cursor explicitly inactive")
	}
	if got := connector.LoadActiveConnectors(dir); !reflect.DeepEqual(got, []string{"cursor"}) {
		t.Fatalf("active state after failed teardown = %v, want [cursor]", got)
	}
}

func TestConnectorVerify_UnknownConnector_Exit2(t *testing.T) {
	dir := t.TempDir()
	defer withConnectorState(t, dir, "")()
	_, stderr, exitCode := runConnectorCmd(t, "verify", "--connector", "ghostclaw")
	if exitCode != 2 {
		t.Fatalf("expected exit 2 for unknown connector, got %d (stderr=%q)", exitCode, stderr)
	}
	if !strings.Contains(stderr, "ghostclaw") {
		t.Fatalf("expected ghostclaw in stderr; got %q", stderr)
	}
}

func TestConnectorVerify_CleanOpenClaw(t *testing.T) {
	dir := t.TempDir()
	defer withConnectorState(t, dir, "openclaw")()

	// OpenClaw inspects $HOME/.openclaw via openClawHome(). Override it
	// to a fresh temp dir that contains no defenseclaw artifacts, so
	// VerifyClean can report a clean state regardless of the developer's
	// real ~/.openclaw on the host running this test.
	prev := connector.OpenClawHomeOverride
	connector.OpenClawHomeOverride = filepath.Join(dir, "openclaw-home")
	if err := os.MkdirAll(connector.OpenClawHomeOverride, 0o755); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { connector.OpenClawHomeOverride = prev })

	stdout, stderr, exitCode := runConnectorCmd(t, "verify", "--connector", "openclaw")
	if exitCode != 0 {
		t.Fatalf("expected exit 0 (clean), got %d (stdout=%q stderr=%q)", exitCode, stdout, stderr)
	}
	if !strings.Contains(stdout, "no residual DefenseClaw state") {
		t.Fatalf("expected clean verdict in stdout; got %q", stdout)
	}
}

// TestConnectorVerify_CleanPerConnector — plan E1 / item 4. Cover
// the verify path for the three non-OpenClaw connectors. Each one
// uses a different config-path override (ZeptoClawConfigPathOverride,
// ClaudeCodeSettingsPathOverride, CodexConfigPathOverride) so a single
// shared helper can't take their place — we walk them as t.Run subtests
// and document which override redirects which on-disk artifact.
//
// The CLI's verify command is connector-agnostic; this test proves the
// plumbing works end-to-end for each connector in the registry, not
// just OpenClaw.
func TestConnectorVerify_CleanPerConnector(t *testing.T) {
	cases := []struct {
		connector string
		// applyOverride redirects the connector's host config path to
		// a fresh tmp file that does NOT exist. VerifyClean tolerates
		// a missing config (os.ReadFile errors are swallowed) so the
		// "clean" assertion holds without needing to seed a pristine
		// host config on every CI box.
		applyOverride func(t *testing.T, tmpHome string)
	}{
		{
			connector: "zeptoclaw",
			applyOverride: func(t *testing.T, tmpHome string) {
				prev := connector.ZeptoClawConfigPathOverride
				connector.ZeptoClawConfigPathOverride = filepath.Join(tmpHome, ".zeptoclaw", "config.json")
				t.Cleanup(func() { connector.ZeptoClawConfigPathOverride = prev })
			},
		},
		{
			connector: "claudecode",
			applyOverride: func(t *testing.T, tmpHome string) {
				prev := connector.ClaudeCodeSettingsPathOverride
				connector.ClaudeCodeSettingsPathOverride = filepath.Join(tmpHome, ".claude", "settings.json")
				t.Cleanup(func() { connector.ClaudeCodeSettingsPathOverride = prev })
			},
		},
		{
			connector: "codex",
			applyOverride: func(t *testing.T, tmpHome string) {
				prev := connector.CodexConfigPathOverride
				connector.CodexConfigPathOverride = filepath.Join(tmpHome, ".codex", "config.toml")
				t.Cleanup(func() { connector.CodexConfigPathOverride = prev })
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.connector, func(t *testing.T) {
			dir := t.TempDir()
			defer withConnectorState(t, dir, tc.connector)()

			tmpHome := t.TempDir()
			tc.applyOverride(t, tmpHome)

			stdout, stderr, exitCode := runConnectorCmd(t,
				"verify", "--connector", tc.connector)
			if exitCode != 0 {
				t.Fatalf("connector=%s: expected exit 0 (clean), got %d (stdout=%q stderr=%q)",
					tc.connector, exitCode, stdout, stderr)
			}
			if !strings.Contains(stdout, "no residual DefenseClaw state") {
				t.Fatalf("connector=%s: expected clean verdict in stdout; got %q",
					tc.connector, stdout)
			}
		})
	}
}

// TestConnectorVerify_JSONCleanPerConnector — plan E1 / item 4.
// JSON-output parity for the verify path across the non-OpenClaw
// connectors. Each subtest asserts the exact JSON shape so downstream
// scripts (the install lifecycle smoke matrix in C5, the e2e shell
// suite in E4) can pivot on `connector` and `clean` without per-name
// branching.
func TestConnectorVerify_JSONCleanPerConnector(t *testing.T) {
	cases := []struct {
		connector     string
		applyOverride func(t *testing.T, tmpHome string)
	}{
		{
			connector: "zeptoclaw",
			applyOverride: func(t *testing.T, tmpHome string) {
				prev := connector.ZeptoClawConfigPathOverride
				connector.ZeptoClawConfigPathOverride = filepath.Join(tmpHome, ".zeptoclaw", "config.json")
				t.Cleanup(func() { connector.ZeptoClawConfigPathOverride = prev })
			},
		},
		{
			connector: "claudecode",
			applyOverride: func(t *testing.T, tmpHome string) {
				prev := connector.ClaudeCodeSettingsPathOverride
				connector.ClaudeCodeSettingsPathOverride = filepath.Join(tmpHome, ".claude", "settings.json")
				t.Cleanup(func() { connector.ClaudeCodeSettingsPathOverride = prev })
			},
		},
		{
			connector: "codex",
			applyOverride: func(t *testing.T, tmpHome string) {
				prev := connector.CodexConfigPathOverride
				connector.CodexConfigPathOverride = filepath.Join(tmpHome, ".codex", "config.toml")
				t.Cleanup(func() { connector.CodexConfigPathOverride = prev })
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.connector, func(t *testing.T) {
			dir := t.TempDir()
			defer withConnectorState(t, dir, tc.connector)()

			tmpHome := t.TempDir()
			tc.applyOverride(t, tmpHome)

			stdout, _, exitCode := runConnectorCmd(t,
				"verify", "--connector", tc.connector, "--json")
			if exitCode != 0 {
				t.Fatalf("connector=%s: expected exit 0, got %d", tc.connector, exitCode)
			}
			var payload struct {
				Connector string `json:"connector"`
				Action    string `json:"action"`
				Clean     bool   `json:"clean"`
			}
			if err := json.Unmarshal([]byte(stdout), &payload); err != nil {
				t.Fatalf("connector=%s: invalid JSON: %v\n%s", tc.connector, err, stdout)
			}
			if payload.Connector != tc.connector || payload.Action != "verify" || !payload.Clean {
				t.Fatalf("connector=%s: unexpected payload: %+v", tc.connector, payload)
			}
		})
	}
}

func TestConnectorVerify_JSONClean(t *testing.T) {
	dir := t.TempDir()
	defer withConnectorState(t, dir, "openclaw")()

	prev := connector.OpenClawHomeOverride
	connector.OpenClawHomeOverride = filepath.Join(dir, "openclaw-home")
	if err := os.MkdirAll(connector.OpenClawHomeOverride, 0o755); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { connector.OpenClawHomeOverride = prev })

	stdout, _, exitCode := runConnectorCmd(t, "verify", "--connector", "openclaw", "--json")
	if exitCode != 0 {
		t.Fatalf("expected exit 0, got %d", exitCode)
	}
	var payload struct {
		Connector string `json:"connector"`
		Action    string `json:"action"`
		Clean     bool   `json:"clean"`
	}
	if err := json.Unmarshal([]byte(stdout), &payload); err != nil {
		t.Fatalf("invalid JSON: %v\n%s", err, stdout)
	}
	if payload.Connector != "openclaw" || payload.Action != "verify" || !payload.Clean {
		t.Fatalf("unexpected payload: %+v", payload)
	}
}

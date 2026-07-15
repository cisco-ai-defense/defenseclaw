// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"
	"testing"
	"time"

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

	return func() {
		cfg = origCfg
		connectorFlagName = origName
		connectorFlagJSON = origJSON
		connectorFlagDataDir = origDir
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

	for _, candidate := range []string{"--connector", "--data-dir"} {
		for i, a := range tail {
			if a == candidate && i+1 < len(tail) {
				switch candidate {
				case "--connector":
					connectorFlagName = tail[i+1]
				case "--data-dir":
					connectorFlagDataDir = tail[i+1]
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

func TestConnectorReconcileRefreshesOnlySelectedRegistration(t *testing.T) {
	dataDir := testenv.PrivateTempDir(t)
	seedCodexSelectionForTest(t, dataDir)
	home := t.TempDir()
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
	cfg.Guardrail.Enabled = true
	cfg.Guardrail.HookFailMode = "open"
	cfg.Guardrail.Connectors = map[string]config.PerConnectorGuardrailConfig{
		"codex":      {HookFailMode: "closed"},
		"claudecode": {HookFailMode: "open"},
	}
	stdout, stderr, _ := runConnectorCmd(t, "reconcile", "--connector", "codex", "--json")
	if stderr != "" {
		t.Fatalf("reconcile stderr: %s", stderr)
	}
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

func TestConnectorReconcileMixedModesKeepsBothContractsCurrent(t *testing.T) {
	dataDir := testenv.PrivateTempDir(t)
	seedCodexSelectionForTest(t, dataDir)
	home := t.TempDir()
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
		if stderr != "" {
			t.Fatalf("initial %s reconcile: %s", name, stderr)
		}
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
	if stderr != "" {
		t.Fatalf("Claude close reconcile: %s", stderr)
	}
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
	if stderr != "" {
		t.Fatalf("legacy migration reconcile: %s", stderr)
	}
	assertMixedHookContractsCurrent(t, dataDir, home)

	// Reverse the mixed state and repeatedly switch one connector.  Every
	// intermediate lock must validate both registrations simultaneously.
	claudeMode = cfg.Guardrail.Connectors["claudecode"]
	claudeMode.HookFailMode = "open"
	cfg.Guardrail.Connectors["claudecode"] = claudeMode
	_, stderr, _ = runConnectorCmd(t, "reconcile", "--connector", "claudecode", "--json")
	if stderr != "" {
		t.Fatalf("Claude reopen reconcile: %s", stderr)
	}
	codexMode := cfg.Guardrail.Connectors["codex"]
	codexMode.HookFailMode = "closed"
	cfg.Guardrail.Connectors["codex"] = codexMode
	_, stderr, _ = runConnectorCmd(t, "reconcile", "--connector", "codex", "--json")
	if stderr != "" {
		t.Fatalf("Codex close reconcile: %s", stderr)
	}
	reverse := assertMixedHookContractsCurrent(t, dataDir, home)
	if reverse.Connectors["claudecode"].HookFailMode != "open" || reverse.Connectors["codex"].HookFailMode != "closed" {
		t.Fatalf("reverse mixed modes are wrong: %+v", reverse.Connectors)
	}
	for _, mode := range []string{"closed", "open", "closed", "open"} {
		claudeMode = cfg.Guardrail.Connectors["claudecode"]
		claudeMode.HookFailMode = mode
		cfg.Guardrail.Connectors["claudecode"] = claudeMode
		_, stderr, _ = runConnectorCmd(t, "reconcile", "--connector", "claudecode", "--json")
		if stderr != "" {
			t.Fatalf("repeated Claude %s reconcile: %s", mode, stderr)
		}
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
	dir := t.TempDir()
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
	dir := t.TempDir()
	defer withConnectorState(t, dir, "cursor")()

	cfgPath := filepath.Join(t.TempDir(), "hooks.json")
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
	dir := t.TempDir()
	defer withConnectorState(t, dir, "cursor")()

	cfgPath := filepath.Join(t.TempDir(), "hooks.json")
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

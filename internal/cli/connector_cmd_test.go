// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/spf13/cobra"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/gateway/connector"
)

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
	default:
		t.Fatalf("unknown subcommand for harness: %s", sub)
	}
	if err != nil {
		fmt.Fprintln(&errb, err.Error())
	}
	return out.String(), errb.String(), exitCode
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

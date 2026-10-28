// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/spf13/cobra"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/gateway/connector"
	"github.com/defenseclaw/defenseclaw/internal/testenv"
)

// reconcileEveryFixture is a data dir with Claude Code and Codex configured
// in a private home, and the hook launcher a Windows install has.
func reconcileEveryFixture(t *testing.T) (dataDir, claudePath, codexPath string) {
	t.Helper()
	dataDir = testenv.PrivateTempDir(t)
	seedCodexSelectionForTest(t, dataDir)
	home := testenv.PrivateTempDir(t)
	testenv.SetHome(t, home)
	claudePath = filepath.Join(home, ".claude", "settings.json")
	codexPath = filepath.Join(home, ".codex", "config.toml")
	for _, dir := range []string{filepath.Dir(claudePath), filepath.Dir(codexPath)} {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	if runtime.GOOS == "windows" {
		launcher := filepath.Join(home, ".local", "bin", "defenseclaw-hook.exe")
		if err := os.MkdirAll(filepath.Dir(launcher), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(launcher, []byte("MZ-native-hook-fixture"), 0o700); err != nil {
			t.Fatal(err)
		}
	}
	previousClaude, previousCodex := connector.ClaudeCodeSettingsPathOverride, connector.CodexConfigPathOverride
	previousKiro := connector.KiroHomeOverride
	connector.ClaudeCodeSettingsPathOverride = claudePath
	connector.CodexConfigPathOverride = codexPath
	connector.KiroHomeOverride = filepath.Join(home, "kiro")
	previousEvery, previousReadBack := connectorReconcileEvery, connectorReconcileReadBack
	t.Cleanup(func() {
		connector.ClaudeCodeSettingsPathOverride = previousClaude
		connector.CodexConfigPathOverride = previousCodex
		connector.KiroHomeOverride = previousKiro
		connectorReconcileEvery = previousEvery
		connectorReconcileReadBack = previousReadBack
	})
	t.Cleanup(withConnectorState(t, dataDir, ""))
	cfg.Guardrail.Enabled = true
	cfg.Guardrail.HookFailMode = "closed"
	off := false
	cfg.Guardrail.Connectors = map[string]config.PerConnectorGuardrailConfig{
		"claudecode": {},
		"codex":      {},
		"cursor":     {Enabled: &off},
	}
	connectorReconcileEvery = true
	return dataDir, claudePath, codexPath
}

func runReconcileEvery(t *testing.T) (stdout, stderr string, err error) {
	t.Helper()
	var out, errb strings.Builder
	cmd := &cobra.Command{Use: "reconcile"}
	cmd.SetOut(&out)
	cmd.SetErr(&errb)
	err = runConnectorReconcile(cmd, nil)
	return out.String(), errb.String(), err
}

func TestConnectorReconcileEveryPutsEachGuardedConnectorOnItsCurrentHook(t *testing.T) {
	// An upgrade of a stopped gateway does not start it, so it rendered no
	// hook of this release and exited 0 (a 1.0.3 Hermes hook cannot answer
	// this release's execution probe). --every-connector refreshes every
	// guarded connector and reads each back; one turned off is left alone.
	dataDir, claudePath, codexPath := reconcileEveryFixture(t)

	stdout, stderr, err := runReconcileEvery(t)
	if err != nil {
		t.Fatalf("reconcile --every-connector: %v\nstderr: %s", err, stderr)
	}
	for _, name := range []string{"claudecode", "codex"} {
		if !strings.Contains(stdout, name+" is on its current hook") {
			t.Fatalf("stdout does not report %s on its current hook:\n%s", name, stdout)
		}
		if lock := connector.LoadHookContractLockEntry(dataDir, name); lock.Connector != name || lock.HookFailMode != "closed" {
			// The lock records the per-user outage mode: the fixture's
			// saved hook_fail_mode closed wins over the tier (owner
			// decision 2026-10-23).
			t.Fatalf("%s lock = %+v, want an entry of this release with the saved outage mode closed", name, lock)
		}
	}
	if strings.Contains(stdout, "cursor") {
		t.Fatalf("a connector turned off was reconciled:\n%s", stdout)
	}
	for _, path := range []string{claudePath, codexPath} {
		if _, err := os.Stat(path); err != nil {
			t.Fatalf("registration %s missing: %v", path, err)
		}
	}
	registry := connector.NewDefaultRegistry()
	for _, name := range []string{"claudecode", "codex"} {
		conn, _ := registry.Get(name)
		present, err := connector.OwnedHooksPresent(conn, reconcileConnectorOpts(dataDir, name))
		if err != nil || !present {
			t.Fatalf("%s registration after reconcile: present=%v err=%v", name, present, err)
		}
	}
}

func TestConnectorReconcileEveryNamesEachConnectorNotOnItsCurrentHook(t *testing.T) {
	// A connector whose hook does not answer after the refresh (the Hermes
	// execution probe), and one this build does not ship, are each named with
	// the cause and the command exits 3; the connectors after a failure are
	// still done.
	_, _, _ = reconcileEveryFixture(t)
	cfg.Guardrail.Connectors["acme"] = config.PerConnectorGuardrailConfig{}
	connectorReconcileReadBack = func(conn connector.Connector, opts connector.SetupOpts) (bool, error) {
		if conn.Name() == "claudecode" {
			return false, nil
		}
		return connector.OwnedHooksPresent(conn, opts)
	}

	stdout, _, err := runReconcileEvery(t)
	if err == nil {
		t.Fatalf("reconcile --every-connector exited 0 with connectors not on their hooks:\n%s", stdout)
	}
	if code := commandExitCode(err); code != gatewayStartAdmissionRefusedExitCode {
		t.Fatalf("exit code = %d, want %d (%v)", code, gatewayStartAdmissionRefusedExitCode, err)
	}
	message := err.Error()
	for _, want := range []string{
		"not every connector is on its current hook",
		"claudecode: its current hook is not in place",
		"acme: this DefenseClaw build does not ship it",
	} {
		if !strings.Contains(message, want) {
			t.Fatalf("error %q does not contain %q", message, want)
		}
	}
	if strings.Contains(message, "codex:") || !strings.Contains(stdout, "codex is on its current hook") {
		t.Fatalf("codex, after the failed claudecode, was not reconciled: err=%q stdout=%s", message, stdout)
	}
}

func TestConnectorReconcileEveryWithTheGuardrailOffChangesNothing(t *testing.T) {
	dataDir, claudePath, codexPath := reconcileEveryFixture(t)
	cfg.Guardrail.Enabled = false

	stdout, stderr, err := runReconcileEvery(t)
	if err != nil || stdout != "" || stderr != "" {
		t.Fatalf("guardrail off: err=%v stdout=%q stderr=%q", err, stdout, stderr)
	}
	for _, path := range []string{claudePath, codexPath, filepath.Join(dataDir, "hook_contract_lock.json")} {
		if _, err := os.Stat(path); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("%s was written with the guardrail off (%v)", path, err)
		}
	}
}

func TestConnectorReconcileEveryTakesNoConnectorOrJSON(t *testing.T) {
	_, _, _ = reconcileEveryFixture(t)
	for _, set := range []func(){
		func() { connectorFlagName = "codex" },
		func() { connectorFlagJSON = true },
	} {
		connectorFlagName, connectorFlagJSON = "", false
		set()
		if _, _, err := runReconcileEvery(t); err == nil || !strings.Contains(err.Error(), "takes neither --connector nor --json") {
			t.Fatalf("err = %v, want the flag refusal", err)
		}
	}
}

// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/config"
)

func stubRootRuntimeLeftovers(t *testing.T, names ...string) {
	t.Helper()
	old := rootRuntimeLeftovers
	t.Cleanup(func() { rootRuntimeLeftovers = old })
	rootRuntimeLeftovers = func(string) []string { return names }
}

// GAP-0788: a start or restart over root-owned runtime files from a stopped
// sudo-run gateway names the files and the repair chain, not the daemon's raw
// protected-state error, and does so before anything is launched or stopped.
func TestRootOwnedRuntimeLeftoversRefuseStartAndRestartWithTheChain(t *testing.T) {
	home := t.TempDir()
	store := filepath.Join(t.TempDir(), "store")
	t.Setenv("DEFENSECLAW_HOME", home)
	cfg := config.DefaultConfig()
	cfg.DataDir = store
	stubRootRuntimeLeftovers(t, "hook_contract_lock.json", "active_connector.json")

	for _, verb := range []string{"start", "restart"} {
		err := rootOwnedRuntimeLeftoversRefusal(cfg, verb)
		if err == nil {
			t.Fatalf("%s over root-owned files was allowed", verb)
		}
		text := err.Error()
		for _, want := range []string{
			"cannot " + verb + " the gateway",
			filepath.Join(store, "hook_contract_lock.json"),
			filepath.Join(store, "active_connector.json"),
			"stop the gateway if it runs as root, give its files back to this account and start it as yourself: ",
			`sudo chown -R "$(id -un)" `,
		} {
			if !strings.Contains(text, want) {
				t.Errorf("%s error lacks %q: %s", verb, want, text)
			}
		}
		if strings.Contains(text, "protected state is unsafe") {
			t.Errorf("%s error repeats the raw protected-state text: %s", verb, text)
		}
	}
}

// The benign twin, and the installs that keep their own trust model.
func TestRootOwnedRuntimeLeftoversRefusalLeavesOrdinaryStartsAlone(t *testing.T) {
	t.Setenv("DEFENSECLAW_HOME", t.TempDir())
	cfg := config.DefaultConfig()
	cfg.DataDir = t.TempDir()

	stubRootRuntimeLeftovers(t)
	if err := rootOwnedRuntimeLeftoversRefusal(cfg, "start"); err != nil {
		t.Fatalf("a clean data directory was refused: %v", err)
	}

	stubRootRuntimeLeftovers(t, "active_connector.json")
	managedCfg := config.DefaultConfig()
	managedCfg.DataDir = cfg.DataDir
	managedCfg.DeploymentMode = "managed_enterprise"
	if err := rootOwnedRuntimeLeftoversRefusal(managedCfg, "start"); err != nil {
		t.Fatalf("a managed install lost its own guidance: %v", err)
	}
	if err := rootOwnedRuntimeLeftoversRefusal(nil, "start"); err != nil {
		t.Fatalf("a nil config was refused: %v", err)
	}
}

// Start must consult the check before it launches anything.
func TestRunStartRefusesRootOwnedLeftoversBeforeLaunching(t *testing.T) {
	home := t.TempDir()
	t.Setenv("DEFENSECLAW_HOME", home)
	if err := os.WriteFile(filepath.Join(home, "config.yaml"), []byte("config_version: 8\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	stubRootRuntimeLeftovers(t, "application_protection_state.json")
	err := runStartLocked(startCmd, nil, false)
	if err == nil || !strings.Contains(err.Error(), "application_protection_state.json") ||
		!strings.Contains(err.Error(), `sudo chown -R "$(id -un)" `) {
		t.Fatalf("start over root-owned files = %v", err)
	}
}

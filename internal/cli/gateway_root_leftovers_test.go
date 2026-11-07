// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/config"
)

// rootStartBlockersSeen is what the stubbed blockers lookup was asked.
type rootStartBlockersSeen struct {
	discovery   bool
	installHome string
	loose       []string
}

// stubRootRuntimeLeftovers stands in for the root-owned state it cannot create
// as an ordinary user, and records what the refusal asked about.
func stubRootRuntimeLeftovers(t *testing.T, names ...string) *rootStartBlockersSeen {
	t.Helper()
	seen := &rootStartBlockersSeen{}
	old := rootRuntimeStartBlockers
	t.Cleanup(func() { rootRuntimeStartBlockers = old })
	rootRuntimeStartBlockers = func(_, installHome string, discovery bool) ([]string, []string) {
		seen.discovery, seen.installHome = discovery, installHome
		return names, seen.loose
	}
	return seen
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

// The gateway reads the AI discovery state only when discovery is enabled, so
// the refusal passes the configured flag; the install home is where the PID
// records are validated.
func TestRootOwnedRuntimeLeftoversRefusalAsksAboutTheConfiguredDiscoveryAndHome(t *testing.T) {
	home := t.TempDir()
	t.Setenv("DEFENSECLAW_HOME", home)
	cfg := config.DefaultConfig()
	cfg.DataDir = t.TempDir()
	seen := stubRootRuntimeLeftovers(t, "gateway.pid")
	for _, enabled := range []bool{false, true} {
		cfg.AIDiscovery.Enabled = enabled
		if err := rootOwnedRuntimeLeftoversRefusal(cfg, "start"); err == nil {
			t.Fatal("a root-owned PID record was allowed")
		}
		if seen.discovery != enabled || seen.installHome != config.DefaultDataPath() {
			t.Fatalf("asked discovery=%v home=%q, want discovery=%v home=%q", seen.discovery, seen.installHome, enabled, config.DefaultDataPath())
		}
	}
}

// A file the gateway refuses for its group or other access is repaired by the
// chain, not only by the owner change.
func TestRootOwnedRuntimeLeftoversRefusalChainTakesAwayLooseAccess(t *testing.T) {
	t.Setenv("DEFENSECLAW_HOME", t.TempDir())
	cfg := config.DefaultConfig()
	cfg.DataDir = t.TempDir()
	seen := stubRootRuntimeLeftovers(t, "active_connector.json")
	seen.loose = []string{filepath.Join(cfg.DataDir, "active_connector.json")}
	err := rootOwnedRuntimeLeftoversRefusal(cfg, "start")
	if err == nil || !strings.Contains(err.Error(), " && chmod go-rwx ") || !strings.HasSuffix(err.Error(), " && defenseclaw-gateway start") {
		t.Fatalf("refusal = %v", err)
	}
}

// A root-owned PID record fails the identity check that runs before the
// config is read; the refusal still happens, with the chain in place of the
// raw identity text. An identity error with no root-owned cause is unchanged.
func TestRefuseOverRootOwnedStateReplacesOnlyARootOwnedCause(t *testing.T) {
	t.Setenv("DEFENSECLAW_HOME", t.TempDir())
	identityErr := errors.New("gateway PID record is unsafe")

	stubRootRuntimeLeftovers(t, "gateway.pid")
	for _, verb := range []string{"start", "restart"} {
		err := refuseOverRootOwnedState(startCmd, verb, identityErr)
		if err == nil || errors.Is(err, identityErr) || !strings.Contains(err.Error(), "cannot "+verb+" the gateway") ||
			!strings.Contains(err.Error(), "gateway.pid") || !strings.Contains(err.Error(), `sudo chown -R "$(id -un)" `) {
			t.Fatalf("%s identity refusal over a root-owned record = %v", verb, err)
		}
	}

	stubRootRuntimeLeftovers(t)
	if err := refuseOverRootOwnedState(startCmd, "start", identityErr); !errors.Is(err, identityErr) {
		t.Fatalf("an identity error with no root-owned cause was replaced: %v", err)
	}
}

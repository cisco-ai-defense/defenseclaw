// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/daemon"
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

// pidIdentityError is the real start preflight failing on a malformed PID
// record, the way the account sees it. The record stays account-owned: the
// root-owned state is stubbed separately.
func pidIdentityError(t *testing.T, record string) error {
	t.Helper()
	home := t.TempDir()
	t.Setenv("DEFENSECLAW_HOME", home)
	if err := os.WriteFile(filepath.Join(home, record), []byte("invalid\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	err := daemon.New(home).ValidateStartIdentityFiles()
	if failed, unreadable := daemon.FailedPIDRecord(err); err == nil || failed != record || unreadable {
		t.Fatalf("identity preflight for %s = %v (record %q unreadable %v)", record, err, failed, unreadable)
	}
	return err
}

// unreadablePIDIdentityError is the real start preflight failing on a PID
// record this account may not read, the failure a root-owned 0600 record gives.
// The record is made unreadable by its mode, since the test cannot create a
// root-owned file, so it is account-owned and the daemon rightly does not
// attribute the refusal to root: asRootDenied stands in for the owner.
func unreadablePIDIdentityError(t *testing.T, record string) error {
	t.Helper()
	if runtime.GOOS == "windows" || os.Geteuid() == 0 {
		t.Skip("a mode cannot make a file unreadable here")
	}
	home := t.TempDir()
	t.Setenv("DEFENSECLAW_HOME", home)
	if err := os.WriteFile(filepath.Join(home, record), []byte("1\n"), 0o000); err != nil {
		t.Fatal(err)
	}
	err := daemon.New(home).ValidateStartIdentityFiles()
	if failed, rootDenied := daemon.FailedPIDRecord(err); err == nil || failed != record || rootDenied {
		t.Fatalf("identity preflight for unreadable %s = %v (record %q root-denied %v)", record, err, failed, rootDenied)
	}
	return err
}

// asRootDenied makes the refusal count as root, as it is when root owns the
// record (the daemon tests pin that classification with the owner stubbed).
func asRootDenied(t *testing.T) {
	t.Helper()
	old := failedPIDRecord
	t.Cleanup(func() { failedPIDRecord = old })
	failedPIDRecord = func(err error) (string, bool) {
		record, _ := daemon.FailedPIDRecord(err)
		return record, record != ""
	}
}

// A root-owned PID record fails the identity check that runs before the
// config is read; the refusal still happens, with the chain in place of the
// raw identity text. An identity error with no root-owned cause is unchanged.
func TestRefuseOverRootOwnedStateReplacesOnlyARootOwnedCause(t *testing.T) {
	for _, record := range []string{"gateway.pid", "watchdog.pid"} {
		identityErr := unreadablePIDIdentityError(t, record)
		asRootDenied(t)
		stubRootRuntimeLeftovers(t, record)
		for _, verb := range []string{"start", "restart"} {
			err := refuseOverRootOwnedState(startCmd, verb, identityErr)
			if err == nil || errors.Is(err, identityErr) || !strings.Contains(err.Error(), "cannot "+verb+" the gateway") ||
				!strings.Contains(err.Error(), record) || !strings.Contains(err.Error(), `sudo chown -R "$(id -un)" `) {
				t.Fatalf("%s identity refusal over a root-owned %s = %v", verb, record, err)
			}
		}

		stubRootRuntimeLeftovers(t)
		if err := refuseOverRootOwnedState(startCmd, "start", identityErr); !errors.Is(err, identityErr) {
			t.Fatalf("an identity error with no root-owned cause was replaced: %v", err)
		}
	}
}

// An account-owned PID record can be malformed while another runtime file, or
// the other PID record, is root-owned. Returning the ownership does not make
// the malformed record valid, so the identity error and its guidance stay first
// and the root-owned report follows (GAP-0788 reviews 2 and 3).
func TestRefuseOverRootOwnedStateKeepsAnIndependentPIDCause(t *testing.T) {
	cases := []struct{ name, malformed, rootOwned string }{
		{"other_runtime_file", "gateway.pid", "active_connector.json"},
		{"malformed_gateway_root_watchdog", "gateway.pid", "watchdog.pid"},
		{"malformed_watchdog_root_gateway", "watchdog.pid", "gateway.pid"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			identityErr := pidIdentityError(t, tc.malformed)
			stubRootRuntimeLeftovers(t, tc.rootOwned)
			for _, verb := range []string{"start", "restart"} {
				err := refuseOverRootOwnedState(startCmd, verb, identityErr)
				if err == nil || !errors.Is(err, identityErr) {
					t.Fatalf("%s: the PID reason was lost: %v", verb, err)
				}
				for _, want := range []string{tc.rootOwned, `sudo chown -R "$(id -un)" `, "cannot " + verb + " the gateway"} {
					if !strings.Contains(err.Error(), want) {
						t.Errorf("%s: mixed refusal lacks %q: %v", verb, want, err)
					}
				}
				if strings.Index(err.Error(), identityErr.Error()) > strings.Index(err.Error(), tc.rootOwned) {
					t.Errorf("%s: the PID reason does not come first: %v", verb, err)
				}
			}
		})
	}
}

// A root-owned PID record (or a root-owned install home) that the account can
// read can still be malformed. Returning the ownership leaves it malformed and
// the next start fails again, so its own reason stays first and the chain
// follows (GAP-0788 review 4). The benign twin is the unreadable record above,
// where the chain does replace the identity text.
func TestRefuseOverRootOwnedStateKeepsAMalformedRecordThatIsItselfRootOwned(t *testing.T) {
	for _, record := range []string{"gateway.pid", "watchdog.pid"} {
		for _, blocker := range []string{record, "./"} {
			t.Run(record+"_"+strings.TrimSuffix(blocker, "/"), func(t *testing.T) {
				identityErr := pidIdentityError(t, record)
				stubRootRuntimeLeftovers(t, blocker)
				for _, verb := range []string{"start", "restart"} {
					err := refuseOverRootOwnedState(startCmd, verb, identityErr)
					if err == nil || !errors.Is(err, identityErr) ||
						!strings.Contains(err.Error(), "cannot "+verb+" the gateway") ||
						!strings.Contains(err.Error(), `sudo chown -R "$(id -un)" `) {
						t.Fatalf("%s: the malformed record reason or the chain is missing: %v", verb, err)
					}
					if strings.Index(err.Error(), identityErr.Error()) > strings.Index(err.Error(), "cannot "+verb) {
						t.Errorf("%s: the malformed record reason does not come first: %v", verb, err)
					}
				}
			})
		}
	}
}

// A root-owned install home the account cannot enter hides its PID records, so
// the store entry is the PID cause only when the store is the install home.
func TestRootOwnedStartRefusalAttributesAHiddenStoreToThePIDCheckOnlyInTheInstallHome(t *testing.T) {
	home := t.TempDir()
	t.Setenv("DEFENSECLAW_HOME", home)
	stubRootRuntimeLeftovers(t, "./")
	cfg := config.DefaultConfig()

	cfg.DataDir = config.DefaultDataPath()
	if pidBlockers, refusal := rootOwnedStartRefusal(cfg, "start"); refusal == nil || !slices.Contains(pidBlockers, daemon.StoreDirEntry) {
		t.Fatalf("hidden install home: refusal=%v pidBlockers=%v", refusal, pidBlockers)
	}
	cfg.DataDir = filepath.Join(t.TempDir(), "moved")
	if pidBlockers, refusal := rootOwnedStartRefusal(cfg, "start"); refusal == nil || len(pidBlockers) != 0 {
		t.Fatalf("hidden moved store: refusal=%v pidBlockers=%v", refusal, pidBlockers)
	}
}

// A hidden install home is the cause of whichever PID record failed: the chain
// replaces the identity text for either record.
func TestRefuseOverRootOwnedStateHiddenInstallHomeReplacesEitherPIDRecord(t *testing.T) {
	for _, record := range []string{"gateway.pid", "watchdog.pid"} {
		identityErr := unreadablePIDIdentityError(t, record)
		asRootDenied(t)
		stubRootRuntimeLeftovers(t, "./")
		err := refuseOverRootOwnedState(startCmd, "start", identityErr)
		if err == nil || errors.Is(err, identityErr) || !strings.Contains(err.Error(), "cannot start the gateway") {
			t.Fatalf("hidden install home over a failed %s = %v", record, err)
		}
	}
}

// A record the account cannot read because of a mode on a file it owns itself
// is not cleared by the chain, whatever root-owned state sits beside it: the
// refusal keeps its own text first and the chain is only reported after it, so
// nothing promises a start that would fail again (GAP-0788 review 5).
func TestRefuseOverRootOwnedStateKeepsAnUnreadableRecordThatRootDoesNotOwn(t *testing.T) {
	for _, record := range []string{"gateway.pid", "watchdog.pid"} {
		for _, blocker := range []string{record, "./", "active_connector.json"} {
			t.Run(record+"_"+strings.TrimSuffix(blocker, "/"), func(t *testing.T) {
				identityErr := unreadablePIDIdentityError(t, record)
				stubRootRuntimeLeftovers(t, blocker)
				err := refuseOverRootOwnedState(startCmd, "start", identityErr)
				if err == nil || !errors.Is(err, identityErr) ||
					strings.Index(err.Error(), identityErr.Error()) > strings.Index(err.Error(), "cannot start the gateway") {
					t.Fatalf("the independent permission failure was folded into the chain: %v", err)
				}
			})
		}
	}
}

// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package connector

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/testenv"
)

// GAP-0978: Hermes' TUI (hermes --tui, a separate tui_gateway process) and
// dashboard chat built their agent without registering the config.yaml shell
// hooks before 0.21.1 (v2026.9.7), so a terminal call there ran with no
// pre_tool_call. On the host those releases are known broken, by release, by
// release date and by the date a git build prints; the pinned build of the
// OpenShell image keeps its contract.
func TestHermesWhoseTUISkipsShellHooksIsKnownBrokenOnTheHost(t *testing.T) {
	for _, raw := range []string{
		"0.19.0",
		"Hermes Agent v0.19.0 (2026.7.20)",
		"Hermes Agent v0.19.1",
		"Hermes Agent v0.20.6 (2026.8.27)",
		"0.21.0",
		"2026.7.20",
		"2026.8.16.2",
		"2026.8.31",
		"2026.9.6",
		"Hermes Agent vunknown (2026.8.27)",
		"Hermes Agent vgit.5bba024 (2026.8.27)",
		"Hermes Agent vgit.5bba024 (2026.8.31)",
	} {
		for _, strict := range []bool{false, true} {
			got := resolveHookContractForOSMode("hermes", raw, "linux", strict)
			if got.Status != HookCompatibilityUnknown || !got.KnownBroken || got.Contract.ContractID != "" ||
				!strings.Contains(got.Reason, "known broken") || !strings.Contains(got.Reason, "hermes --tui") ||
				!strings.Contains(got.Reason, "0.21.1") || !strings.Contains(got.Reason, hermesTUIShellHooksFix) {
				t.Errorf("host %q strict=%t = %+v, want known broken with the cause and the fix", raw, strict, got)
			}
			if !HookContractNeedsActionOverride(got) {
				t.Errorf("host %q is not refused as an unverified version", raw)
			}
		}
		for _, goos := range []string{"windows", "darwin"} {
			if got := resolveHookContractForOSMode("hermes", raw, goos, false); !got.KnownBroken {
				t.Errorf("host %q on %s = %+v, want known broken", raw, goos, got)
			}
		}
	}
	for _, raw := range []string{
		"0.21.1",
		"Hermes Agent v0.21.5 (2026.10.1)",
		"2026.9.7",
		"2026.9.24",
		"Hermes Agent vgit.5bba024 (2026.9.24)",
		"Hermes Agent vgit.5bba024",
	} {
		if got := resolveHookContractForOSMode("hermes", raw, "linux", false); got.Status != HookCompatibilityKnown ||
			got.KnownBroken || got.Contract.ContractID != "hermes-hooks-v2" {
			t.Errorf("host %q = %+v, want hermes-hooks-v2", raw, got)
		}
	}
	if got := ResolveHookContract("hermes", "0.18.2"); got.KnownBroken || got.Status != HookCompatibilityUnknown {
		t.Errorf("Hermes 0.18.2 = %+v, want below the floor, not known broken", got)
	}
	// The OpenShell image pins Hermes 0.19.0; its own TUI limit is
	// documented there and not refused here.
	if got := ResolveSandboxHookContract("hermes", "0.19.0"); got.Status != HookCompatibilityKnown || got.Contract.ContractID != "hermes-hooks-v1" {
		t.Errorf("sandbox Hermes 0.19.0 = %+v, want hermes-hooks-v1", got)
	}
}

// Every path that sets Hermes up on the host (setup, a gateway start, the
// stopped-upgrade reconcile, the managed guardian) runs Setup: it refuses a
// known-broken Hermes in either guardrail mode before it writes anything, so
// an earlier registration is kept and nothing claims the TUI is guarded.
func TestHermesSetupRefusesAReleaseWhoseTUISkipsShellHooks(t *testing.T) {
	dataDir := testenv.PrivateTempDir(t)
	home := testenv.PrivateTempDir(t)
	configPath := filepath.Join(home, ".hermes", "config.yaml")
	if err := os.MkdirAll(filepath.Dir(configPath), 0o700); err != nil {
		t.Fatal(err)
	}
	original := []byte("model:\n  default: test\n")
	if err := os.WriteFile(configPath, original, 0o600); err != nil {
		t.Fatal(err)
	}
	previous := HermesConfigPathOverride
	HermesConfigPathOverride = configPath
	t.Cleanup(func() { HermesConfigPathOverride = previous })
	for _, version := range []string{"Hermes Agent v0.19.0 (2026.7.20)", "0.20.6", "0.21.0", "Hermes Agent vgit.5bba024 (2026.8.27)"} {
		for _, mode := range []string{"observe", "action"} {
			err := NewHermesConnector().Setup(context.Background(), SetupOpts{
				DataDir:       dataDir,
				APIAddr:       "127.0.0.1:18970",
				AgentVersion:  version,
				GuardrailMode: mode,
			})
			if !errors.Is(err, ErrSetupRefusedUnchanged) || !strings.Contains(err.Error(), "hermes --tui") ||
				!strings.Contains(err.Error(), "no changes made") {
				t.Fatalf("%s %s: Setup err = %v, want a refusal before any change naming the TUI", version, mode, err)
			}
			if got, err := os.ReadFile(configPath); err != nil || string(got) != string(original) {
				t.Fatalf("%s %s: Hermes config changed: %q (%v)", version, mode, got, err)
			}
			if entries, _ := os.ReadDir(dataDir); len(entries) != 0 {
				t.Fatalf("%s %s: Setup wrote into the data dir: %v", version, mode, entries)
			}
		}
	}
}

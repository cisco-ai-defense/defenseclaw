// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package connector

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/testenv"
)

// GAP-0978: Hermes' TUI (hermes --tui, a separate tui_gateway process) and
// dashboard chat built their agent without registering the config.yaml shell
// hooks before 0.21.1 (v2026.9.7), so a terminal call there ran with no
// pre_tool_call. Its classic interface, cron, ACP and messaging gateway run
// the hooks in every release, so on the host those releases keep their
// contract and carry a warning that names the TUI and the fix, by release, by
// release date and by the date a git build prints. The pinned build of the
// OpenShell image has no warning: its launcher refuses that TUI.
func TestHermesWhoseTUISkipsShellHooksKeepsItsContractWithAWarning(t *testing.T) {
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
		"Hermes Agent vgit.5bba024 (2026.8.27)",
		"Hermes Agent vgit.5bba024 (2026.8.31)",
	} {
		for _, goos := range []string{"linux", "windows", "darwin"} {
			got := resolveHookContractForOSMode("hermes", raw, goos, false)
			if got.Status != HookCompatibilityKnown || got.Contract.ContractID == "" || HookContractNeedsActionOverride(got) ||
				!strings.Contains(got.Warning, "hermes --tui") || !strings.Contains(got.Warning, "0.21.1") ||
				!strings.Contains(got.Warning, hermesTUIShellHooksFix) || strings.Contains(got.Reason, "known broken") {
				t.Errorf("host %q on %s = %+v, want its contract with the TUI warning", raw, goos, got)
			}
		}
		// Exact-range (Secure Client) mode keeps the warning on a version it
		// matches and drops it with the contract of one it does not.
		if strict := resolveHookContractForOSMode("hermes", raw, "linux", true); (strict.Status == HookCompatibilityKnown) == (strict.Warning == "") {
			t.Errorf("strict host %q = %+v", raw, strict)
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
			got.Warning != "" || got.Contract.ContractID != "hermes-hooks-v2" {
			t.Errorf("host %q = %+v, want hermes-hooks-v2 without a warning", raw, got)
		}
	}
	if got := ResolveHookContract("hermes", "0.18.2"); got.Warning != "" || got.Status != HookCompatibilityUnknown {
		t.Errorf("Hermes 0.18.2 = %+v, want below the floor without a warning", got)
	}
	if got := ResolveSandboxHookContract("hermes", "0.19.0"); got.Status != HookCompatibilityKnown ||
		got.Contract.ContractID != "hermes-hooks-v1" || got.Warning != "" {
		t.Errorf("sandbox Hermes 0.19.0 = %+v, want hermes-hooks-v1 without a warning", got)
	}
}

// Every path that sets Hermes up on the host (setup, a gateway start, the
// stopped-upgrade reconcile, the managed guardian) runs Setup. For a Hermes
// whose TUI skips the hooks it registers them in either guardrail mode, so
// its classic sessions are guarded, and warns about the TUI; it refused the
// whole release before (1.0.4 review).
func TestHermesSetupGuardsAReleaseWhoseTUISkipsShellHooks(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("the Windows admission fixture pins Hermes 0.21.5")
	}
	var warnings bytes.Buffer
	previousOutput := hermesSetupWarningOutput
	hermesSetupWarningOutput = &warnings
	t.Cleanup(func() { hermesSetupWarningOutput = previousOutput })
	for _, version := range []string{"Hermes Agent v0.19.0 (2026.7.20)", "0.20.6", "0.21.0", "Hermes Agent vgit.5bba024 (2026.8.27)"} {
		for _, mode := range []string{"observe", "action"} {
			root := testenv.PrivateTempDir(t)
			configPath := filepath.Join(root, ".hermes", "config.yaml")
			if err := os.MkdirAll(filepath.Dir(configPath), 0o700); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(configPath, []byte("model:\n  default: test\n"), 0o600); err != nil {
				t.Fatal(err)
			}
			previous := HermesConfigPathOverride
			HermesConfigPathOverride = configPath
			conn := NewHermesConnector()
			opts := prepareHermesSetupAdmissionFixture(t, SetupOpts{
				DataDir:       filepath.Join(root, ".defenseclaw"),
				APIAddr:       "127.0.0.1:18970",
				APIToken:      "tok-test",
				AgentVersion:  version,
				GuardrailMode: mode,
			})
			warnings.Reset()
			err := conn.Setup(context.Background(), opts)
			present, presentErr := OwnedHooksPresent(conn, opts)
			HermesConfigPathOverride = previous
			if err != nil {
				t.Fatalf("%s %s: Setup = %v, want the hooks registered", version, mode, err)
			}
			if presentErr != nil || !present {
				t.Fatalf("%s %s: OwnedHooksPresent after Setup = %v, %v; want present", version, mode, present, presentErr)
			}
			if got := warnings.String(); !strings.Contains(got, "WARNING: hermes") || !strings.Contains(got, "hermes --tui") ||
				!strings.Contains(got, "0.21.1") {
				t.Fatalf("%s %s: Setup warned %q, want the TUI warning", version, mode, got)
			}
		}
	}
}

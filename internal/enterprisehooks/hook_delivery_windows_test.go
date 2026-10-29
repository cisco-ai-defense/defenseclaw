// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0
//go:build windows

package enterprisehooks

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/gateway/connector"
)

func TestWindowsManagedRuntimeBundleAuthenticatesDeliveryMode(t *testing.T) {
	// Secure Client records the selected delivery mode (#1163).
	setStandaloneProfileForTest(t, false)
	for _, mode := range []string{"", "open", "closed"} {
		t.Run(mode, func(t *testing.T) {
			desired := WindowsManagedRuntimeGenerationDesired{FailMode: mode}
			bundle := windowsManagedRuntimeBundleFromDesired(desired, strings.Repeat("a", 32))
			if bundle.FailMode != canonicalHookFailMode(mode) || !windowsManagedRuntimeBundleMatchesDesired(bundle, desired) {
				t.Fatal("bundle did not retain effective delivery policy")
			}
			if bundle.FailMode == "open" {
				bundle.FailMode = "closed"
			} else {
				bundle.FailMode = "open"
			}
			if windowsManagedRuntimeBundleMatchesDesired(bundle, desired) {
				t.Fatal("mode drift matched authenticated generation")
			}
		})
	}
}

// Outside Secure Client the authenticated runtime generation records the
// administrator's mode (owner decision 2026-10-20): explicit open or closed,
// closed when unset; a drifted mode does not match it.
func TestWindowsManagedRuntimeBundleFollowsTheAdministratorOutsideSecureClient(t *testing.T) {
	setStandaloneProfileForTest(t, true)
	for mode, want := range map[string]string{"": "closed", "open": "open", "closed": "closed"} {
		desired := WindowsManagedRuntimeGenerationDesired{FailMode: mode}
		bundle := windowsManagedRuntimeBundleFromDesired(desired, strings.Repeat("a", 32))
		if bundle.FailMode != want || !windowsManagedRuntimeBundleMatchesDesired(bundle, desired) {
			t.Fatalf("mode %q: bundle fail mode = %q, want %q", mode, bundle.FailMode, want)
		}
		if want == "open" {
			bundle.FailMode = "closed"
		} else {
			bundle.FailMode = "open"
		}
		if windowsManagedRuntimeBundleMatchesDesired(bundle, desired) {
			t.Fatalf("mode %q: a drifted bundle matched outside Secure Client", mode)
		}
	}
}

func TestWindowsManagedInstallDefaultsOpenAndClaudeVersionCanBeMissing(t *testing.T) {
	// Secure Client (#1163).
	useWindowsSecureClientForTest(t)
	t.Run("codex default", func(t *testing.T) {
		fixture := newWindowsGenericCodexFixture(t)
		opts := fixture.opts
		opts.HookFailMode = ""
		// The generic fixture tests per-user contract/rendering policy. The
		// public Codex installer additionally requires protected machine state.
		if _, err := installWindowsGenericManagedResult(context.Background(), opts); err != nil {
			t.Fatal(err)
		}
		lock := connector.LoadHookContractLockEntry(filepath.Join(fixture.home, ".defenseclaw"), "codex")
		if lock.HookFailMode != "open" {
			t.Fatalf("default lock=%+v", lock)
		}
		if _, err := verifyWindowsGenericManagedResult(context.Background(), opts); err != nil {
			t.Fatal(err)
		}
	})
	t.Run("claude unversioned", func(t *testing.T) {
		fixture := newWindowsManagedInstallFixture(t, map[string]interface{}{"allowManagedHooksOnly": true})
		opts := windowsManagedInstallOptions(fixture)
		opts.AgentVersion = ""
		opts.HookFailMode = "closed"
		if _, err := Install(context.Background(), opts); err != nil {
			t.Fatal(err)
		}
		lock := connector.LoadHookContractLockEntry(filepath.Join(fixture.home, ".defenseclaw"), "claudecode")
		if lock.HookFailMode != "open" || lock.CompatibilityStatus != connector.HookCompatibilityUnversioned {
			t.Fatalf("fallback lock=%+v", lock)
		}
		if _, err := Verify(context.Background(), opts); err != nil {
			t.Fatal(err)
		}
	})
}

func TestWindowsCodexVersionFallbackStillRequiresProtectedMachineRuntime(t *testing.T) {
	// The version fallback is the Secure Client contract (#1163).
	useWindowsSecureClientForTest(t)
	for _, agentVersion := range []string{"", "codex-cli 0.142.0"} {
		t.Run(agentVersion, func(t *testing.T) {
			fixture := newWindowsGenericCodexFixture(t)
			t.Setenv("DEFENSECLAW_HOME", "")
			opts := fixture.opts
			opts.AgentVersion = agentVersion
			if _, err := Install(context.Background(), opts); err == nil ||
				!strings.Contains(err.Error(), "DEFENSECLAW_HOME must be exact protected StateRoot\\runtime") {
				t.Fatalf("Install without protected machine runtime = %v, want StateRoot/runtime rejection", err)
			}
		})
	}
}

func TestWindowsEnumerationUsesPresenceWithoutAgentVersion(t *testing.T) {
	// Presence-only admission is the Secure Client fallback (#1163).
	useWindowsSecureClientForTest(t)
	for _, agent := range []string{"codex", "claudecode", "cursor"} {
		t.Run(agent, func(t *testing.T) {
			home := t.TempDir()
			path := filepath.Join(home, ".codex", "auth.json")
			if agent == "claudecode" {
				path = filepath.Join(home, ".local", "bin", "claude.exe")
			}
			if agent == "cursor" {
				path = filepath.Join(home, "AppData", "Local", "Programs", "cursor", "Cursor.exe")
			}
			if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(path, []byte("fixture"), 0o600); err != nil {
				t.Fatal(err)
			}
			row := ManifestTarget{UserHome: home, SID: "S-1-5-21-1-2-3-1001", Connector: agent}
			if !applyPreviousRowState(&row, nil, nil) || row.AgentVersion != "" || row.Enabled == nil || !*row.Enabled {
				t.Fatalf("presence fallback row=%+v", row)
			}
		})
	}
}

func TestWindowsPresenceRejectsHookConfigAndDirectoryMasqueradingAsExecutable(t *testing.T) {
	home := t.TempDir()
	for _, path := range []string{
		filepath.Join(home, ".local", "bin", "claude.exe"),
		filepath.Join(home, ".local", "bin", "codex.exe"),
	} {
		if err := os.MkdirAll(path, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	for _, path := range []string{
		filepath.Join(home, ".claude", "settings.json"),
		filepath.Join(home, ".codex", "config.toml"),
	} {
		if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte("fixture"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	for _, agent := range []string{"claudecode", "codex"} {
		if windowsAgentPresence(home, agent) {
			t.Fatalf("%s discovery accepted non-installation evidence", agent)
		}
	}
}

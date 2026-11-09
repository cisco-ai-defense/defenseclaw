// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package enterprisehooks

import (
	"os"
	"path/filepath"
	"testing"
)

// useMacOSSecureClientGuardian makes this process look like the macOS Secure
// Client guardian (not standalone, a verified Secure Client install, darwin).
func useMacOSSecureClientGuardian(t *testing.T) {
	t.Helper()
	useSecureClientHookDelivery(t)
	previousGOOS := secureClientOwnedHookConfigGOOS
	previousStandalone := StandaloneUnix()
	secureClientOwnedHookConfigGOOS = "darwin"
	SetStandaloneUnix(false)
	t.Cleanup(func() {
		secureClientOwnedHookConfigGOOS = previousGOOS
		SetStandaloneUnix(previousStandalone)
	})
}

// A Secure Client Mac creates Copilot's hooks folder as the user, owner-only,
// so an account that never added hooks of its own can be enrolled.
func TestSecureClientMacCreatesCopilotHookConfigParents(t *testing.T) {
	useMacOSSecureClientGuardian(t)
	home := t.TempDir()
	hookFile := filepath.Join(home, ".copilot", "hooks", "defenseclaw.json")

	verified := secureClientOwnedHookConfigConnector("copilot")
	// As the user the marker check can fail (a folder it cannot search):
	// the folder still comes from the decision the guardian made as root.
	secureClientHookDeliveryHost = false
	owned, created, err := prepareOwnedHookConfigParents(home, "copilot", []string{hookFile}, os.Geteuid(), verified)
	if err != nil {
		t.Fatalf("prepareOwnedHookConfigParents: %v", err)
	}
	if len(owned) != 1 || owned[0] != hookFile {
		t.Fatalf("owned hook configs = %v, want [%s]", owned, hookFile)
	}
	want := []string{filepath.Join(home, ".copilot"), filepath.Join(home, ".copilot", "hooks")}
	if len(created) != len(want) || created[0] != want[0] || created[1] != want[1] {
		t.Fatalf("created folders = %v, want %v", created, want)
	}
	for _, dir := range want {
		info, err := os.Lstat(dir)
		if err != nil {
			t.Fatalf("lstat %s: %v", dir, err)
		}
		if !info.IsDir() || info.Mode().Perm() != 0o700 {
			t.Fatalf("%s mode = %v, want a 0700 directory", dir, info.Mode())
		}
	}
	if _, err := os.Lstat(hookFile); !os.IsNotExist(err) {
		t.Fatalf("the hook file itself is Setup's to write; lstat err = %v", err)
	}
}

// Only Copilot, and only the macOS Secure Client guardian, gets the folder:
// another DefenseClaw-owned hook config (Kiro), another OS, a process that is
// not running as the target user, and an unverified Secure Client install
// all leave the home untouched.
func TestSecureClientCopilotHookConfigParentsStayScoped(t *testing.T) {
	cases := []struct {
		name      string
		connector string
		setup     func(t *testing.T)
		uid       func() int
	}{
		{"kiro is standalone only", "kiro", useMacOSSecureClientGuardian, os.Geteuid},
		{"linux has no Secure Client profile", "copilot", func(t *testing.T) {
			useMacOSSecureClientGuardian(t)
			secureClientOwnedHookConfigGOOS = "linux"
		}, os.Geteuid},
		{"not running as the target user", "copilot", useMacOSSecureClientGuardian, func() int { return os.Geteuid() + 1 }},
		{"no verified Secure Client install", "copilot", func(t *testing.T) {
			useMacOSSecureClientGuardian(t)
			secureClientHookDeliveryHost = false
		}, os.Geteuid},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			tc.setup(t)
			home := t.TempDir()
			hookFile := filepath.Join(home, "."+tc.connector, "hooks", "defenseclaw.json")
			owned, created, err := prepareOwnedHookConfigParents(home, tc.connector, []string{hookFile}, tc.uid(),
				secureClientOwnedHookConfigConnector(tc.connector))
			if err != nil || owned != nil || created != nil {
				t.Fatalf("prepareOwnedHookConfigParents = %v, %v, %v; want nothing", owned, created, err)
			}
			if _, err := os.Lstat(filepath.Join(home, "."+tc.connector)); !os.IsNotExist(err) {
				t.Fatalf("a folder was created in the home: lstat err = %v", err)
			}
		})
	}
}

// A hooks folder someone else could write to is refused, as on the
// standalone profile.
func TestSecureClientCopilotHookConfigParentRefusesGroupWritableFolder(t *testing.T) {
	useMacOSSecureClientGuardian(t)
	home := t.TempDir()
	copilotHome := filepath.Join(home, ".copilot")
	if err := os.Mkdir(copilotHome, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(copilotHome, 0o770); err != nil {
		t.Fatal(err)
	}
	hookFile := filepath.Join(copilotHome, "hooks", "defenseclaw.json")
	if _, _, err := prepareOwnedHookConfigParents(home, "copilot", []string{hookFile}, os.Geteuid(), true); err == nil {
		t.Fatal("a group-writable ~/.copilot was accepted")
	}
	if _, err := os.Lstat(filepath.Join(copilotHome, "hooks")); !os.IsNotExist(err) {
		t.Fatalf("a folder was created below a refused parent: lstat err = %v", err)
	}
}

// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package enterprisehooks

import (
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/winpath"
)

func pinWindowsPerUserRuntimeStandaloneForTest(t *testing.T, standalone bool) {
	t.Helper()
	pinWindowsStandaloneProfileForTest(t, standalone)
	original := windowsPerUserRuntimeStandalone
	windowsPerUserRuntimeStandalone = func() bool { return standalone }
	t.Cleanup(func() { windowsPerUserRuntimeStandalone = original })
}

// Secure Client manages GitHub Copilot alone among the per-user connectors;
// the standalone profile keeps all of them.
func TestWindowsSecureClientPerUserConnectorSet(t *testing.T) {
	pinWindowsPerUserRuntimeStandaloneForTest(t, false)
	if got := WindowsProfilePerUserConnectorNames(); !reflect.DeepEqual(got, []string{"copilot"}) {
		t.Fatalf("Secure Client per-user connectors = %v", got)
	}
	if !IsWindowsProfilePerUserConnector("Copilot ") || IsWindowsProfilePerUserConnector("devin") ||
		IsWindowsProfilePerUserConnector("codex") {
		t.Fatal("Secure Client per-user connector membership is wrong")
	}
	pinWindowsPerUserRuntimeStandaloneForTest(t, true)
	if got := WindowsProfilePerUserConnectorNames(); !reflect.DeepEqual(got, WindowsStandalonePerUserConnectorNames()) {
		t.Fatalf("standalone per-user connectors = %v", got)
	}
	if !IsWindowsProfilePerUserConnector("devin") {
		t.Fatal("standalone profile does not manage devin per user")
	}
}

// On Secure Client, Copilot's enrollment and selector live in DefenseClaw's
// folder in Copilot's machine folder; no other per-user connector resolves
// one. The standalone profile keeps its hook runtime directory.
func TestWindowsSecureClientPerUserRuntimeDirectory(t *testing.T) {
	programData, err := winpath.TrustedProgramData()
	if err != nil {
		t.Fatal(err)
	}
	pinWindowsPerUserRuntimeStandaloneForTest(t, false)
	got, err := windowsPerUserManagedRuntimeDir("copilot")
	if err != nil {
		t.Fatal(err)
	}
	if want := filepath.Join(programData, "GitHub", "Copilot", "DefenseClaw"); got != want {
		t.Fatalf("Secure Client copilot runtime directory = %s, want %s", got, want)
	}
	if _, err := windowsPerUserManagedRuntimeDir("devin"); err == nil ||
		!strings.Contains(err.Error(), "does not manage") {
		t.Fatalf("Secure Client resolved a devin runtime directory: %v", err)
	}
	pinWindowsPerUserRuntimeStandaloneForTest(t, true)
	got, err = windowsPerUserManagedRuntimeDir("copilot")
	if err != nil {
		t.Fatal(err)
	}
	if filepath.Base(got) != "copilot" || strings.Contains(got, `GitHub\Copilot`) {
		t.Fatalf("standalone copilot runtime directory = %s", got)
	}
}

// Under Secure Client (#1163) Copilot follows the configured delivery mode
// like Codex, unset open; the standalone profile follows the administrator's
// explicit mode too, unset closed (owner decision 2026-10-20).
func TestWindowsSecureClientCopilotFailMode(t *testing.T) {
	pinWindowsPerUserRuntimeStandaloneForTest(t, false)
	useSecureClientHookDelivery(t)
	for configured, want := range map[string]string{"": "open", "open": "open", "closed": "closed", "bogus": "closed"} {
		if got := canonicalHookFailMode(configured); got != want {
			t.Fatalf("Secure Client copilot fail mode for %q = %q, want %q", configured, got, want)
		}
	}
	pinWindowsPerUserRuntimeStandaloneForTest(t, true)
	for configured, want := range map[string]string{"": "closed", "open": "open", "closed": "closed"} {
		if got := canonicalHookFailMode(configured); got != want {
			t.Fatalf("standalone copilot fail mode for %q = %q, want %q", configured, got, want)
		}
	}
}

// The GitHub Copilot app keeps the Copilot CLI releases it runs under
// github-copilot-sdk\cli\<version>; the newest one with its copilot.exe is the
// version, and the app counts as a Copilot install. Microsoft Copilot never
// does.
func TestWindowsCopilotAppCLIDiscovery(t *testing.T) {
	home := t.TempDir()
	write := func(path string) {
		t.Helper()
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte("x"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	// Microsoft Copilot's package folder is not GitHub Copilot.
	write(filepath.Join(home, "AppData", "Local", "Packages", "Microsoft.Copilot_8wekyb3d8bbwe", "Settings", "settings.dat"))
	if windowsAgentPresence(home, "copilot") || discoverWindowsCopilotAppCLIVersion(home) != "" {
		t.Fatal("Microsoft Copilot counted as GitHub Copilot")
	}
	root := windowsCopilotAppCLIRoot(home)
	write(filepath.Join(root, "1.0.79-5", "copilot.exe"))
	write(filepath.Join(root, "1.0.90-0", "copilot.exe"))
	if err := os.MkdirAll(filepath.Join(root, "1.0.95-1"), 0o755); err != nil {
		t.Fatal(err)
	}
	write(filepath.Join(root, "not-a-version", "copilot.exe"))
	if got := discoverWindowsCopilotAppCLIVersion(home); got != "1.0.90" {
		t.Fatalf("app CLI version = %q, want 1.0.90", got)
	}
	if got := windowsCopilotAppCLIExecutable(home); got != filepath.Join(root, "1.0.90-0", "copilot.exe") {
		t.Fatalf("app CLI executable = %q", got)
	}
	if !windowsAgentPresence(home, "copilot") {
		t.Fatal("the GitHub Copilot app's CLI is not Copilot presence")
	}
}

// Teardown removes DefenseClaw's Copilot folder once it holds only lock files
// and keeps it while anything else is there.
func TestRemoveWindowsSecureClientPerUserRuntimeDirectories(t *testing.T) {
	pinWindowsPerUserRuntimeStandaloneForTest(t, false)
	directory := filepath.Join(t.TempDir(), "GitHub", "Copilot", windowsSecureClientPerUserRuntimeLeaf)
	original := windowsPerUserManagedRuntimeDirResolver
	windowsPerUserManagedRuntimeDirResolver = func(string) (string, error) { return directory, nil }
	t.Cleanup(func() { windowsPerUserManagedRuntimeDirResolver = original })

	if kept, err := RemoveWindowsSecureClientPerUserRuntimeDirectories(); err != nil || len(kept) != 0 {
		t.Fatalf("absent folder: kept=%v err=%v", kept, err)
	}
	if err := os.MkdirAll(directory, 0o755); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{windowsPerUserManagedEnrollmentLockFile, windowsManagedRuntimeSelectorLockFile, "enrollment.json"} {
		if err := os.WriteFile(filepath.Join(directory, name), nil, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	if kept, err := RemoveWindowsSecureClientPerUserRuntimeDirectories(); err != nil || len(kept) != 1 {
		t.Fatalf("folder with an enrollment: kept=%v err=%v", kept, err)
	}
	if err := os.Remove(filepath.Join(directory, "enrollment.json")); err != nil {
		t.Fatal(err)
	}
	// An administrator's policy in Copilot's folder keeps it and GitHub's.
	adminPolicy := filepath.Join(filepath.Dir(directory), "policy.d", "10-company.json")
	if err := os.MkdirAll(filepath.Dir(adminPolicy), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(adminPolicy, []byte("{}"), 0o644); err != nil {
		t.Fatal(err)
	}
	if kept, err := RemoveWindowsSecureClientPerUserRuntimeDirectories(); err != nil || len(kept) != 0 {
		t.Fatalf("lock-only folder: kept=%v err=%v", kept, err)
	}
	if _, err := os.Stat(directory); !os.IsNotExist(err) {
		t.Fatalf("lock-only folder survived: %v", err)
	}
	if _, err := os.Stat(adminPolicy); err != nil {
		t.Fatalf("the administrator's Copilot policy was removed: %v", err)
	}
	// Once DefenseClaw's folder was the last thing there, the empty Copilot
	// and GitHub folders go with it.
	if err := os.RemoveAll(filepath.Dir(adminPolicy)); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(directory, 0o755); err != nil {
		t.Fatal(err)
	}
	if kept, err := RemoveWindowsSecureClientPerUserRuntimeDirectories(); err != nil || len(kept) != 0 {
		t.Fatalf("last folder: kept=%v err=%v", kept, err)
	}
	if _, err := os.Stat(filepath.Dir(filepath.Dir(directory))); !os.IsNotExist(err) {
		t.Fatalf("the empty GitHub folder survived: %v", err)
	}
	pinWindowsPerUserRuntimeStandaloneForTest(t, true)
	if kept, err := RemoveWindowsSecureClientPerUserRuntimeDirectories(); err != nil || kept != nil {
		t.Fatalf("standalone: kept=%v err=%v", kept, err)
	}
}

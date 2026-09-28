// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package enterprisehooks

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/sys/windows"

	"github.com/defenseclaw/defenseclaw/internal/gateway/connector"
)

// Only the standalone in-agent plugin connectors (OpenCode and Amp) carry the
// install marker and the listener proof; every hook-binary and
// machine-policy connector, and Secure Client, carry neither, so their
// renders keep an unconditional fail mode.
func TestWindowsStandalonePluginOptionsCarryTheMarkerAndListenerProof(t *testing.T) {
	root := filepath.Join(t.TempDir(), "DefenseClaw-HookRuntime")
	previousRoot := windowsStandaloneHookRuntimeRoot
	previousStandalone := windowsEnterpriseStandaloneProcess
	t.Cleanup(func() {
		windowsStandaloneHookRuntimeRoot = previousRoot
		windowsEnterpriseStandaloneProcess = previousStandalone
	})
	windowsStandaloneHookRuntimeRoot = func() (string, error) { return root, nil }
	options := func(name string) (connector.SetupOpts, error) {
		setup := connector.SetupOpts{ManagedEnterprise: true}
		err := applyWindowsStandalonePluginOptions(name, &setup)
		return setup, err
	}

	windowsEnterpriseStandaloneProcess = func() bool { return true }
	for _, name := range []string{"opencode", "amp"} {
		if got, err := windowsStandalonePluginInstallMarker(name); err != nil || got != root {
			t.Fatalf("%s install marker = %q, %v; want %q", name, got, err, root)
		}
		if setup, err := options(name); err != nil || !setup.ManagedListenerProof || setup.ManagedInstallMarker != root {
			t.Fatalf("%s standalone options = proof %v marker %q err %v; want the proof and %q", name, setup.ManagedListenerProof, setup.ManagedInstallMarker, err, root)
		}
	}
	for _, name := range []string{"antigravity", "copilot", "devin", "hermes", "claudecode", "codex", "cursor"} {
		if setup, err := options(name); err != nil || setup.ManagedListenerProof || setup.ManagedInstallMarker != "" {
			t.Fatalf("%s must carry neither option: proof %v marker %q err %v", name, setup.ManagedListenerProof, setup.ManagedInstallMarker, err)
		}
	}

	windowsEnterpriseStandaloneProcess = func() bool { return false }
	for _, name := range []string{"opencode", "amp"} {
		if setup, err := options(name); err != nil || setup.ManagedListenerProof || setup.ManagedInstallMarker != "" {
			t.Fatalf("Secure Client %s options = proof %v marker %q err %v; want none", name, setup.ManagedListenerProof, setup.ManagedInstallMarker, err)
		}
	}

	windowsEnterpriseStandaloneProcess = func() bool { return true }
	windowsStandaloneHookRuntimeRoot = func() (string, error) { return `DefenseClaw-HookRuntime`, nil }
	if _, err := windowsStandalonePluginInstallMarker("opencode"); err == nil {
		t.Fatal("a relative install marker was accepted")
	}
}

// The guardian creates the marker before it renders a plugin that names it,
// and verification reports a missing or substituted marker instead of a
// healthy deployment whose plugins would no longer fail closed.
func TestWindowsStandalonePluginInstallMarkerIsCreatedAndVerified(t *testing.T) {
	user, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil || user == nil || user.User.Sid == nil {
		t.Fatalf("resolve test SID: %v", err)
	}
	previousOwner := windowsManagedPolicyOwnerSID
	previousAncestor := windowsManagedPolicyAncestorTrustCheck
	previousDir := windowsManagedPolicyDirTrustCheck
	t.Cleanup(func() {
		windowsManagedPolicyOwnerSID = previousOwner
		windowsManagedPolicyAncestorTrustCheck = previousAncestor
		windowsManagedPolicyDirTrustCheck = previousDir
	})
	windowsManagedPolicyOwnerSID = func() (*windows.SID, error) { return user.User.Sid, nil }
	windowsManagedPolicyAncestorTrustCheck = func(string) error { return nil }
	windowsManagedPolicyDirTrustCheck = func(string) error { return nil }

	marker := filepath.Join(t.TempDir(), "Cisco", "DefenseClaw-HookRuntime")
	if err := verifyWindowsStandalonePluginInstallMarker(marker); err == nil || !strings.Contains(err.Error(), "is missing") {
		t.Fatalf("missing marker verify = %v, want a refusal", err)
	}
	for attempt := 0; attempt < 2; attempt++ {
		if err := ensureWindowsStandalonePluginInstallMarker(marker); err != nil {
			t.Fatalf("ensure marker (attempt %d): %v", attempt, err)
		}
	}
	if err := verifyWindowsStandalonePluginInstallMarker(marker); err != nil {
		t.Fatalf("verify created marker: %v", err)
	}

	if err := os.Remove(marker); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(marker, []byte("not a directory"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := verifyWindowsStandalonePluginInstallMarker(marker); err == nil {
		t.Fatal("a file in place of the install marker verified")
	}

	if err := ensureWindowsStandalonePluginInstallMarker(""); err != nil {
		t.Fatalf("no marker to ensure: %v", err)
	}
	if err := verifyWindowsStandalonePluginInstallMarker(""); err != nil {
		t.Fatalf("no marker to verify: %v", err)
	}
}

// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package enterprisehooks

import (
	"errors"
	"os"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/managed"
)

func stubOffRosterSeams(t *testing.T) {
	t.Helper()
	ensure, write, fileTrust, dirTrust := windowsStandaloneHookClosureEnsure, windowsStandaloneHookClosureWrite, windowsManagedPolicyFileTrustCheck, windowsManagedPolicyDirTrustCheck
	windowsStandaloneHookClosureEnsure = func(string) error { return nil }
	windowsStandaloneHookClosureWrite = func(path string, body []byte, _ bool) error { return os.WriteFile(path, body, 0o600) }
	windowsManagedPolicyFileTrustCheck = func(string) error { return nil }
	windowsManagedPolicyDirTrustCheck = func(string) error { return nil }
	t.Cleanup(func() {
		windowsStandaloneHookClosureEnsure, windowsStandaloneHookClosureWrite, windowsManagedPolicyFileTrustCheck, windowsManagedPolicyDirTrustCheck = ensure, write, fileTrust, dirTrust
	})
}

// The guardian publishes the marker while the config does not publish the
// connector and removes it when it does; the hook's read accepts only a valid
// marker in a trusted directory.
func TestWindowsConnectorOffRosterMarker(t *testing.T) {
	stubOffRosterSeams(t)
	layout := managed.StandaloneLayout{HookRuntimeDir: t.TempDir()}
	for _, name := range []string{"claudecode", "codex"} {
		if off, err := windowsConnectorOffRoster(layout, name); err != nil || off {
			t.Fatalf("%s before: off=%t err=%v", name, off, err)
		}
		if err := publishWindowsConnectorOffRoster(layout, name, true); err != nil {
			t.Fatal(err)
		}
		if off, err := windowsConnectorOffRoster(layout, name); err != nil || !off {
			t.Fatalf("%s published: off=%t err=%v", name, off, err)
		}
		// Publishing again changes nothing; one connector's marker is not the other's.
		if err := publishWindowsConnectorOffRoster(layout, name, true); err != nil {
			t.Fatal(err)
		}
	}
	if err := publishWindowsConnectorOffRoster(layout, "codex", false); err != nil {
		t.Fatal(err)
	}
	if off, _ := windowsConnectorOffRoster(layout, "codex"); off {
		t.Fatal("the codex marker survived its removal")
	}
	if off, err := windowsConnectorOffRoster(layout, "claudecode"); err != nil || !off {
		t.Fatalf("removing codex's marker removed claudecode's: off=%t err=%v", off, err)
	}
	// Removing a marker that is not there is not an error.
	if err := publishWindowsConnectorOffRoster(layout, "codex", false); err != nil {
		t.Fatal(err)
	}
	// A damaged marker, and an untrusted directory, are "no" with an error.
	if err := os.WriteFile(windowsConnectorOffRosterPath(layout, "claudecode"), []byte("other"), 0o600); err != nil {
		t.Fatal(err)
	}
	if off, err := windowsConnectorOffRoster(layout, "claudecode"); err == nil || off {
		t.Fatalf("damaged marker: off=%t err=%v", off, err)
	}
	if err := publishWindowsConnectorOffRoster(layout, "claudecode", true); err != nil {
		t.Fatalf("a damaged marker was not replaced: %v", err)
	}
	windowsManagedPolicyDirTrustCheck = func(string) error { return errors.New("untrusted directory") }
	if off, err := windowsConnectorOffRoster(layout, "claudecode"); err == nil || off {
		t.Fatalf("untrusted directory: off=%t err=%v", off, err)
	}
	// Only the connectors with a callable hook binary have a marker.
	if WindowsConnectorOffRosterConnector("cursor") || WindowsConnectorOffRosterConnector("copilot") || !WindowsConnectorOffRosterConnector("Codex") {
		t.Fatal("wrong covered connectors")
	}
	if err := PublishWindowsConnectorOffRoster("cursor", true); err == nil {
		t.Fatal("a marker was published for cursor")
	}
}

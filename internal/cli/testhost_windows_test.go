// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package cli

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/sys/windows"

	"github.com/defenseclaw/defenseclaw/internal/managed"
)

// isolateTestHost keeps the package's tests off the computer's own managed
// deployment. On a computer that is itself managed, the per-user gateway
// guard read the real HKLM marker and refused every start, stop and restart
// test that did not stub it; and a test that reached the scanner lifecycle
// without its own runtime folder worked on the installed scanner runtime.
// Tests that need a managed computer or a runtime folder set their own.
func isolateTestHost() func() {
	managedHostWindowsStandalone = func() (string, bool) { return "", false }
	dir, err := os.MkdirTemp("", "defenseclaw-cli-test-")
	if err != nil {
		windowsScannerRuntimeDir = func() (string, error) { return "", err }
		return func() {}
	}
	// Absent like on a computer without a deployment.
	runtimeDir := filepath.Join(dir, "scanners")
	windowsScannerRuntimeDir = func() (string, error) { return runtimeDir, nil }
	return func() { _ = os.RemoveAll(dir) }
}

// skipIfLocalSystem skips a test whose fixture cannot hold when it runs as
// LocalSystem, saying why.
func skipIfLocalSystem(t *testing.T, why string) {
	t.Helper()
	if testRunsAsLocalSystem() {
		t.Skip("skipped as LocalSystem: " + why)
	}
}

func testRunsAsLocalSystem() bool {
	user, err := windows.GetCurrentProcessToken().GetTokenUser()
	return err == nil && user != nil && user.User.Sid != nil && user.User.Sid.IsWellKnown(windows.WinLocalSystemSid)
}

// The package runs with neither the computer's managed marker nor its
// installed scanner runtime in reach, managed or not.
func TestPackageTestsDoNotReachTheInstalledDeployment(t *testing.T) {
	if where, managed := managedHostWindowsStandalone(); managed {
		t.Fatalf("the managed-host guard reads the real deployment (%s)", where)
	}
	root, err := windowsScannerRuntimeDir()
	if err != nil {
		t.Fatal(err)
	}
	installed, err := managed.StandaloneWindowsScannerRuntimeDir()
	if err == nil && strings.EqualFold(filepath.Clean(root), filepath.Clean(installed)) {
		t.Fatalf("the scanner lifecycle works on the installed runtime %s", installed)
	}
	if rel, err := filepath.Rel(os.TempDir(), root); err != nil || strings.HasPrefix(rel, "..") {
		t.Fatalf("scanner runtime %s is outside the temp folder %s", root, os.TempDir())
	}
}

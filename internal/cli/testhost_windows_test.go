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

	"github.com/defenseclaw/defenseclaw/internal/gateway/connector"
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
	// GAP-2572: on a managed lane host the HKLM marker key exists, so the
	// "marker present but unverified" check read it and closed every
	// per-user outage case; Secure Client and the runtime descriptor are the
	// other two machine signals the outage mode reads.
	managedHostWindowsMarkerUncertain = func() bool { return false }
	secureClientHost = func() bool { return false }
	dir, err := os.MkdirTemp("", "defenseclaw-cli-test-")
	if err != nil {
		windowsScannerRuntimeDir = func() (string, error) { return "", err }
		managedHostDescriptorPath = func() string { return "" }
		return func() {}
	}
	missingDescriptor := filepath.Join(dir, "no-runtime-descriptor")
	managedHostDescriptorPath = func() string { return missingDescriptor }
	// Absent like on a computer without a deployment.
	runtimeDir := filepath.Join(dir, "scanners")
	windowsScannerRuntimeDir = func() (string, error) { return runtimeDir, nil }
	return func() { _ = os.RemoveAll(dir) }
}

// isolateWindowsEnterpriseHostReaders makes the computer's own standalone
// deployment state read as absent, as on a build box: its config and
// manifest, the guardian's last pass and per-user cleanup ledger, its agent
// config notices, the Amp machine folder and the discovery homes. On a
// managed lane host these added the real accounts' warnings
// (agent_settings_not_restored, guardian_repair_pending,
// hook_process_fail_open) to results a test builds from a stubbed installer
// report (GAP-2572). A test that needs one of them sets its own after this.
func isolateWindowsEnterpriseHostReaders(t *testing.T) {
	t.Helper()
	oldV2, oldGuardian, oldCleanups := windowsEnterpriseStatusV2Read, windowsEnterpriseGuardianStateForStatus, windowsEnterpriseUserCleanupsForStatus
	oldSettings, oldOTLP := windowsEnterpriseAgentSettingsNotices, windowsEnterpriseNativeOTLPNotices
	oldAmp, oldHomes := windowsEnterpriseAmpMachineFolderProblems, windowsEnterpriseDiscoveryHomeDirs
	t.Cleanup(func() {
		windowsEnterpriseStatusV2Read, windowsEnterpriseGuardianStateForStatus, windowsEnterpriseUserCleanupsForStatus = oldV2, oldGuardian, oldCleanups
		windowsEnterpriseAgentSettingsNotices, windowsEnterpriseNativeOTLPNotices = oldSettings, oldOTLP
		windowsEnterpriseAmpMachineFolderProblems, windowsEnterpriseDiscoveryHomeDirs = oldAmp, oldHomes
	})
	registry := connector.NewDefaultRegistry()
	windowsEnterpriseStatusV2Read = func() windowsEnterpriseStatusV2Inputs {
		return windowsEnterpriseStatusV2Inputs{
			configErr:     os.ErrNotExist,
			manifestErr:   os.ErrNotExist,
			machinePolicy: func(string) bool { return false },
			gatewayHealth: func() ([]byte, error) { return nil, os.ErrNotExist },
			knownConnector: func(name string) bool {
				_, ok := registry.Get(name)
				return ok
			},
		}
	}
	windowsEnterpriseGuardianStateForStatus = func() (enterpriseHookGuardianState, bool, error) {
		return enterpriseHookGuardianState{}, false, nil
	}
	windowsEnterpriseUserCleanupsForStatus = func() ([]enterpriseHookUserCleanup, error) { return nil, nil }
	windowsEnterpriseAgentSettingsNotices = func() []string { return nil }
	windowsEnterpriseNativeOTLPNotices = func() []string { return nil }
	windowsEnterpriseAmpMachineFolderProblems = func() []string { return nil }
	windowsEnterpriseDiscoveryHomeDirs = func() ([]string, error) { return nil, nil }
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
	if managedHostWindowsMarkerUncertain() || secureClientHost() {
		t.Fatal("the outage mode reads the computer's own HKLM marker or Secure Client install")
	}
	if descriptor := managedHostDescriptorPath(); descriptor != "" {
		if rel, err := filepath.Rel(os.TempDir(), descriptor); err != nil || strings.HasPrefix(rel, "..") {
			t.Fatalf("the managed runtime descriptor %s is outside the temp folder %s", descriptor, os.TempDir())
		}
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

// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package cli

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/sys/windows"

	"github.com/defenseclaw/defenseclaw/internal/enterprisestatus"
	"github.com/defenseclaw/defenseclaw/internal/managed"
	"github.com/defenseclaw/defenseclaw/internal/winpath"
)

// stageWindowsScannerRuntimeTest points the scanner step at a temporary
// root and stages an unsigned scanner executable beside an installer.
func stageWindowsScannerRuntimeTest(t *testing.T) (root, installer, source string) {
	t.Helper()
	if !windows.GetCurrentProcessToken().IsElevated() {
		t.Skip("the scanner runtime root is administrator-only; run elevated")
	}
	dirSeam, accountSeam, sourceSeam := windowsScannerRuntimeDir, windowsScannerGatewayAccount, windowsScannerSourceCheck
	t.Cleanup(func() {
		windowsScannerRuntimeDir, windowsScannerGatewayAccount, windowsScannerSourceCheck = dirSeam, accountSeam, sourceSeam
	})
	root = filepath.Join(t.TempDir(), "DefenseClaw-ScannerRuntime")
	windowsScannerRuntimeDir = func() (string, error) { return root, nil }
	windowsScannerGatewayAccount = `NT SERVICE\TrustedInstaller`
	windowsScannerSourceCheck = func(string, string) error { return nil }
	payload := t.TempDir()
	installer = filepath.Join(payload, "install-enterprise.ps1")
	source = filepath.Join(payload, managed.StandaloneWindowsScannerRuntimeName)
	for _, path := range []string{installer, source} {
		if err := os.WriteFile(path, []byte("unsigned "+filepath.Base(path)), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	return root, installer, source
}

// GAP-0919: an installed scanner executable with the staged bytes and an
// admission record is admitted again under the current trust policy. Before,
// matching bytes skipped admission, so a new signer restriction never
// applied to it.
func TestWindowsScannerRuntimeMatchingBytesAreAdmittedAgain(t *testing.T) {
	root, installer, source := stageWindowsScannerRuntimeTest(t)
	setWindowsScannerRuntimeDeploymentTest(t, func() winpath.EnterpriseDeployment {
		return winpath.EnterpriseDeployment{State: winpath.EnterpriseDeploymentInstalled, ProductVersion: "1.0.4"}
	})
	gateway, err := managed.WindowsServiceAccountSID(windowsScannerGatewayAccount)
	if err != nil {
		t.Fatal(err)
	}
	if err := ensureWindowsScannerRuntimeRoot(root, gateway); err != nil {
		t.Fatal(err)
	}
	staged, err := os.ReadFile(source)
	if err != nil {
		t.Fatal(err)
	}
	target := filepath.Join(root, managed.StandaloneWindowsScannerRuntimeName)
	if err := os.WriteFile(target, staged, 0o755); err != nil {
		t.Fatal(err)
	}
	digest, err := windowsEnterpriseFileSHA256(source)
	if err != nil {
		t.Fatal(err)
	}
	// An earlier run admitted these bytes under a looser policy.
	if err := managed.WriteScannerRuntimeAdmission(root, digest, managed.ScannerRuntimeTrustAuthenticode); err != nil {
		t.Fatal(err)
	}
	opts := &windowsEnterpriseLifecycleOptions{resolvedInstaller: installer, trustMode: windowsEnterpriseTrustAuthenticode, productVersion: "1.0.4"}
	err = installWindowsScannerRuntime(source, "ensure", opts)
	if err == nil || !strings.Contains(err.Error(), "not admitted by the standalone payload trust policy") {
		t.Fatalf("install = %v, want the trust policy refusal for matching bytes", err)
	}
}

// GAP-1166: the scanner step of a run older than the installed deployment
// leaves the runtime to the run that installed it, and says so.
func TestWindowsScannerRuntimeOlderRunDoesNotReplaceANewerRuntime(t *testing.T) {
	root, installer, _ := stageWindowsScannerRuntimeTest(t)
	setWindowsScannerRuntimeDeploymentTest(t, func() winpath.EnterpriseDeployment {
		return winpath.EnterpriseDeployment{State: winpath.EnterpriseDeploymentInstalled, ProductVersion: "1.5.0"}
	})
	opts := &windowsEnterpriseLifecycleOptions{resolvedInstaller: installer, trustMode: windowsEnterpriseTrustAuthenticode,
		productVersion: "1.4.0"}
	result := enterprisestatus.New("upgrade", managed.ProfileStandalone, "windows", "1.4.0")
	applyWindowsStandaloneScannerRuntime(result, opts)
	if _, err := os.Lstat(filepath.Join(root, managed.StandaloneWindowsScannerRuntimeName)); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("the older run installed its scanner executable: %v", err)
	}
	if len(result.Errors) != 0 || !windowsEnterpriseResultHasWarning(result, "scanner_runtime_superseded") {
		t.Fatalf("errors %+v warnings %+v, want only scanner_runtime_superseded", result.Errors, result.Warnings)
	}
}

// setWindowsScannerRuntimeDeploymentTest makes the scanner step read the
// deployment record that record returns, on each read.
func setWindowsScannerRuntimeDeploymentTest(t *testing.T, record func() winpath.EnterpriseDeployment) {
	t.Helper()
	seam := windowsScannerRuntimeDeployment
	t.Cleanup(func() { windowsScannerRuntimeDeployment = seam })
	windowsScannerRuntimeDeployment = func(*windowsEnterpriseLifecycleOptions) (winpath.EnterpriseDeployment, error) {
		deployment := record()
		deployment.Profile = managed.ProfileStandalone
		deployment.MetadataPath = `C:\ProgramData\Cisco\DefenseClaw\install\deployment.json`
		return deployment, nil
	}
}

// GAP-1166 review: an upgrade whose scanner step runs after another run
// uninstalled DefenseClaw does not recreate the scanner runtime: not when
// the uninstall came before the step (no folder is made, and a folder the
// uninstall left goes), and not when it committed while the step waited for
// the scanner runtime lock. Before, a missing gateway version let it go on.
func TestWindowsScannerRuntimeUpgradeOvertakenByUninstallDoesNotRecreateIt(t *testing.T) {
	root, installer, _ := stageWindowsScannerRuntimeTest(t)
	reads := 0
	installedReads := 0
	setWindowsScannerRuntimeDeploymentTest(t, func() winpath.EnterpriseDeployment {
		reads++
		if reads <= installedReads {
			return winpath.EnterpriseDeployment{State: winpath.EnterpriseDeploymentInstalled, ProductVersion: "1.0.4"}
		}
		return winpath.EnterpriseDeployment{State: winpath.EnterpriseDeploymentTombstone, ProductVersion: "1.0.4"}
	})
	opts := &windowsEnterpriseLifecycleOptions{resolvedInstaller: installer, trustMode: windowsEnterpriseTrustAuthenticode,
		productVersion: "1.0.4"}
	gateway, err := managed.WindowsServiceAccountSID(windowsScannerGatewayAccount)
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name           string
		installedReads int
		leftover       bool
	}{
		{name: "uninstalled before the step", installedReads: 0},
		{name: "uninstalled before the step, folder left", installedReads: 0, leftover: true},
		{name: "uninstalled while the step waited for the lock", installedReads: 1},
	} {
		reads, installedReads = 0, tc.installedReads
		if tc.leftover {
			if err := ensureWindowsScannerRuntimeRoot(root, gateway); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(root, managed.StandaloneWindowsScannerRuntimeName), []byte("old runtime"), 0o755); err != nil {
				t.Fatal(err)
			}
		}
		result := enterprisestatus.New("upgrade", managed.ProfileStandalone, "windows", "1.0.4")
		result.Installed = true
		applyWindowsStandaloneScannerRuntime(result, opts)
		if _, err := os.Lstat(root); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("%s: the scanner runtime folder exists after the uninstall: %v", tc.name, err)
		}
		if len(result.Errors) != 0 || !windowsEnterpriseResultHasWarning(result, "scanner_runtime_superseded") ||
			!strings.Contains(fmt.Sprint(result.Warnings), "uninstalled DefenseClaw") {
			t.Fatalf("%s: errors %+v warnings %+v, want only scanner_runtime_superseded naming the uninstall", tc.name, result.Errors, result.Warnings)
		}
	}
}

// GAP-1166 review: the scanner step publishes only the runtime of the
// release the deployment record names for this run.
func TestWindowsScannerRuntimeReleaseMatches(t *testing.T) {
	for _, tc := range []struct {
		action, run, installed string
		want                   bool
	}{
		{"upgrade", "1.0.4", "1.0.4", true},
		{"upgrade", "1.0.4", "1.0.5", false},
		{"upgrade", "1.0.4", "1.0.3", false},
		{"ensure", "1.0.4", "1.0.3", false},
		{"install", "1.0.4", "", false},
		{"repair", "1.0.4", "1.0.3", true},
		{"repair", "1.0.4", "1.0.5", false},
		{"ensure", "dev", "dev", true},
		{"ensure", "v1.0.4", "1.0.4", true},
	} {
		if got := windowsScannerRuntimeReleaseMatches(tc.action, tc.run, tc.installed); got != tc.want {
			t.Errorf("%s run %q over installed %q = %v, want %v", tc.action, tc.run, tc.installed, got, tc.want)
		}
	}
}

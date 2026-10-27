// Copyright 2026 Cisco Systems, Inc. and its affiliates
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
)

// GAP-1687: a scanner runtime prepare that hit its bound on a busy computer
// is retryable (1618) with the same command, not a failed deployment (1603);
// any other prepare failure stays 1603.
func TestWindowsScannerPrepareTimeoutIsRetryable(t *testing.T) {
	timedOut := enterprisestatus.New("ensure", "standalone", "windows", "1.0.5")
	timedOut.AddError("scanner_runtime_unavailable", windowsScannerRuntimePrepareFailed(
		fmt.Errorf("prepare the scanner runtime: timed out after 15m0s: %w", errWindowsScannerPrepareTimedOut)))
	if code := windowsEnterpriseFailureCodeFor(timedOut); code != enterprisestatus.WindowsExitBusy {
		t.Fatalf("timed-out prepare exit = %d, want %d: %s", code, enterprisestatus.WindowsExitBusy, timedOut.Errors[0].Message)
	}
	failed := enterprisestatus.New("ensure", "standalone", "windows", "1.0.5")
	failed.AddError("scanner_runtime_unavailable", windowsScannerRuntimePrepareFailed(errors.New("prepare the scanner runtime: exit status 2")))
	if code := windowsEnterpriseFailureCodeFor(failed); code == enterprisestatus.WindowsExitBusy {
		t.Fatalf("a failed prepare became retryable: %s", failed.Errors[0].Message)
	}
}

// GAP-1709: a recovery that put an earlier release back reports that
// release's scanner runtime, which this release's admission rule does not
// prove, as a warning; a recovery of this release, and verify, still fail.
func TestWindowsRecoveryToAnEarlierReleaseDoesNotFailOnItsScannerRuntime(t *testing.T) {
	reader := windowsScannerRuntimeReader
	t.Cleanup(func() { windowsScannerRuntimeReader = reader })
	windowsScannerRuntimeReader = func() *enterprisestatus.ScannerRuntime {
		return &enterprisestatus.ScannerRuntime{State: "untrusted"}
	}
	opts := &windowsEnterpriseLifecycleOptions{productVersion: "1.0.5"}
	for _, tc := range []struct {
		action, installed string
		wantError         bool
	}{
		{action: "recover", installed: "1.0.2"},
		{action: "recover", installed: "1.0.5", wantError: true},
		{action: "verify", installed: "1.0.2", wantError: true},
	} {
		result := enterprisestatus.New(tc.action, "standalone", "windows", "1.0.5")
		result.Installed, result.InstalledVersion = true, tc.installed
		applyWindowsStandaloneScannerRuntime(result, opts)
		if got := windowsEnterpriseResultHasError(result, "scanner_runtime_unavailable"); got != tc.wantError {
			t.Errorf("%s over %s: error=%t, want %t (warnings %+v)", tc.action, tc.installed, got, tc.wantError, result.Warnings)
		}
		if !tc.wantError {
			// The plain ensure clears it, so the warning names it, not /repair.
			for _, warning := range result.Warnings {
				if warning.Code == "scanner_runtime_unavailable" &&
					(!strings.Contains(warning.Message, "/ensure CONFIG=") || strings.Contains(warning.Message, "/repair")) {
					t.Errorf("%s over %s: warning does not name the clearing /ensure: %s", tc.action, tc.installed, warning.Message)
				}
			}
		}
	}
}

// GAP-1718: after the scanner runtime work adopts Administrators as the
// default owner, a file this elevated process creates is owned by
// Administrators even when the token belongs to the built-in Administrator
// (RID 500, no Admin Approval Mode), whose default owner is its own SID.
func TestWindowsScannerRuntimeFilesAreOwnedByAdministrators(t *testing.T) {
	if !windows.GetCurrentProcessToken().IsElevated() {
		t.Skip("needs an elevated administrator token")
	}
	user, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		t.Fatal(err)
	}
	if user.User.Sid.IsWellKnown(windows.WinLocalSystemSid) {
		t.Skip("LocalSystem owns what it creates as SYSTEM")
	}
	restore, err := adoptWindowsAdministratorsDefaultOwner()
	if err != nil {
		t.Fatalf("adopt Administrators as the default owner: %v", err)
	}
	defer restore()
	path := filepath.Join(t.TempDir(), "admission.json")
	if err := os.WriteFile(path, []byte("{}"), 0o644); err != nil {
		t.Fatal(err)
	}
	owned, err := windowsPathOwnedByAdministrators(path)
	if err != nil || !owned {
		t.Fatalf("a file written after the adoption is not owned by Administrators: owned=%t err=%v", owned, err)
	}
}

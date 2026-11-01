// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package cli

import (
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/enterprisestatus"
	"github.com/defenseclaw/defenseclaw/internal/managed"
)

// GAP-2456: TIMEOUTSECONDS stopped a loaded 1.0.3 -> 1.0.5 Setup /ensure
// after the transaction committed and before its scanner step. Setup's
// bounded recovery then settled 1.0.5 beside the 1.0.3 scanner runtime and
// its schema 1 admission record, which 1.0.5 does not run, so the recovery
// failed scanner_runtime_unavailable and verify failed until a manual
// /repair. A recovery that settled this release from a Setup payload now
// runs the scanner step the stopped run did not reach, and only then.
func TestWindowsScannerRuntimeRecoveryFinishesTheStoppedRunsScannerStep(t *testing.T) {
	readerSeam, installerSeam, serviceSeam := windowsScannerRuntimeReader, windowsScannerRuntimeInstaller, windowsScannerRuntimeServiceCheck
	t.Cleanup(func() {
		windowsScannerRuntimeReader, windowsScannerRuntimeInstaller, windowsScannerRuntimeServiceCheck = readerSeam, installerSeam, serviceSeam
	})
	windowsScannerRuntimeServiceCheck = func() error { return nil }
	payload := t.TempDir()
	installer := filepath.Join(payload, "install-enterprise.ps1")
	source := filepath.Join(payload, managed.StandaloneWindowsScannerRuntimeName)
	for _, path := range []string{installer, source} {
		if err := os.WriteFile(path, []byte("payload "+filepath.Base(path)), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	state := "untrusted"
	windowsScannerRuntimeReader = func() *enterprisestatus.ScannerRuntime {
		return &enterprisestatus.ScannerRuntime{State: state, JudgeModel: "judge"}
	}
	var calls []string
	var installErr error
	windowsScannerRuntimeInstaller = func(got, action string, _ *windowsEnterpriseLifecycleOptions) error {
		calls = append(calls, action+" "+got)
		if installErr != nil {
			return installErr
		}
		state = "ready"
		return nil
	}
	run := func(action, installed, staged string) *enterprisestatus.Result {
		t.Helper()
		state, calls = "untrusted", nil
		result := enterprisestatus.New(action, managed.ProfileStandalone, "windows", "1.0.5")
		result.Installed, result.InstalledVersion = true, installed
		applyWindowsStandaloneScannerRuntime(result, &windowsEnterpriseLifecycleOptions{
			productVersion: "1.0.5", resolvedInstaller: staged, trustMode: windowsEnterpriseTrustAuthenticode,
		})
		return result
	}

	// The recovery settled this release: the stopped run's scanner step runs
	// from the staged payload and the recovery is clean.
	result := run("recover", "1.0.5", installer)
	if len(calls) != 1 || calls[0] != "recover "+source {
		t.Fatalf("installer calls %q, want one recover from %s", calls, source)
	}
	if len(result.Errors) != 0 || result.Scanners == nil || result.Scanners.State != "ready" {
		t.Fatalf("recovery errors %+v scanners %+v, want a ready runtime and no error", result.Errors, result.Scanners)
	}

	// A step that fails is one scanner_runtime_unavailable error naming it.
	installErr = errors.New("not admitted by the standalone payload trust policy")
	result = run("recover", "1.0.5", installer)
	installErr = nil
	if len(calls) != 1 || len(result.Errors) != 1 || result.Errors[0].Code != "scanner_runtime_unavailable" {
		t.Fatalf("failed step: calls %q errors %+v, want one scanner_runtime_unavailable", calls, result.Errors)
	}

	// Nothing else installs: a recovery that put an earlier release back
	// keeps that release's runtime (GAP-1709), a recovery from the installed
	// CLI has no payload, and status and verify only read.
	for _, tc := range []struct{ action, installed, staged string }{
		{"recover", "1.0.3", installer},
		{"recover", "1.0.5", ""},
		{"verify", "1.0.5", installer},
		{"status", "1.0.5", installer},
	} {
		result = run(tc.action, tc.installed, tc.staged)
		if len(calls) != 0 {
			t.Fatalf("%s of %s (installer %q) ran the scanner step: %q", tc.action, tc.installed, tc.staged, calls)
		}
		if tc.action != "status" && tc.installed == "1.0.5" && !windowsEnterpriseResultHasError(result, "scanner_runtime_unavailable") {
			t.Fatalf("%s of %s: errors %+v, want the untrusted runtime reported", tc.action, tc.installed, result.Errors)
		}
	}

	// A ready runtime is left alone.
	state = "ready"
	calls = nil
	result = enterprisestatus.New("recover", managed.ProfileStandalone, "windows", "1.0.5")
	result.Installed, result.InstalledVersion = true, "1.0.5"
	applyWindowsStandaloneScannerRuntime(result, &windowsEnterpriseLifecycleOptions{productVersion: "1.0.5", resolvedInstaller: installer})
	if len(calls) != 0 || len(result.Errors) != 0 {
		t.Fatalf("ready runtime: calls %q errors %+v, want neither", calls, result.Errors)
	}
}

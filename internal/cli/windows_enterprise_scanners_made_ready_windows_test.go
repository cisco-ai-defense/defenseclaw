// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package cli

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/enterprisestatus"
	"github.com/defenseclaw/defenseclaw/internal/managed"
)

// GAP-0679: an ensure that made the scanner runtime ready again (it had lost
// its Python interpreter, so it was installed but not prepared) is a repair:
// the result lists the change and is not a no-op, so the MDM Fix script says
// repaired instead of "no repair needed after verify". A runtime that was
// ready stays a no-op, and verify, a failed prepare or a run another
// deployment overtook add no change.
func TestWindowsScannerRuntimeMadeReadyIsAChange(t *testing.T) {
	newWindowsScannerRuntimeRemovalTest(t)
	readerSeam, repreparerSeam, installerSeam, serviceSeam :=
		windowsScannerRuntimeReader, windowsScannerRuntimeRepreparer, windowsScannerRuntimeInstaller, windowsScannerRuntimeServiceCheck
	t.Cleanup(func() {
		windowsScannerRuntimeReader, windowsScannerRuntimeRepreparer = readerSeam, repreparerSeam
		windowsScannerRuntimeInstaller, windowsScannerRuntimeServiceCheck = installerSeam, serviceSeam
	})
	windowsScannerRuntimeServiceCheck = func() error { return nil }
	state := ""
	windowsScannerRuntimeReader = func() *enterprisestatus.ScannerRuntime {
		return &enterprisestatus.ScannerRuntime{State: state, JudgeModel: "judge"}
	}
	var stepErr error
	steps := 0
	windowsScannerRuntimeRepreparer = func(string, *windowsEnterpriseLifecycleOptions) error {
		steps++
		var superseded *windowsScannerRuntimeSupersededError
		if errors.As(stepErr, &superseded) {
			// The run that overtook this one prepared it.
			state = "ready"
		}
		if stepErr != nil {
			return stepErr
		}
		state = "ready"
		return nil
	}
	windowsScannerRuntimeInstaller = func(string, string, *windowsEnterpriseLifecycleOptions) error {
		steps++
		if stepErr != nil {
			return stepErr
		}
		state = "ready"
		return nil
	}
	payload := t.TempDir()
	installer := filepath.Join(payload, "install-enterprise.ps1")
	for _, path := range []string{installer, filepath.Join(payload, managed.StandaloneWindowsScannerRuntimeName)} {
		if err := os.WriteFile(path, []byte("payload "+filepath.Base(path)), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	run := func(action, found, staged string) *enterprisestatus.Result {
		t.Helper()
		state, steps = found, 0
		result := enterprisestatus.New(action, managed.ProfileStandalone, "windows", "1.0.6")
		result.Installed, result.InstalledVersion = true, "1.0.6"
		if action == "ensure" {
			// The plan found the deployment compliant before the scanner step.
			result.Noop, result.NoopReason = true, "already_applied"
		}
		applyWindowsStandaloneScannerRuntime(result, &windowsEnterpriseLifecycleOptions{
			productVersion: "1.0.6", resolvedInstaller: staged, trustMode: windowsEnterpriseTrustAuthenticode,
		})
		return result
	}
	changed := func(result *enterprisestatus.Result, was string) bool {
		return !result.Noop && result.NoopReason == "" && len(result.Changes) == 1 &&
			strings.Contains(result.Changes[0], "scanner runtime ready again") && strings.Contains(result.Changes[0], was)
	}

	// The lane's case: the ensure from the installed CLI (the Fix script)
	// prepared the runtime again.
	result := run("ensure", "not_prepared", "")
	if steps != 1 || len(result.Errors) != 0 || !changed(result, "installed but not prepared") {
		t.Fatalf("installed-CLI ensure over a not prepared runtime: steps %d noop %v (%q) changes %q errors %+v",
			steps, result.Noop, result.NoopReason, result.Changes, result.Errors)
	}
	// A repair says so too.
	if result = run("repair", "not_prepared", ""); !changed(result, "installed but not prepared") {
		t.Fatalf("repair over a not prepared runtime: changes %q", result.Changes)
	}
	// Setup /ensure from its payload installed a missing runtime.
	if result = run("ensure", "missing", installer); steps != 1 || !changed(result, "it was missing") {
		t.Fatalf("Setup ensure over a missing runtime: steps %d noop %v changes %q", steps, result.Noop, result.Changes)
	}

	// A healthy host stays a no-op, from the installed CLI and from Setup.
	for _, staged := range []string{"", installer} {
		result = run("ensure", "ready", staged)
		if !result.Noop || result.NoopReason != "already_applied" || len(result.Changes) != 0 || len(result.Errors) != 0 {
			t.Fatalf("healthy ensure (staged %q): noop %v (%q) changes %q errors %+v",
				staged, result.Noop, result.NoopReason, result.Changes, result.Errors)
		}
	}

	// A prepare that failed is not a repair.
	stepErr = errors.New("prepare failed")
	result = run("ensure", "not_prepared", "")
	stepErr = nil
	if len(result.Changes) != 0 || !windowsEnterpriseResultHasError(result, "scanner_runtime_unavailable") {
		t.Fatalf("failed prepare: changes %q errors %+v", result.Changes, result.Errors)
	}
	// Nor is a runtime another run owns now, even when it is ready.
	stepErr = &windowsScannerRuntimeSupersededError{run: "1.0.6", installed: "1.0.7"}
	result = run("ensure", "not_prepared", "")
	stepErr = nil
	if result.Scanners == nil || result.Scanners.State != "ready" || len(result.Changes) != 0 || !result.Noop {
		t.Fatalf("superseded prepare: scanners %+v noop %v changes %q", result.Scanners, result.Noop, result.Changes)
	}
	// Verify reads the runtime and changes nothing.
	if result = run("verify", "ready", ""); len(result.Changes) != 0 || steps != 0 {
		t.Fatalf("verify: steps %d changes %q", steps, result.Changes)
	}
}

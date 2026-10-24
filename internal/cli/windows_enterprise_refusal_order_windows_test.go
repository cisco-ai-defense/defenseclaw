// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/spf13/cobra"

	"github.com/defenseclaw/defenseclaw/internal/enterprisestatus"
	"github.com/defenseclaw/defenseclaw/internal/managed"
	"github.com/defenseclaw/defenseclaw/internal/winpath"
)

// Review P2 (q-win-lifecycle loop round 3), kept after the hook session keys
// were retired: the installer refuses these requests for the recorded
// deployment before it changes anything, and the CLI now refuses them first,
// before its own first change (the hook runtime access repair) and without
// running the installer. A deferred install over an installed deployment
// and, while the deployment waits for its deferred configuration, an install
// or upgrade, or a repair without both --config and --manifest or with
// --no-start, are refused with invalid_arguments; the other requests go on to
// the installer.
func TestWindowsRecordedDeploymentRefusalsComeBeforeAnyChange(t *testing.T) {
	installerRuns := stubWindowsRefusalOrderInstaller(t)
	originalInspector, originalPending := windowsEnterpriseDeploymentInspector, windowsEnterpriseStandaloneTransactionPending
	originalPort, originalStaged, originalEnrolled := windowsEnterpriseConfigAPIPort, windowsEnterpriseStagedConnectors, windowsEnterpriseEnrolledConnectors
	originalHookRuntime := windowsEnterpriseHookRuntimeDir
	t.Cleanup(func() {
		windowsEnterpriseDeploymentInspector, windowsEnterpriseStandaloneTransactionPending = originalInspector, originalPending
		windowsEnterpriseConfigAPIPort, windowsEnterpriseStagedConnectors, windowsEnterpriseEnrolledConnectors = originalPort, originalStaged, originalEnrolled
		windowsEnterpriseHookRuntimeDir = originalHookRuntime
	})
	windowsEnterpriseHookRuntimeDir = func() (string, error) { return "", nil }
	windowsEnterpriseConfigAPIPort = func(string) (int, error) { return 18970, nil }
	windowsEnterpriseStagedConnectors = func(string) ([]string, error) { return []string{"codex"}, nil }
	windowsEnterpriseEnrolledConnectors = func() ([]string, error) { return []string{"codex"}, nil }
	var recorded winpath.EnterpriseDeployment
	pending := false
	windowsEnterpriseDeploymentInspector = func(profile string) (winpath.EnterpriseDeployment, error) {
		if profile != managed.ProfileStandalone {
			return winpath.EnterpriseDeployment{Profile: profile, State: winpath.EnterpriseDeploymentAbsent}, nil
		}
		deployment := recorded
		deployment.Profile = profile
		return deployment, nil
	}
	windowsEnterpriseStandaloneTransactionPending = func() bool { return pending }
	installed := winpath.EnterpriseDeployment{State: winpath.EnterpriseDeploymentInstalled}
	waiting := winpath.EnterpriseDeployment{State: winpath.EnterpriseDeploymentInstalled, DeferredConfigPending: true}
	for _, tc := range []struct {
		name, action      string
		deployment        winpath.EnterpriseDeployment
		pending           bool
		config, manifest  string
		deferred, noStart bool
		refused           bool
	}{
		{name: "deferred install over an installed deployment", action: "install", deployment: installed, deferred: true, refused: true},
		{name: "deferred install over a deferred deployment", action: "install", deployment: waiting, deferred: true, refused: true},
		{name: "install while the deferred configuration waits", action: "install", deployment: waiting,
			config: `C:\stage\config.yaml`, manifest: `C:\stage\targets.yaml`, refused: true},
		{name: "upgrade while the deferred configuration waits", action: "upgrade", deployment: waiting, config: `C:\stage\config.yaml`, refused: true},
		{name: "repair without --manifest while the deferred configuration waits", action: "repair", deployment: waiting,
			config: `C:\stage\config.yaml`, refused: true},
		{name: "repair with --no-start while the deferred configuration waits", action: "repair", deployment: waiting,
			config: `C:\stage\config.yaml`, manifest: `C:\stage\targets.yaml`, noStart: true, refused: true},
		{name: "deferred install over a tombstone", action: "install",
			deployment: winpath.EnterpriseDeployment{State: winpath.EnterpriseDeploymentTombstone}, deferred: true},
		{name: "deferred install over no deployment", action: "install",
			deployment: winpath.EnterpriseDeployment{State: winpath.EnterpriseDeploymentAbsent}, deferred: true},
		{name: "repair that completes the deferred configuration", action: "repair", deployment: waiting,
			config: `C:\stage\config.yaml`, manifest: `C:\stage\targets.yaml`},
		{name: "install over a pending transaction while the deferred configuration waits", action: "install", deployment: waiting, pending: true,
			config: `C:\stage\config.yaml`, manifest: `C:\stage\targets.yaml`},
		{name: "install over an installed deployment", action: "install", deployment: installed,
			config: `C:\stage\config.yaml`, manifest: `C:\stage\targets.yaml`},
	} {
		*installerRuns = 0
		recorded, pending = tc.deployment, tc.pending
		opts := &windowsEnterpriseLifecycleOptions{profile: "standalone", resolvedProfile: "standalone", jsonOutput: true,
			configPath: tc.config, manifestPath: tc.manifest, deferredConfig: tc.deferred, noStart: tc.noStart}
		result, err := runWindowsRefusalOrderAction(t, tc.action, opts)
		if !tc.refused {
			if *installerRuns != 1 {
				t.Fatalf("%s: a run that goes on must reach the installer: installer runs %d, errors %+v (%v)",
					tc.name, *installerRuns, result.Errors, err)
			}
			continue
		}
		if commandExitCode(err) != enterprisestatus.WindowsExitInvalidArgs || len(result.Errors) != 1 || result.Errors[0].Code != "invalid_arguments" ||
			!strings.Contains(result.Errors[0].Message, "nothing was changed") {
			t.Fatalf("%s: refusal %v, errors %+v", tc.name, err, result.Errors)
		}
		if *installerRuns != 0 {
			t.Fatalf("%s: a refusal that changes nothing ran the installer %d time(s)", tc.name, *installerRuns)
		}
	}
}

// Review P2 (q-win-lifecycle loop round 3): an untrusted scanner runtime the
// retire cannot remove is refused, read only, before the run changes
// anything or runs the installer.
func TestWindowsUnremovableScannerRuntimeRefusalComesBeforeAnyChange(t *testing.T) {
	installerRuns := stubWindowsRefusalOrderInstaller(t)
	seamDir, seamCheck := windowsScannerRuntimeDir, windowsScannerRuntimeTreeCheck
	t.Cleanup(func() { windowsScannerRuntimeDir, windowsScannerRuntimeTreeCheck = seamDir, seamCheck })
	runtime := filepath.Join(t.TempDir(), "not-the-scanner-runtime")
	if err := os.MkdirAll(runtime, 0o700); err != nil {
		t.Fatal(err)
	}
	windowsScannerRuntimeDir = func() (string, error) { return runtime, nil }
	windowsScannerRuntimeTreeCheck = func(string) error { return errors.New(`BUILTIN\Users can add files to the python folder`) }
	// With the installer arguments a real run passes: the retire before the
	// services start reads its action from them.
	opts := &windowsEnterpriseLifecycleOptions{profile: "standalone", resolvedProfile: "standalone", jsonOutput: true}
	command := &cobra.Command{}
	var stdout bytes.Buffer
	command.SetOut(&stdout)
	command.SetErr(&bytes.Buffer{})
	err := runWindowsEnterpriseStandaloneAction(context.Background(), command, "install", opts, `C:\stage\install-enterprise.ps1`,
		windowsEnterprisePowerShellArgs("install", opts))
	var result enterprisestatus.Result
	if decodeErr := json.Unmarshal(stdout.Bytes(), &result); decodeErr != nil {
		t.Fatalf("decode %q: %v", stdout.String(), decodeErr)
	}
	if err == nil || !windowsBundleHasCode(result.Errors, "scanner_runtime_untrusted") {
		t.Fatalf("install over an unremovable untrusted scanner runtime: %v, errors %+v", err, result.Errors)
	}
	if *installerRuns != 0 {
		t.Fatalf("a refusal that changes nothing ran the installer %d time(s)", *installerRuns)
	}
}

// runWindowsRefusalOrderAction runs one standalone lifecycle action with the
// installer stubbed (stubWindowsRefusalOrderInstaller) and returns its
// schema-2 result.
func runWindowsRefusalOrderAction(t *testing.T, action string, opts *windowsEnterpriseLifecycleOptions) (enterprisestatus.Result, error) {
	t.Helper()
	command := &cobra.Command{}
	var stdout bytes.Buffer
	command.SetOut(&stdout)
	command.SetErr(&bytes.Buffer{})
	err := runWindowsEnterpriseStandaloneAction(context.Background(), command, action, opts, `C:\stage\install-enterprise.ps1`, nil)
	var result enterprisestatus.Result
	if decodeErr := json.Unmarshal(stdout.Bytes(), &result); decodeErr != nil {
		t.Fatalf("%s: decode %q: %v", action, stdout.String(), decodeErr)
	}
	return result, err
}

// stubWindowsRefusalOrderInstaller fails every installer run and counts the
// runs, and keeps the host's own deployment out of the result.
func stubWindowsRefusalOrderInstaller(t *testing.T) *int {
	t.Helper()
	stubWindowsEnterpriseDeployments(t, nil)
	originalRunner, originalObserver := windowsEnterpriseStandaloneRunner, windowsEnterpriseStandaloneObserver
	t.Cleanup(func() {
		windowsEnterpriseStandaloneRunner, windowsEnterpriseStandaloneObserver = originalRunner, originalObserver
	})
	runs := new(int)
	windowsEnterpriseStandaloneRunner = func(context.Context, *cobra.Command, string, []string) (windowsEnterpriseStandaloneRun, error) {
		*runs++
		return windowsEnterpriseStandaloneRun{}, errors.New("the test runs no installer")
	}
	windowsEnterpriseStandaloneObserver = func(*enterprisestatus.Result, *windowsEnterpriseLifecycleOptions) string { return "" }
	return runs
}

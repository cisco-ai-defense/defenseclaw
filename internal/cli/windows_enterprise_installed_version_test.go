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
)

func TestWindowsFileProductVersionReadsAVersionResource(t *testing.T) {
	path := filepath.Join(os.Getenv("SystemRoot"), "System32", "kernel32.dll")
	version, err := windowsFileProductVersion(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	if _, _, ok := parseWindowsEnterpriseVersion(strings.Fields(version)[0]); !ok {
		t.Fatalf("kernel32 product version %q is not a dotted version", version)
	}
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := windowsFileProductVersion(executable); err == nil {
		t.Fatal("a binary without a version resource reported a version")
	}
}

func TestWindowsEnterpriseRepairRecordsTheInstalledVersion(t *testing.T) {
	original := windowsEnterpriseInstalledProductVersion
	t.Cleanup(func() { windowsEnterpriseInstalledProductVersion = original })
	installed, readErr := "1.3.0", error(nil)
	windowsEnterpriseInstalledProductVersion = func(*windowsEnterpriseLifecycleOptions) (string, error) {
		return installed, readErr
	}
	standalone := &windowsEnterpriseLifecycleOptions{profile: "standalone", resolvedProfile: "standalone", productVersion: "1.4.0", trustMode: "authenticode"}

	got := windowsEnterpriseRepairRecordingOptions("repair", standalone)
	if got == standalone || got.productVersion != "1.3.0" || standalone.productVersion != "1.4.0" {
		t.Fatalf("repair options: got %q (caller %q)", got.productVersion, standalone.productVersion)
	}
	if !containsString(windowsEnterprisePowerShellArgs("repair", got), "1.3.0") {
		t.Fatal("repair arguments do not record the installed version")
	}
	for _, action := range []string{"upgrade", "install", "status", "verify", "ensure"} {
		if windowsEnterpriseRepairRecordingOptions(action, standalone) != standalone {
			t.Fatalf("%s options changed", action)
		}
	}
	secureClient := &windowsEnterpriseLifecycleOptions{profile: "secure_client", resolvedProfile: "secure_client"}
	if windowsEnterpriseRepairRecordingOptions("repair", secureClient) != secureClient {
		t.Fatal("Secure Client repair options changed")
	}
	for _, tc := range []struct {
		version string
		err     error
	}{{"", nil}, {"1.3.0", errors.New("no version resource")}, {"not a version", nil}} {
		installed, readErr = tc.version, tc.err
		if windowsEnterpriseRepairRecordingOptions("repair", standalone) != standalone {
			t.Fatalf("unreadable installed version %q/%v changed the options", tc.version, tc.err)
		}
	}
}

// A failed upgrade whose rollback could not finish leaves a pending
// transaction. The next ensure repairs it on the payload in place (the older
// binaries) and must then still run the upgrade instead of reporting a
// converged host at the new version.
func TestWindowsEnterpriseEnsureUpgradesAfterFinishingAPendingTransaction(t *testing.T) {
	stubWindowsEnterpriseDeployments(t, nil)
	originalRunner := windowsEnterpriseStandaloneRunner
	originalObserver := windowsEnterpriseStandaloneObserver
	originalDrift := windowsEnterpriseEnsureDriftDetector
	originalInstalled := windowsEnterpriseInstalledProductVersion
	t.Cleanup(func() {
		windowsEnterpriseStandaloneRunner = originalRunner
		windowsEnterpriseStandaloneObserver = originalObserver
		windowsEnterpriseEnsureDriftDetector = originalDrift
		windowsEnterpriseInstalledProductVersion = originalInstalled
	})
	windowsEnterpriseEnsureDriftDetector = func(*windowsEnterpriseLifecycleOptions, string) (string, error) { return "", nil }
	windowsEnterpriseInstalledProductVersion = func(*windowsEnterpriseLifecycleOptions) (string, error) { return "1.3.0", nil }
	windowsEnterpriseStandaloneObserver = func(*enterprisestatus.Result, *windowsEnterpriseLifecycleOptions) string { return "" }

	var actions []string
	statusCalls := 0
	windowsEnterpriseStandaloneRunner = func(_ context.Context, _ *cobra.Command, _ string, args []string) (windowsEnterpriseStandaloneRun, error) {
		action := ""
		for index := 0; index+1 < len(args); index++ {
			if args[index] == "-Action" {
				action = args[index+1]
			}
		}
		actions = append(actions, action)
		version := func() string {
			for index := 0; index+1 < len(args); index++ {
				if args[index] == "-ProductVersion" {
					return args[index+1]
				}
			}
			return ""
		}()
		report := map[string]any{"schema_version": 1, "ok": true, "action": strings.ToLower(action), "installed": true, "errors": []string{}}
		switch action {
		case "Status":
			statusCalls++
			if statusCalls == 1 {
				report["transaction_pending"] = true
				report["installed_version"] = "1.4.0"
			} else {
				report["installed_version"] = "1.3.0"
			}
		case "Repair":
			if version != "1.3.0" {
				t.Errorf("repair records version %q, want the installed 1.3.0", version)
			}
			report["installed_version"] = version
		case "Upgrade":
			if version != "1.4.0" || !containsString(args, "-GatewayBinary") {
				t.Errorf("upgrade arguments %q", args)
			}
			report["installed_version"] = version
		default:
			t.Errorf("unexpected installer action %q", action)
		}
		body, _ := json.Marshal(report)
		return windowsEnterpriseStandaloneRun{Output: body}, nil
	}

	command := &cobra.Command{}
	var stdout bytes.Buffer
	command.SetOut(&stdout)
	command.SetErr(&bytes.Buffer{})
	opts := &windowsEnterpriseLifecycleOptions{
		profile: "standalone", resolvedProfile: "standalone", productVersion: "1.4.0", jsonOutput: true, trustMode: "authenticode",
		gatewayBinary: `C:\p\defenseclaw-gateway.exe`, acpBinary: `C:\p\defenseclaw-acp.exe`,
		hookBinary: `C:\p\defenseclaw-hook.exe`, sensorHelperBinary: `C:\p\defenseclaw-sensor-helper.exe`,
	}
	if err := runWindowsEnterpriseStandaloneEnsure(context.Background(), command, opts, `C:\p\install-enterprise.ps1`); err != nil {
		t.Fatal(err)
	}
	if got := strings.Join(actions, ","); got != "Status,Repair,Status,Upgrade" {
		t.Fatalf("installer actions %s", got)
	}
	var result enterprisestatus.Result
	if err := json.Unmarshal(stdout.Bytes(), &result); err != nil {
		t.Fatalf("decode %q: %v", stdout.String(), err)
	}
	codes := []string{}
	for _, warning := range result.Warnings {
		codes = append(codes, warning.Code)
	}
	if !result.OK || result.InstalledVersion != "1.4.0" ||
		!containsString(codes, "recovered_pending_transaction") || !containsString(codes, "ensure_upgrade") {
		t.Fatalf("result ok=%v installed=%q warnings=%v", result.OK, result.InstalledVersion, codes)
	}
}

// A pending repair transaction whose restored release cannot be
// reactivated. Recovery leaves it stopped and the repair fails on purpose;
// ensure then upgrades to this Setup's release in the same invocation. A
// repair that fails for any other reason is reported, not followed.
func TestWindowsEnterpriseEnsureUpgradesAfterARecoveryDeferredActivation(t *testing.T) {
	for _, deferred := range []bool{true, false} {
		stubWindowsEnterpriseDeployments(t, nil)
		originalRunner := windowsEnterpriseStandaloneRunner
		originalObserver := windowsEnterpriseStandaloneObserver
		originalDrift := windowsEnterpriseEnsureDriftDetector
		originalInstalled := windowsEnterpriseInstalledProductVersion
		windowsEnterpriseEnsureDriftDetector = func(*windowsEnterpriseLifecycleOptions, string) (string, error) { return "", nil }
		windowsEnterpriseInstalledProductVersion = func(*windowsEnterpriseLifecycleOptions) (string, error) { return "1.0.48", nil }
		windowsEnterpriseStandaloneObserver = func(*enterprisestatus.Result, *windowsEnterpriseLifecycleOptions) string { return "" }

		var actions []string
		statusCalls := 0
		windowsEnterpriseStandaloneRunner = func(_ context.Context, _ *cobra.Command, _ string, args []string) (windowsEnterpriseStandaloneRun, error) {
			action := ""
			for index := 0; index+1 < len(args); index++ {
				if args[index] == "-Action" {
					action = args[index+1]
				}
			}
			actions = append(actions, action)
			report := map[string]any{"schema_version": 1, "ok": true, "action": strings.ToLower(action), "installed": true, "errors": []string{}}
			switch action {
			case "Status":
				statusCalls++
				report["installed_version"] = "1.0.48"
				report["transaction_pending"] = statusCalls == 1
			case "Repair":
				// The installer's failure document: no installed state.
				report = map[string]any{
					"schema_version": 1, "ok": false, "action": "repair", "transaction_pending": false,
					"error":  "Repair recovered the pending transaction, but its restored release could not be reactivated, so the DefenseClaw services stay stopped.",
					"errors": []string{"Repair recovered the pending transaction, but its restored release could not be reactivated, so the DefenseClaw services stay stopped."},
				}
				if deferred {
					report["recovery_gateway_runs"] = []map[string]any{{
						"action": "service-reactivation", "binary": `C:\Program Files\Cisco\DefenseClaw\bin\defenseclaw-gateway.exe`,
						"source": `C:\p\defenseclaw-gateway.exe`, "sha256": "bb", "trust": "hash_pinned",
						"product_version": "1.0.50", "identity": `NT AUTHORITY\SYSTEM`, "staged_version": "1.0.48",
						"staged_error": "guardian did not publish fresh required coverage", "outcome": "deferred",
					}}
				}
			case "Upgrade":
				report["installed_version"] = "1.0.50"
			default:
				t.Errorf("unexpected installer action %q", action)
			}
			body, _ := json.Marshal(report)
			return windowsEnterpriseStandaloneRun{Output: body}, nil
		}

		command := &cobra.Command{}
		var stdout bytes.Buffer
		command.SetOut(&stdout)
		command.SetErr(&bytes.Buffer{})
		opts := &windowsEnterpriseLifecycleOptions{
			profile: "standalone", resolvedProfile: "standalone", productVersion: "1.0.50", jsonOutput: true, trustMode: "hash_pinned",
			gatewayBinary: `C:\p\defenseclaw-gateway.exe`, acpBinary: `C:\p\defenseclaw-acp.exe`,
			hookBinary: `C:\p\defenseclaw-hook.exe`, sensorHelperBinary: `C:\p\defenseclaw-sensor-helper.exe`,
		}
		err := runWindowsEnterpriseStandaloneEnsure(context.Background(), command, opts, `C:\p\install-enterprise.ps1`)
		windowsEnterpriseStandaloneRunner = originalRunner
		windowsEnterpriseStandaloneObserver = originalObserver
		windowsEnterpriseEnsureDriftDetector = originalDrift
		windowsEnterpriseInstalledProductVersion = originalInstalled

		var result enterprisestatus.Result
		if decodeErr := json.Unmarshal(stdout.Bytes(), &result); decodeErr != nil {
			t.Fatalf("deferred=%v decode %q: %v", deferred, stdout.String(), decodeErr)
		}
		codes := []string{}
		for _, warning := range result.Warnings {
			codes = append(codes, warning.Code)
		}
		if deferred {
			if err != nil || strings.Join(actions, ",") != "Status,Repair,Status,Upgrade" || !result.OK ||
				result.InstalledVersion != "1.0.50" || !containsString(codes, "recovery_activation_deferred") ||
				!containsString(codes, "recovered_pending_transaction") {
				t.Fatalf("deferred: err=%v actions=%v ok=%v installed=%q warnings=%v", err, actions, result.OK, result.InstalledVersion, codes)
			}
			continue
		}
		// A refused repair reports the deployment state a status probe reads,
		// not "not installed".
		if err == nil || strings.Join(actions, ",") != "Status,Repair,Status" || result.OK || !result.Installed {
			t.Fatalf("plain repair failure: err=%v actions=%v ok=%v installed=%v", err, actions, result.OK, result.Installed)
		}
	}
}

// The installed standalone CLI asked for a changed config cannot apply it
// (it has no payload): ensure says to hand the file to Setup /ensure, not
// to pass four internal binary flags it can never have (GAP-0682).
func TestWindowsEnterpriseInstalledCLIEnsureConfigPointsAtSetup(t *testing.T) {
	originalDrift := windowsEnterpriseEnsureDriftDetector
	t.Cleanup(func() { windowsEnterpriseEnsureDriftDetector = originalDrift })
	windowsEnterpriseEnsureDriftDetector = func(*windowsEnterpriseLifecycleOptions, string) (string, error) { return "config", nil }
	status := &windowsEnterpriseInstallerReport{OK: true, Installed: true, InstalledVersion: "1.0.921"}
	opts := &windowsEnterpriseLifecycleOptions{resolvedProfile: "standalone", productVersion: "1.0.921", configPath: `C:\dc-test\cfg.yaml`}
	_, err := planWindowsEnterpriseEnsure(status, opts, "")
	if !errors.Is(err, errWindowsEnterpriseInvalidArguments) || !strings.Contains(err.Error(), "/ensure CONFIG=") ||
		strings.Contains(err.Error(), "--gateway-binary") {
		t.Fatalf("installed CLI ensure --config = %v", err)
	}
	opts.resolvedProfile = "secure_client"
	if _, err := planWindowsEnterpriseEnsure(status, opts, ""); err == nil || !strings.Contains(err.Error(), "--gateway-binary") {
		t.Fatalf("Secure Client ensure --config = %v", err)
	}
}

// A config with connectors: {} for a deployment that protects agents is
// refused before anything changes, so one config push cannot silently take
// DefenseClaw off every user (GAP-0602).
func TestWindowsEnterpriseEnsureRefusesAConnectorlessConfigForAProtectedDeployment(t *testing.T) {
	originalStaged, originalInstalled := windowsEnterpriseStagedConnectors, windowsEnterpriseEnrolledConnectors
	originalDrift := windowsEnterpriseEnsureDriftDetector
	t.Cleanup(func() {
		windowsEnterpriseStagedConnectors, windowsEnterpriseEnrolledConnectors = originalStaged, originalInstalled
		windowsEnterpriseEnsureDriftDetector = originalDrift
	})
	windowsEnterpriseEnsureDriftDetector = func(*windowsEnterpriseLifecycleOptions, string) (string, error) { return "config", nil }
	windowsEnterpriseStagedConnectors = func(string) ([]string, error) { return nil, nil }
	windowsEnterpriseEnrolledConnectors = func() ([]string, error) { return []string{"claudecode", "codex"}, nil }
	status := &windowsEnterpriseInstallerReport{OK: true, Installed: true, InstalledVersion: "1.0.921"}
	opts := &windowsEnterpriseLifecycleOptions{
		resolvedProfile: "standalone", productVersion: "1.0.921", configPath: `C:\stage\cfg-e7f.yaml`,
		gatewayBinary: "g", acpBinary: "a", hookBinary: "h", sensorHelperBinary: "s",
	}
	_, err := planWindowsEnterpriseEnsure(status, opts, "")
	if !errors.Is(err, errWindowsEnterpriseInvalidArguments) || !strings.Contains(err.Error(), "claudecode, codex") {
		t.Fatalf("connectorless config for a protected deployment = %v", err)
	}
	windowsEnterpriseStagedConnectors = func(string) ([]string, error) { return []string{"claudecode"}, nil }
	if plan, err := planWindowsEnterpriseEnsure(status, opts, ""); err != nil || plan.Action != "upgrade" {
		t.Fatalf("config with a connector = %+v, %v", plan, err)
	}
}

// Direct upgrade and repair must refuse a config that would remove every
// connector from a protected standalone deployment, before invoking Setup.
func TestWindowsEnterpriseDirectLifecycleRefusesConnectorlessConfig(t *testing.T) {
	originalStaged, originalInstalled := windowsEnterpriseStagedConnectors, windowsEnterpriseEnrolledConnectors
	originalRunner, originalObserver := windowsEnterpriseStandaloneRunner, windowsEnterpriseStandaloneObserver
	t.Cleanup(func() {
		windowsEnterpriseStagedConnectors, windowsEnterpriseEnrolledConnectors = originalStaged, originalInstalled
		windowsEnterpriseStandaloneRunner, windowsEnterpriseStandaloneObserver = originalRunner, originalObserver
	})
	windowsEnterpriseStagedConnectors = func(string) ([]string, error) { return nil, nil }
	windowsEnterpriseEnrolledConnectors = func() ([]string, error) { return []string{"codex"}, nil }
	windowsEnterpriseStandaloneObserver = func(*enterprisestatus.Result, *windowsEnterpriseLifecycleOptions) string { return "" }
	called := false
	windowsEnterpriseStandaloneRunner = func(context.Context, *cobra.Command, string, []string) (windowsEnterpriseStandaloneRun, error) {
		called = true
		return windowsEnterpriseStandaloneRun{Output: []byte("{}")}, nil
	}

	opts := &windowsEnterpriseLifecycleOptions{
		profile: "standalone", resolvedProfile: "standalone", configPath: "staged.yaml", jsonOutput: true,
	}
	for _, action := range []string{"upgrade", "repair"} {
		t.Run(action, func(t *testing.T) {
			called = false
			command := &cobra.Command{}
			var stdout bytes.Buffer
			command.SetOut(&stdout)
			err := runWindowsEnterpriseStandaloneAction(context.Background(), command, action, opts, "installer.ps1", nil)
			if called {
				t.Fatal("installer ran with connectorless config")
			}
			if !errors.Is(err, errWindowsEnterpriseInvalidArguments) && commandExitCode(err) != enterprisestatus.WindowsExitInvalidArgs {
				t.Fatalf("%s refusal = %v", action, err)
			}
			var result enterprisestatus.Result
			if decodeErr := json.Unmarshal(stdout.Bytes(), &result); decodeErr != nil {
				t.Fatalf("decode refusal: %v", decodeErr)
			}
			if len(result.Errors) != 1 || result.Errors[0].Code != "invalid_arguments" {
				t.Fatalf("%s result errors = %v", action, result.Errors)
			}
		})
	}
}

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

// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/spf13/cobra"

	"github.com/defenseclaw/defenseclaw/internal/enterprisestatus"
	"github.com/defenseclaw/defenseclaw/internal/managed"
	"github.com/defenseclaw/defenseclaw/internal/winpath"
)

// GAP-2061: Setup /repair from another release than the installed one put
// that release's hook program and Codex requirements in place while the
// deployment kept the installed version. It is refused before anything
// changes and names the installed release's Setup /repair and this Setup's
// /ensure (or /upgrade for an older Setup). The same release still repairs,
// and so do the installed CLI (no payload) and a pending recovery.
func TestWindowsEnterpriseSetupRepairFromAnotherReleaseIsRefusedBeforeAnyChange(t *testing.T) {
	originalInspector, originalPending := windowsEnterpriseDeploymentInspector, windowsEnterpriseStandaloneRecoveryPending
	originalRunner, originalObserver := windowsEnterpriseStandaloneRunner, windowsEnterpriseStandaloneObserver
	t.Cleanup(func() {
		windowsEnterpriseDeploymentInspector, windowsEnterpriseStandaloneRecoveryPending = originalInspector, originalPending
		windowsEnterpriseStandaloneRunner, windowsEnterpriseStandaloneObserver = originalRunner, originalObserver
	})
	installed := "1.0.2"
	windowsEnterpriseDeploymentInspector = func(profile string) (winpath.EnterpriseDeployment, error) {
		if profile != managed.ProfileStandalone {
			return winpath.EnterpriseDeployment{Profile: profile, State: winpath.EnterpriseDeploymentAbsent}, nil
		}
		return winpath.EnterpriseDeployment{Profile: profile, State: winpath.EnterpriseDeploymentInstalled, ProductVersion: installed}, nil
	}
	pending := false
	windowsEnterpriseStandaloneRecoveryPending = func(*windowsEnterpriseLifecycleOptions) bool { return pending }
	windowsEnterpriseStandaloneObserver = func(*enterprisestatus.Result, *windowsEnterpriseLifecycleOptions) string { return "" }
	setup := func(version string) *windowsEnterpriseLifecycleOptions {
		return &windowsEnterpriseLifecycleOptions{profile: "standalone", resolvedProfile: "standalone", jsonOutput: true,
			productVersion: version, gatewayBinary: `C:\payload\defenseclaw-gateway.exe`, acpBinary: `C:\payload\defenseclaw-acp.exe`,
			hookBinary: `C:\payload\defenseclaw-hook.exe`, sensorHelperBinary: `C:\payload\defenseclaw-sensor-helper.exe`}
	}

	for _, tc := range []struct{ setup, next string }{{"1.0.5", "/ensure JSON=1 to upgrade"}, {"1.0.1", "/upgrade JSON=1 to downgrade"}} {
		if err := refuseWindowsEnterpriseRepairFromAnotherRelease("repair", setup(tc.setup)); !errors.Is(err, errWindowsEnterpriseInvalidArguments) ||
			!strings.Contains(err.Error(), "Run the 1.0.2 Setup with /repair JSON=1") || !strings.Contains(err.Error(), tc.next) ||
			!strings.Contains(err.Error(), "nothing was changed") {
			t.Fatalf("Setup %s /repair over installed 1.0.2: %v", tc.setup, err)
		}
	}
	for name, opts := range map[string]*windowsEnterpriseLifecycleOptions{
		"same release":               setup("1.0.2"),
		"same release, build suffix": setup("1.0.2+abc"),
		"installed CLI (no payload)": {profile: "standalone", resolvedProfile: "standalone", productVersion: "1.0.5"},
		"unreadable Setup version":   setup("dev"),
		"Secure Client":              {profile: "secure_client", resolvedProfile: "secure_client", productVersion: "1.0.5"},
	} {
		if err := refuseWindowsEnterpriseRepairFromAnotherRelease("repair", opts); err != nil {
			t.Fatalf("%s refused: %v", name, err)
		}
	}
	for _, action := range []string{"upgrade", "ensure", "install", "uninstall", "status", "verify"} {
		if err := refuseWindowsEnterpriseRepairFromAnotherRelease(action, setup("1.0.5")); err != nil {
			t.Fatalf("%s refused: %v", action, err)
		}
	}
	pending = true
	if err := refuseWindowsEnterpriseRepairFromAnotherRelease("repair", setup("1.0.5")); err != nil {
		t.Fatalf("recovery of a pending transaction refused: %v", err)
	}
	pending = false
	installed = "unknown"
	if err := refuseWindowsEnterpriseRepairFromAnotherRelease("repair", setup("1.0.5")); err != nil {
		t.Fatalf("unreadable installed version refused: %v", err)
	}
	installed = "1.0.2"

	called := false
	windowsEnterpriseStandaloneRunner = func(context.Context, *cobra.Command, string, []string) (windowsEnterpriseStandaloneRun, error) {
		called = true
		return windowsEnterpriseStandaloneRun{Output: []byte("{}")}, nil
	}
	command := &cobra.Command{}
	var stdout bytes.Buffer
	command.SetOut(&stdout)
	err := runWindowsEnterpriseStandaloneAction(context.Background(), command, "repair", setup("1.0.5"), "installer.ps1", nil)
	if called {
		t.Fatal("the installer ran for a Setup /repair of another release")
	}
	if !errors.Is(err, errWindowsEnterpriseInvalidArguments) && commandExitCode(err) != enterprisestatus.WindowsExitInvalidArgs {
		t.Fatalf("refusal = %v", err)
	}
	var result enterprisestatus.Result
	if decodeErr := json.Unmarshal(stdout.Bytes(), &result); decodeErr != nil {
		t.Fatalf("decode refusal: %v (%s)", decodeErr, stdout.String())
	}
	if len(result.Errors) != 1 || result.Errors[0].Code != "invalid_arguments" || !strings.Contains(result.Errors[0].Message, "1.0.2 Setup") {
		t.Fatalf("result errors = %+v", result.Errors)
	}
}

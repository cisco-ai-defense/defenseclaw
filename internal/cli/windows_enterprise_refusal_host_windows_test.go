// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package cli

import (
	"bytes"
	"encoding/json"
	"errors"
	"testing"

	"github.com/spf13/cobra"

	"github.com/defenseclaw/defenseclaw/internal/enterprisestatus"
	"github.com/defenseclaw/defenseclaw/internal/winpath"
)

// GAP-0036: an ensure refused because its --config does not exist changed
// nothing, so its result reports the installed deployment and its services,
// with the health_not_checked warning, not installed=false.
func TestWindowsEnterpriseMissingConfigRefusalReportsTheInstalledDeployment(t *testing.T) {
	stubWindowsEnterpriseDeployments(t, map[string]winpath.EnterpriseDeploymentState{"standalone": winpath.EnterpriseDeploymentInstalled})
	originalElevated, originalServiceState := windowsEnterpriseIsElevated, windowsEnterpriseServiceState
	t.Cleanup(func() {
		windowsEnterpriseIsElevated, windowsEnterpriseServiceState = originalElevated, originalServiceState
	})
	windowsEnterpriseIsElevated = func() bool { return true }
	windowsEnterpriseServiceState = func(string) string { return "running" }
	var stdout bytes.Buffer
	command := &cobra.Command{}
	command.SetOut(&stdout)
	command.SetErr(&bytes.Buffer{})
	opts := &windowsEnterpriseLifecycleOptions{profile: "standalone", jsonOutput: true}
	cause := errors.New(`open managed config C:\lane\missing.yaml: open C:\lane\missing.yaml: The system cannot find the file specified.`)
	if err := writeWindowsEnterpriseStandalonePreflightFailure(command, "ensure", opts, cause); err == nil {
		t.Fatal("the refusal returned no error")
	}
	var result enterprisestatus.Result
	if err := json.Unmarshal(stdout.Bytes(), &result); err != nil {
		t.Fatalf("decode: %v: %s", err, stdout.String())
	}
	if !result.Installed || len(result.Services) == 0 || !windowsBundleHasCode(result.Errors, "preflight_failed") ||
		!windowsEnterpriseResultHasWarning(&result, windowsEnterpriseHealthNotChecked) {
		t.Fatalf("installed=%t services=%d errors=%+v warnings=%+v, want the installed deployment with health_not_checked",
			result.Installed, len(result.Services), result.Errors, result.Warnings)
	}
}

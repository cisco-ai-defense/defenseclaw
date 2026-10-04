// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"bytes"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/spf13/cobra"

	"github.com/defenseclaw/defenseclaw/internal/enterprisestatus"
	"github.com/defenseclaw/defenseclaw/internal/inventory"
	"github.com/defenseclaw/defenseclaw/internal/managed"
)

// GAP-2456: `enterprise windows discovery --user <unknown> --json` and a
// gateway it cannot read printed no JSON at all, only cobra's "Error:" line.
// They now answer with one JSON document (errors[] with a code, exit_code)
// and a coded error the command silences; text mode keeps the sentence.
func TestWindowsDiscoveryJSONCallerErrorsPrintJSON(t *testing.T) {
	stubEnterpriseDiscoveryRuntime(t, nil, errors.New("stub"))
	previous := enterpriseDiscoveryGatewayReport
	t.Cleanup(func() { enterpriseDiscoveryGatewayReport = previous })
	gatewayErr := error(nil)
	enterpriseDiscoveryGatewayReport = func() (enterpriseGatewayAIUsage, string, error) {
		return enterpriseGatewayAIUsage{Enabled: true, Signals: []inventory.AISignal{
			{Name: "Amp", Category: "supported_connector", UserName: "dcw-std1", UserID: "S-1-5-21-1"},
		}}, "127.0.0.1:18970", gatewayErr
	}
	for _, tc := range []struct {
		name, code, text string
		gateway          error
	}{
		{"unknown user", "account_not_found", `no AI Discovery signal for account "nosuchuser"`, nil},
		{"gateway down", "error", "read the AI Discovery inventory: the gateway at 127.0.0.1:18970 did not answer", errors.New("the gateway at 127.0.0.1:18970 did not answer")},
	} {
		gatewayErr = tc.gateway
		var text bytes.Buffer
		err := writeWindowsEnterpriseDiscovery(&text, "nosuchuser", false)
		if text.Len() != 0 || err == nil || !strings.HasPrefix(err.Error(), tc.text) || commandExitCode(err) != 1 {
			t.Fatalf("%s text: output %q, error %v", tc.name, text.String(), err)
		}
		var out bytes.Buffer
		err = writeWindowsEnterpriseDiscovery(&out, "nosuchuser", true)
		var result struct {
			OK       bool                       `json:"ok"`
			Errors   []enterprisestatus.Message `json:"errors"`
			ExitCode int                        `json:"exit_code"`
		}
		if jsonErr := json.Unmarshal(out.Bytes(), &result); jsonErr != nil || result.OK || result.ExitCode != 1 ||
			len(result.Errors) != 1 || result.Errors[0].Code != tc.code || !strings.HasPrefix(result.Errors[0].Message, tc.text) {
			t.Fatalf("%s --json: stdout %q (%v)", tc.name, out.String(), jsonErr)
		}
		command := &cobra.Command{}
		silenceJSONReportedError(command, true, err)
		if !command.SilenceErrors || commandExitCode(err) != 1 {
			t.Fatalf("%s --json: the Error line is not silenced (exit %d)", tc.name, commandExitCode(err))
		}
	}
}

// GAP-2456: `enterprise hooks status --json` run by hand on a managed
// Windows computer failed in its pre-run (no per-user config) and printed
// only the "Error:" line. It now prints its report with ok=false and the
// reason in errors[]; under the deployment-mode pin (the services and the
// lifecycle) the output is unchanged.
func TestEnterpriseHooksStatusPreRunFailurePrintsJSON(t *testing.T) {
	previousPreflight, previousPreRun, previousJSON := enterpriseHooksPlatformPreflight, enterpriseHooksRootPersistentPreRun, enterpriseHookJSON
	t.Cleanup(func() {
		enterpriseHooksPlatformPreflight, enterpriseHooksRootPersistentPreRun, enterpriseHookJSON = previousPreflight, previousPreRun, previousJSON
		enterpriseHooksStatusCmd.SetOut(nil)
		enterpriseHooksStatusCmd.SilenceErrors = false
	})
	answer := errors.New("this computer's DefenseClaw is managed by your organization (HKLM), so `enterprise hooks status` has no per-user deployment to check")
	enterpriseHooksPlatformPreflight = func() error { return nil }
	enterpriseHooksRootPersistentPreRun = func(*cobra.Command, []string) error { return answer }

	for _, tc := range []struct {
		name     string
		json     bool
		pin      string
		wantJSON bool
	}{
		{"text", false, "", false},
		{"json", true, "", true},
		{"json under the managed pin", true, managed.DeploymentModeManagedEnterprise, false},
	} {
		t.Setenv(managed.DeploymentModeEnv, tc.pin)
		enterpriseHookJSON = tc.json
		enterpriseHooksStatusCmd.SilenceErrors = false
		var out bytes.Buffer
		enterpriseHooksStatusCmd.SetOut(&out)
		err := enterpriseHooksCmd.PersistentPreRunE(enterpriseHooksStatusCmd, nil)
		if !errors.Is(err, answer) {
			t.Fatalf("%s: error %v", tc.name, err)
		}
		if !tc.wantJSON {
			if out.Len() != 0 || enterpriseHooksStatusCmd.SilenceErrors {
				t.Fatalf("%s: stdout %q, silenced %t", tc.name, out.String(), enterpriseHooksStatusCmd.SilenceErrors)
			}
			continue
		}
		var report enterpriseHookStatusReport
		if jsonErr := json.Unmarshal(out.Bytes(), &report); jsonErr != nil || report.OK ||
			len(report.Errors) != 1 || report.Errors[0] != answer.Error() || !enterpriseHooksStatusCmd.SilenceErrors {
			t.Fatalf("%s: stdout %q (%v), silenced %t", tc.name, out.String(), jsonErr, enterpriseHooksStatusCmd.SilenceErrors)
		}
	}
}

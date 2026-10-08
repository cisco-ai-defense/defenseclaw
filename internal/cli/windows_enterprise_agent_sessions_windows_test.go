// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package cli

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/enterprisestatus"
	"github.com/defenseclaw/defenseclaw/internal/inventory"
	"github.com/defenseclaw/defenseclaw/internal/managed"
)

// GAP-0967: the ensure that activates DefenseClaw, and every status after
// it, names the agent sessions an account started before the activation;
// sessions started later, and service accounts, are not named.
func TestWindowsStandaloneNamesAgentSessionsStartedBeforeActivation(t *testing.T) {
	metadata := filepath.Join(t.TempDir(), "deployment.json")
	if err := os.WriteFile(metadata, []byte(`{"installed":true}`), 0o600); err != nil {
		t.Fatal(err)
	}
	activated := time.Date(2026, 10, 8, 14, 40, 0, 0, time.UTC)
	previousMetadata, previousProcesses := windowsEnterpriseActivationMetadata, windowsEnterpriseAgentProcesses
	t.Cleanup(func() {
		windowsEnterpriseActivationMetadata, windowsEnterpriseAgentProcesses = previousMetadata, previousProcesses
	})
	windowsEnterpriseActivationMetadata = func() (string, bool) { return metadata, true }
	windowsEnterpriseAgentProcesses = func() ([]inventory.AgentProcess, error) {
		return []inventory.AgentProcess{
			{PID: 41, Connector: "cursor", User: `DCFC\dcw-std1`, StartedAt: activated.Add(-time.Hour)},
			{PID: 42, Connector: "claudecode", User: `DCFC\dcw-std1`, StartedAt: activated.Add(time.Minute)},
			{PID: 43, Connector: "codex", User: `NT AUTHORITY\SYSTEM`, StartedAt: activated.Add(-time.Hour)},
		}, nil
	}
	check := func(result *enterprisestatus.Result) {
		t.Helper()
		var named []string
		for _, warning := range result.Warnings {
			if warning.Code == windowsAgentSessionsRestartCode {
				named = append(named, warning.Message)
			}
		}
		if len(named) != 1 || !strings.Contains(named[0], `user DCFC\dcw-std1 runs cursor (pid 41), started before`) ||
			strings.Contains(named[0], "pid 42") {
			t.Fatalf("%s warnings = %+v, want cursor (pid 41) of dcw-std1 only", result.Action, result.Warnings)
		}
	}
	ensure := enterprisestatus.New("ensure", managed.ProfileStandalone, "windows", "1.0.0")
	ensure.Installed = true
	applyWindowsEnterpriseAgentSessions(ensure, &windowsEnterpriseLifecycleOptions{activationStartedAt: activated})
	check(ensure)
	status := enterprisestatus.New("status", managed.ProfileStandalone, "windows", "1.0.0")
	status.Installed = true
	applyWindowsEnterpriseAgentSessions(status, &windowsEnterpriseLifecycleOptions{})
	check(status)
}

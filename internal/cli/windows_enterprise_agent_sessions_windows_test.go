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

// A staged install must retain enough state for the first successful repair
// to date activation, without dating unrelated upgrades from old releases.
func TestWindowsStandaloneStagedInstallRecordsActivationOnRepair(t *testing.T) {
	metadata := filepath.Join(t.TempDir(), "deployment.json")
	if err := os.WriteFile(metadata, []byte(`{"installed":true}`), 0o600); err != nil {
		t.Fatal(err)
	}
	previousMetadata, previousProcesses := windowsEnterpriseActivationMetadata, windowsEnterpriseAgentProcesses
	t.Cleanup(func() {
		windowsEnterpriseActivationMetadata, windowsEnterpriseAgentProcesses = previousMetadata, previousProcesses
	})
	windowsEnterpriseActivationMetadata = func() (string, bool) { return metadata, true }
	started := time.Date(2026, 10, 8, 14, 0, 0, 0, time.UTC)
	windowsEnterpriseAgentProcesses = func() ([]inventory.AgentProcess, error) {
		return []inventory.AgentProcess{{PID: 41, Connector: "cursor", User: `DCFC\dcw-std1`, StartedAt: started}}, nil
	}
	staged := enterprisestatus.New("install", managed.ProfileStandalone, "windows", "1.0.0")
	staged.Installed = true
	applyWindowsEnterpriseAgentSessions(staged, &windowsEnterpriseLifecycleOptions{activationStartedAt: started.Add(time.Minute), noStart: true})
	if len(staged.Warnings) != 0 {
		t.Fatalf("staged install warnings = %+v", staged.Warnings)
	}
	path := filepath.Join(filepath.Dir(metadata), windowsEnterpriseActivationFileName)
	if data, err := os.ReadFile(path); err != nil || !strings.Contains(string(data), `"pending":true`) {
		t.Fatalf("staged activation record = %q, err = %v", data, err)
	}
	repaired := enterprisestatus.New("repair", managed.ProfileStandalone, "windows", "1.0.0")
	repaired.Installed = true
	repaired.Readiness.Gateway = true
	applyWindowsEnterpriseAgentSessions(repaired, &windowsEnterpriseLifecycleOptions{
		activationStartedAt: started.Add(2 * time.Minute), installedBeforeRun: true,
	})
	if len(repaired.Warnings) != 1 || repaired.Warnings[0].Code != windowsAgentSessionsRestartCode {
		t.Fatalf("repair warnings = %+v", repaired.Warnings)
	}
	status := enterprisestatus.New("status", managed.ProfileStandalone, "windows", "1.0.0")
	status.Installed = true
	applyWindowsEnterpriseAgentSessions(status, &windowsEnterpriseLifecycleOptions{})
	if len(status.Warnings) != 1 || status.Warnings[0].Code != windowsAgentSessionsRestartCode {
		t.Fatalf("status warnings = %+v", status.Warnings)
	}
}

// GAP-1193: a full upgrade can enable hooks for a session opened after the
// original install. The upgrade and later status must both ask for a restart.
func TestWindowsStandaloneUpgradeNamesNewConnectorSessions(t *testing.T) {
	metadata := filepath.Join(t.TempDir(), "deployment.json")
	if err := os.WriteFile(metadata, []byte("{}"), 0o600); err != nil {
		t.Fatal(err)
	}
	installedAt := time.Date(2026, 10, 8, 14, 0, 0, 0, time.UTC)
	upgradedAt := installedAt.Add(2 * time.Hour)
	previousMetadata, previousProcesses := windowsEnterpriseActivationMetadata, windowsEnterpriseAgentProcesses
	previousConnectors := windowsEnterpriseEnrolledConnectors
	t.Cleanup(func() {
		windowsEnterpriseActivationMetadata, windowsEnterpriseAgentProcesses = previousMetadata, previousProcesses
		windowsEnterpriseEnrolledConnectors = previousConnectors
	})
	windowsEnterpriseActivationMetadata = func() (string, bool) { return metadata, true }
	windowsEnterpriseEnrolledConnectors = func() ([]string, error) { return []string{"codex", "claudecode"}, nil }
	windowsEnterpriseAgentProcesses = func() ([]inventory.AgentProcess, error) {
		return []inventory.AgentProcess{{
			PID: 42, Connector: "claudecode", User: "DCFC\\dcw-std1",
			StartedAt: installedAt.Add(time.Hour),
		}}, nil
	}
	first := enterprisestatus.New("install", managed.ProfileStandalone, "windows", "1.0.0")
	first.Installed = true
	applyWindowsEnterpriseAgentSessions(first, &windowsEnterpriseLifecycleOptions{activationStartedAt: installedAt})
	upgrade := enterprisestatus.New("upgrade", managed.ProfileStandalone, "windows", "1.0.0")
	upgrade.Installed = true
	upgrade.Readiness.Gateway = true
	applyWindowsEnterpriseAgentSessions(upgrade, &windowsEnterpriseLifecycleOptions{
		activationStartedAt: upgradedAt, installedBeforeRun: true,
		previousConnectors: []string{"codex"}, previousConnectorsKnown: true,
	})
	status := enterprisestatus.New("status", managed.ProfileStandalone, "windows", "1.0.0")
	status.Installed = true
	for _, result := range []*enterprisestatus.Result{upgrade, status} {
		if result == status {
			applyWindowsEnterpriseAgentSessions(result, &windowsEnterpriseLifecycleOptions{})
		}
		if len(result.Warnings) != 1 || result.Warnings[0].Code != windowsAgentSessionsRestartCode ||
			!strings.Contains(result.Warnings[0].Message, "claudecode (pid 42)") {
			t.Fatalf("%s warnings = %+v, want restart for existing Claude Code session", result.Action, result.Warnings)
		}
	}
}

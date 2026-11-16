// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package cli

import (
	"encoding/json"
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
	stubWindowsEnterpriseActivationNow(t, activated)
	applyWindowsEnterpriseAgentSessions(ensure, &windowsEnterpriseLifecycleOptions{activationStartedAt: activated})
	check(ensure)
	status := enterprisestatus.New("status", managed.ProfileStandalone, "windows", "1.0.0")
	status.Installed = true
	applyWindowsEnterpriseAgentSessions(status, &windowsEnterpriseLifecycleOptions{})
	check(status)
}

func stubWindowsEnterpriseActivationNow(t *testing.T, at time.Time) {
	t.Helper()
	previous := windowsEnterpriseActivationNow
	t.Cleanup(func() { windowsEnterpriseActivationNow = previous })
	windowsEnterpriseActivationNow = func() time.Time { return at }
}

// GAP-1352: an agent started after the install began but before it
// installed the hooks never read them; the activation is dated when the
// install finished, so that session is named too.
func TestWindowsStandaloneNamesAgentSessionStartedDuringInstall(t *testing.T) {
	metadata := filepath.Join(t.TempDir(), "deployment.json")
	if err := os.WriteFile(metadata, []byte(`{"installed":true}`), 0o600); err != nil {
		t.Fatal(err)
	}
	started := time.Date(2026, 10, 8, 14, 0, 0, 0, time.UTC)
	previousMetadata, previousProcesses := windowsEnterpriseActivationMetadata, windowsEnterpriseAgentProcesses
	t.Cleanup(func() {
		windowsEnterpriseActivationMetadata, windowsEnterpriseAgentProcesses = previousMetadata, previousProcesses
	})
	windowsEnterpriseActivationMetadata = func() (string, bool) { return metadata, true }
	windowsEnterpriseAgentProcesses = func() ([]inventory.AgentProcess, error) {
		return []inventory.AgentProcess{{PID: 41, Connector: "codex", User: `DCFC\dcw-std1`, StartedAt: started.Add(time.Minute)}}, nil
	}
	stubWindowsEnterpriseActivationNow(t, started.Add(5*time.Minute))
	install := enterprisestatus.New("install", managed.ProfileStandalone, "windows", "1.0.0")
	install.Installed = true
	applyWindowsEnterpriseAgentSessions(install, &windowsEnterpriseLifecycleOptions{activationStartedAt: started})
	if len(install.Warnings) != 1 || install.Warnings[0].Code != windowsAgentSessionsRestartCode ||
		!strings.Contains(install.Warnings[0].Message, "codex (pid 41)") {
		t.Fatalf("install warnings = %+v, want restart for the session started during the install", install.Warnings)
	}
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
	stubWindowsEnterpriseActivationNow(t, started.Add(2*time.Minute))
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

// GAP-1366: an ensure that rolled back a failed initial install (which had
// written deployment.json, so the host looked installed before the run) and
// then installed is a first install: it records the activation and names the
// sessions started before it. An upgrade with the same inputs and no
// recovery, from a build that predates activation-state.json, names none.
func TestWindowsStandaloneRecoveredFirstInstallRecordsActivation(t *testing.T) {
	installedAt := time.Date(2026, 10, 13, 9, 0, 0, 0, time.UTC)
	previousMetadata, previousProcesses := windowsEnterpriseActivationMetadata, windowsEnterpriseAgentProcesses
	previousConnectors, previousTargets := windowsEnterpriseEnrolledConnectors, windowsEnterpriseEnrolledTargets
	t.Cleanup(func() {
		windowsEnterpriseActivationMetadata, windowsEnterpriseAgentProcesses = previousMetadata, previousProcesses
		windowsEnterpriseEnrolledConnectors, windowsEnterpriseEnrolledTargets = previousConnectors, previousTargets
	})
	windowsEnterpriseEnrolledConnectors = func() ([]string, error) { return []string{"claudecode"}, nil }
	windowsEnterpriseEnrolledTargets = func() (map[string]bool, error) { return map[string]bool{}, nil }
	windowsEnterpriseAgentProcesses = func() ([]inventory.AgentProcess, error) {
		return []inventory.AgentProcess{{
			PID: 51, Connector: "claudecode", User: `DCFC\dcw-std1`, StartedAt: installedAt.Add(-time.Hour),
		}}, nil
	}
	for _, recovered := range []bool{true, false} {
		dir := t.TempDir()
		metadata := filepath.Join(dir, "deployment.json")
		if err := os.WriteFile(metadata, []byte("{}"), 0o600); err != nil {
			t.Fatal(err)
		}
		windowsEnterpriseActivationMetadata = func() (string, bool) { return metadata, true }
		result := enterprisestatus.New("ensure", managed.ProfileStandalone, "windows", "1.0.2")
		result.Installed = true
		result.Readiness.Gateway = true
		if recovered {
			result.AddWarning(windowsEnterpriseRecoveredFailedInstallCode, "ensure rolled back a failed initial install before installing")
		}
		stubWindowsEnterpriseActivationNow(t, installedAt)
		applyWindowsEnterpriseAgentSessions(result, &windowsEnterpriseLifecycleOptions{
			activationStartedAt: installedAt, installedBeforeRun: true,
			previousConnectors: []string{"claudecode"}, previousConnectorsKnown: true,
			previousTargets: map[string]bool{}, previousTargetsKnown: true,
		})
		var named []string
		for _, warning := range result.Warnings {
			if warning.Code == windowsAgentSessionsRestartCode {
				named = append(named, warning.Message)
			}
		}
		record, recordErr := os.ReadFile(filepath.Join(dir, windowsEnterpriseActivationFileName))
		if recovered {
			if len(named) != 1 || !strings.Contains(named[0], "claudecode (pid 51)") {
				t.Fatalf("recovered first install warnings = %+v, want the restart warning for pid 51", result.Warnings)
			}
			if recordErr != nil || !strings.Contains(string(record), `"activated_at"`) {
				t.Fatalf("recovered first install activation record = %q (%v), want activated_at", record, recordErr)
			}
			continue
		}
		if len(named) != 0 {
			t.Fatalf("upgrade without a record warnings = %+v, want no restart warning", result.Warnings)
		}
		if recordErr == nil && strings.Contains(string(record), `"activated_at"`) {
			t.Fatalf("upgrade without a record wrote activation %q", record)
		}
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
	stubWindowsEnterpriseActivationNow(t, installedAt)
	applyWindowsEnterpriseAgentSessions(first, &windowsEnterpriseLifecycleOptions{activationStartedAt: installedAt})
	upgrade := enterprisestatus.New("upgrade", managed.ProfileStandalone, "windows", "1.0.0")
	upgrade.Installed = true
	upgrade.Readiness.Gateway = true
	stubWindowsEnterpriseActivationNow(t, upgradedAt)
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

func TestWindowsStandaloneUsesOwnerSIDForPreActivationSession(t *testing.T) {
	const sid = "S-1-5-21-1-2-3-1001"
	activated := time.Date(2026, 10, 13, 9, 0, 0, 0, time.UTC)
	dir := t.TempDir()
	metadata := filepath.Join(dir, "deployment.json")
	record, err := json.Marshal(windowsEnterpriseActivationRecord{ActivatedAt: activated.Format(time.RFC3339Nano)})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, windowsEnterpriseActivationFileName), record, 0o600); err != nil {
		t.Fatal(err)
	}
	previousMetadata, previousProcesses := windowsEnterpriseActivationMetadata, windowsEnterpriseAgentProcesses
	previousRestores, previousSID := windowsEnterpriseGuardianRestores, windowsEnterpriseAccountSID
	t.Cleanup(func() {
		windowsEnterpriseActivationMetadata, windowsEnterpriseAgentProcesses = previousMetadata, previousProcesses
		windowsEnterpriseGuardianRestores, windowsEnterpriseAccountSID = previousRestores, previousSID
	})
	windowsEnterpriseActivationMetadata = func() (string, bool) { return metadata, true }
	windowsEnterpriseAgentProcesses = func() ([]inventory.AgentProcess, error) {
		return []inventory.AgentProcess{{PID: 41, Connector: "codex", OwnerSID: sid, StartedAt: activated.Add(-time.Hour)}}, nil
	}
	windowsEnterpriseGuardianRestores = func() (map[string]time.Time, error) { return nil, nil }
	lookups := 0
	windowsEnterpriseAccountSID = func(string) string { lookups++; return "" }

	result := enterprisestatus.New("status", managed.ProfileStandalone, "windows", "1.0.2")
	result.Installed = true
	applyWindowsEnterpriseAgentSessions(result, &windowsEnterpriseLifecycleOptions{})
	if len(result.Warnings) != 1 || result.Warnings[0].Code != windowsAgentSessionsRestartCode ||
		!strings.Contains(result.Warnings[0].Message, "user "+sid+" runs codex (pid 41), started before") || lookups != 0 {
		t.Fatalf("session owner SID warning = %+v, account lookups = %d", result.Warnings, lookups)
	}
}

func TestWindowsStandaloneUnknownOwnerKeepsRestartStatusIncomplete(t *testing.T) {
	metadata := filepath.Join(t.TempDir(), "deployment.json")
	previousMetadata, previousProcesses := windowsEnterpriseActivationMetadata, windowsEnterpriseAgentProcesses
	previousRestores, previousConnectors := windowsEnterpriseGuardianRestores, windowsEnterpriseEnrolledConnectors
	t.Cleanup(func() {
		windowsEnterpriseActivationMetadata, windowsEnterpriseAgentProcesses = previousMetadata, previousProcesses
		windowsEnterpriseGuardianRestores, windowsEnterpriseEnrolledConnectors = previousRestores, previousConnectors
	})
	windowsEnterpriseActivationMetadata = func() (string, bool) { return metadata, true }
	windowsEnterpriseGuardianRestores = func() (map[string]time.Time, error) { return nil, nil }
	windowsEnterpriseEnrolledConnectors = func() ([]string, error) { return []string{"codex", "claudecode"}, nil }
	started := time.Date(2026, 10, 13, 9, 0, 0, 0, time.UTC)
	windowsEnterpriseAgentProcesses = func() ([]inventory.AgentProcess, error) {
		return []inventory.AgentProcess{
			{PID: 44, Connector: "codex"},
			{PID: 43, Connector: "codex", StartedAt: started},
			{PID: 41, Connector: "claudecode", StartedAt: started},
			{PID: 42, Connector: "codex", OwnerSID: "S-1-5-18", StartedAt: started},
		}, nil
	}
	result := enterprisestatus.New("status", managed.ProfileStandalone, "windows", "1.0.2")
	result.Installed, result.SecurityComplete = true, true
	applyWindowsEnterpriseAgentSessions(result, &windowsEnterpriseLifecycleOptions{})
	if result.SecurityComplete || len(result.Warnings) != 2 {
		t.Fatalf("unknown-owner restart status = %+v, security_complete = %t", result.Warnings, result.SecurityComplete)
	}
	first, second := result.Warnings[0], result.Warnings[1]
	if first.Code != windowsAgentSessionsRestartCode || second.Code != windowsAgentSessionsRestartCode ||
		!strings.HasPrefix(first.Message, "restart status unknown:") ||
		!strings.HasPrefix(second.Message, "restart status unknown:") ||
		!strings.Contains(first.Message, "claudecode (pid 41)") ||
		!strings.Contains(second.Message, "codex (pid 43), codex (pid 44)") ||
		!strings.Contains(second.Message, "account") ||
		!strings.Contains(second.Message, "could not be identified") ||
		!strings.Contains(second.Message, "restarted") ||
		strings.Contains(second.Message, "pid 42") {
		t.Fatalf("unknown-owner warnings are incomplete or unordered: %+v", result.Warnings)
	}
}

func TestWindowsServiceSIDMatchesServiceIdentities(t *testing.T) {
	for _, sid := range []string{"S-1-5-18", "S-1-5-19", "S-1-5-20", "S-1-5-80-1", "S-1-5-90-1", "S-1-5-96-1", "S-1-5-82-1-2-3-4-5"} {
		if !windowsServiceSID(sid) {
			t.Errorf("service SID %q was treated as an interactive account", sid)
		}
	}
	for _, sid := range []string{"S-1-5-21-1-2-3-1001", "S-1-12-1-1111111111-2222222222-333333333-44", ""} {
		if windowsServiceSID(sid) {
			t.Errorf("SID %q was treated as a service", sid)
		}
	}
}

func TestWindowsHotConnectorEnableJudgesUnknownAndSIDOwners(t *testing.T) {
	previous := []byte("guardrail:\n  connectors:\n    codex:\n      enabled: false\n    claudecode: {}\n")
	next := []byte("guardrail:\n  connectors:\n    codex:\n      enabled: true\n    claudecode: {}\n")
	changedAt := time.Date(2026, 10, 13, 9, 0, 0, 0, time.UTC)
	const sid = "S-1-5-21-1-2-3-1001"
	previousProcesses := windowsEnterpriseAgentProcesses
	t.Cleanup(func() { windowsEnterpriseAgentProcesses = previousProcesses })
	windowsEnterpriseAgentProcesses = func() ([]inventory.AgentProcess, error) {
		return []inventory.AgentProcess{
			{PID: 41, Connector: "codex", OwnerSID: sid, StartedAt: changedAt.Add(-time.Minute)},
			{PID: 43, Connector: "codex"},
			{PID: 42, Connector: "codex", StartedAt: changedAt.Add(-time.Minute)},
			{PID: 44, Connector: "codex", OwnerSID: "S-1-5-80-1", StartedAt: changedAt.Add(-time.Minute)},
			{PID: 45, Connector: "claudecode", StartedAt: changedAt.Add(-time.Minute)},
		}, nil
	}
	result := enterprisestatus.New("ensure", managed.ProfileStandalone, "windows", "1.0.2")
	result.SecurityComplete = true
	warnWindowsEnterpriseHotAgentSessions(result, previous, next, changedAt)
	if result.SecurityComplete || len(result.Warnings) != 2 ||
		result.Warnings[0].Code != windowsAgentSessionsRestartCode ||
		!strings.Contains(result.Warnings[0].Message, "user "+sid+" runs codex (pid 41)") ||
		result.Warnings[1].Code != windowsAgentSessionsRestartCode ||
		!strings.HasPrefix(result.Warnings[1].Message, "restart status unknown:") ||
		!strings.Contains(result.Warnings[1].Message, "codex (pid 42), codex (pid 43)") ||
		strings.Contains(result.Warnings[1].Message, "pid 44") ||
		strings.Contains(result.Warnings[1].Message, "pid 45") {
		t.Fatalf("hot connector restart warnings = %+v, security_complete = %t", result.Warnings, result.SecurityComplete)
	}
}

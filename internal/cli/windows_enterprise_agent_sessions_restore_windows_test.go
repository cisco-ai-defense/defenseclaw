// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package cli

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/enterprisestatus"
	"github.com/defenseclaw/defenseclaw/internal/inventory"
	"github.com/defenseclaw/defenseclaw/internal/managed"
)

// GAP-0440: after the hook guardian put back the Hermes hooks a standard
// user had emptied, status and verify name that user's Hermes sessions
// started before the restore and report security_complete false; a session
// started after it, the user's other connectors and other users are not
// named, and a restarted session clears the warning. A Codex session is not
// named after its runtime was put back: Codex reads its hooks from the
// machine requirements, which the user cannot change. A deployment without
// an activation record (an upgrade from a build that predates it) is
// checked too.
func TestWindowsStandaloneNamesSessionsStartedBeforeAGuardianRestore(t *testing.T) {
	const std1, std2 = `DCFC\dcw-std1`, `DCFC\dcw-std2`
	const std1SID, std2SID = "S-1-5-21-1-2-3-1001", "S-1-5-21-1-2-3-1002"
	activated := time.Date(2026, 10, 13, 9, 0, 0, 0, time.UTC)
	restoredAt := time.Date(2026, 10, 13, 13, 24, 30, 0, time.UTC)
	previousMetadata, previousProcesses := windowsEnterpriseActivationMetadata, windowsEnterpriseAgentProcesses
	previousConnectors, previousSID := windowsEnterpriseEnrolledConnectors, windowsEnterpriseAccountSID
	previousRestores := windowsEnterpriseGuardianRestores
	t.Cleanup(func() {
		windowsEnterpriseActivationMetadata, windowsEnterpriseAgentProcesses = previousMetadata, previousProcesses
		windowsEnterpriseEnrolledConnectors, windowsEnterpriseAccountSID = previousConnectors, previousSID
		windowsEnterpriseGuardianRestores = previousRestores
	})
	windowsEnterpriseEnrolledConnectors = func() ([]string, error) { return []string{"hermes", "codex"}, nil }
	windowsEnterpriseAccountSID = func(account string) string {
		switch account {
		case std1:
			return std1SID
		case std2:
			return std2SID
		}
		return ""
	}
	windowsEnterpriseGuardianRestores = func() (map[string]time.Time, error) {
		return map[string]time.Time{
			enterpriseHookGuardianRestoreKey(std1SID, "hermes"): restoredAt,
			enterpriseHookGuardianRestoreKey(std1SID, "codex"):  restoredAt,
		}, nil
	}
	processes := []inventory.AgentProcess{
		{PID: 61, Connector: "hermes", User: std1, StartedAt: restoredAt.Add(-2 * time.Minute)},
		{PID: 62, Connector: "hermes", User: std1, StartedAt: restoredAt.Add(time.Minute)},
		{PID: 63, Connector: "codex", User: std1, StartedAt: restoredAt.Add(-time.Minute)},
		{PID: 64, Connector: "hermes", User: std2, StartedAt: restoredAt.Add(-time.Minute)},
	}
	windowsEnterpriseAgentProcesses = func() ([]inventory.AgentProcess, error) { return processes, nil }
	restartWarnings := func(result *enterprisestatus.Result) []string {
		var named []string
		for _, warning := range result.Warnings {
			if warning.Code == windowsAgentSessionsRestartCode {
				named = append(named, warning.Message)
			}
		}
		return named
	}
	for _, withRecord := range []bool{false, true} {
		dir := t.TempDir()
		metadata := filepath.Join(dir, "deployment.json")
		if err := os.WriteFile(metadata, []byte("{}"), 0o600); err != nil {
			t.Fatal(err)
		}
		if withRecord {
			record := `{"activated_at":"` + activated.Format(time.RFC3339Nano) + `"}`
			if err := os.WriteFile(filepath.Join(dir, windowsEnterpriseActivationFileName), []byte(record), 0o600); err != nil {
				t.Fatal(err)
			}
		}
		windowsEnterpriseActivationMetadata = func() (string, bool) { return metadata, true }
		for _, action := range []string{"status", "verify"} {
			result := enterprisestatus.New(action, managed.ProfileStandalone, "windows", "1.0.2")
			result.Installed = true
			result.SecurityComplete = true
			applyWindowsEnterpriseAgentSessions(result, &windowsEnterpriseLifecycleOptions{})
			named := restartWarnings(result)
			if len(named) != 1 ||
				!strings.Contains(named[0], `user DCFC\dcw-std1 runs hermes (pid 61), started before the hook guardian put back the account's changed or removed hermes hooks at 2026-10-13T13:24:30Z`) ||
				strings.Contains(named[0], "pid 62") || strings.Contains(named[0], "pid 63") || strings.Contains(named[0], "pid 64") {
				t.Fatalf("%s (activation record %t) warnings = %+v, want Hermes pid 61 of dcw-std1 only", action, withRecord, result.Warnings)
			}
			if result.SecurityComplete {
				t.Fatalf("%s (activation record %t) reported security_complete with a session started before the restore", action, withRecord)
			}
		}
	}

	// The user restarted Hermes: nothing is named and coverage is complete.
	processes = []inventory.AgentProcess{{PID: 65, Connector: "hermes", User: std1, StartedAt: restoredAt.Add(3 * time.Minute)}}
	result := enterprisestatus.New("status", managed.ProfileStandalone, "windows", "1.0.2")
	result.Installed = true
	result.SecurityComplete = true
	applyWindowsEnterpriseAgentSessions(result, &windowsEnterpriseLifecycleOptions{})
	if named := restartWarnings(result); len(named) != 0 || !result.SecurityComplete {
		t.Fatalf("after the restart warnings = %+v security_complete = %t, want none and true", result.Warnings, result.SecurityComplete)
	}

	// Pass-6 review: a restore record that stays unreadable (a sharing
	// violation while the guardian replaces it) names each session whose
	// restart status is now unknown instead of none; Codex, whose hooks live
	// in machine policy, is still not named.
	windowsEnterpriseGuardianRestores = func() (map[string]time.Time, error) {
		return nil, errors.New("sharing violation")
	}
	processes = []inventory.AgentProcess{
		{PID: 66, Connector: "hermes", User: std1, StartedAt: restoredAt.Add(3 * time.Minute)},
		{PID: 67, Connector: "codex", User: std1, StartedAt: restoredAt.Add(-time.Minute)},
	}
	result = enterprisestatus.New("status", managed.ProfileStandalone, "windows", "1.0.2")
	result.Installed = true
	result.SecurityComplete = true
	applyWindowsEnterpriseAgentSessions(result, &windowsEnterpriseLifecycleOptions{})
	if named := restartWarnings(result); len(named) != 1 || !strings.Contains(named[0], `user DCFC\dcw-std1 runs hermes (pid 66); restart status unknown`) ||
		!strings.Contains(named[0], "sharing violation") || strings.Contains(named[0], "pid 67") || result.SecurityComplete {
		t.Fatalf("unreadable record: warnings = %+v security_complete = %t, want hermes pid 66 named with its restart status unknown", result.Warnings, result.SecurityComplete)
	}

	// An account lookup can fail during the same sharing violation. The
	// missing SID must not hide the unreadable record or leave status green.
	windowsEnterpriseAccountSID = func(string) string { return "" }
	result = enterprisestatus.New("status", managed.ProfileStandalone, "windows", "1.0.2")
	result.Installed, result.SecurityComplete = true, true
	applyWindowsEnterpriseAgentSessions(result, &windowsEnterpriseLifecycleOptions{})
	if named := restartWarnings(result); len(named) != 1 || !strings.Contains(named[0], "hermes (pid 66); restart status unknown") || result.SecurityComplete {
		t.Fatalf("unresolved account with unreadable record: warnings = %+v security_complete = %t", result.Warnings, result.SecurityComplete)
	}

	// Even with no visible agent sessions, an unreadable record leaves
	// restart status unknown rather than certifying security_complete.
	processes = nil
	result = enterprisestatus.New("verify", managed.ProfileStandalone, "windows", "1.0.2")
	result.Installed, result.SecurityComplete = true, true
	applyWindowsEnterpriseAgentSessions(result, &windowsEnterpriseLifecycleOptions{})
	if named := restartWarnings(result); len(named) != 1 || !strings.Contains(named[0], "restart status unknown") || result.SecurityComplete {
		t.Fatalf("unreadable record without sessions: warnings = %+v security_complete = %t", result.Warnings, result.SecurityComplete)
	}
	windowsEnterpriseAgentProcesses = func() ([]inventory.AgentProcess, error) { return nil, errors.New("process snapshot unavailable") }
	result = enterprisestatus.New("status", managed.ProfileStandalone, "windows", "1.0.2")
	result.Installed, result.SecurityComplete = true, true
	applyWindowsEnterpriseAgentSessions(result, &windowsEnterpriseLifecycleOptions{})
	if named := restartWarnings(result); len(named) != 1 || !strings.Contains(named[0], "restart status unknown") || result.SecurityComplete {
		t.Fatalf("unreadable record and sessions: warnings = %+v security_complete = %t", result.Warnings, result.SecurityComplete)
	}
}

func TestWindowsStandaloneRestoredSessionUsesSnapshotOwnerSID(t *testing.T) {
	const sid = "S-1-5-21-1-2-3-1001"
	restoredAt := time.Date(2026, 10, 13, 13, 24, 30, 0, time.UTC)
	metadata := filepath.Join(t.TempDir(), "deployment.json")
	previousMetadata, previousProcesses := windowsEnterpriseActivationMetadata, windowsEnterpriseAgentProcesses
	previousConnectors, previousSID := windowsEnterpriseEnrolledConnectors, windowsEnterpriseAccountSID
	previousRestores := windowsEnterpriseGuardianRestores
	t.Cleanup(func() {
		windowsEnterpriseActivationMetadata, windowsEnterpriseAgentProcesses = previousMetadata, previousProcesses
		windowsEnterpriseEnrolledConnectors, windowsEnterpriseAccountSID = previousConnectors, previousSID
		windowsEnterpriseGuardianRestores = previousRestores
	})
	windowsEnterpriseActivationMetadata = func() (string, bool) { return metadata, true }
	windowsEnterpriseEnrolledConnectors = func() ([]string, error) { return []string{"hermes"}, nil }
	windowsEnterpriseGuardianRestores = func() (map[string]time.Time, error) {
		return map[string]time.Time{enterpriseHookGuardianRestoreKey(sid, "hermes"): restoredAt}, nil
	}
	lookups := 0
	windowsEnterpriseAccountSID = func(string) string {
		lookups++
		return "S-1-5-21-1-2-3-9999"
	}

	for _, tc := range []struct {
		name, user, wantLabel string
	}{
		{name: "name unavailable", wantLabel: sid},
		{name: "name available", user: "DOMAIN\\member", wantLabel: "DOMAIN\\member"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			windowsEnterpriseAgentProcesses = func() ([]inventory.AgentProcess, error) {
				return []inventory.AgentProcess{{
					PID: 61, Connector: "hermes", User: tc.user, OwnerSID: sid,
					StartedAt: restoredAt.Add(-time.Minute),
				}}, nil
			}
			result := enterprisestatus.New("status", managed.ProfileStandalone, "windows", "1.0.2")
			result.Installed, result.SecurityComplete = true, true
			applyWindowsEnterpriseAgentSessions(result, &windowsEnterpriseLifecycleOptions{})
			if len(result.Warnings) != 1 || result.Warnings[0].Code != windowsAgentSessionsRestartCode ||
				!strings.Contains(result.Warnings[0].Message, "user "+tc.wantLabel+" runs hermes (pid 61), started before the hook guardian put back") ||
				result.SecurityComplete || lookups != 0 {
				t.Fatalf("restored session with snapshot SID = %+v, security_complete = %t, lookups = %d",
					result.Warnings, result.SecurityComplete, lookups)
			}
		})
	}
}

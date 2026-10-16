// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package cli

import (
	"errors"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/enterprisehooks"
	"github.com/defenseclaw/defenseclaw/internal/enterprisestatus"
	"github.com/defenseclaw/defenseclaw/internal/inventory"
	"github.com/defenseclaw/defenseclaw/internal/managed"
)

// GAP-0591: the account of a running agent was deleted, so the snapshot has
// its token SID but no account name, and the enumerator revoked the
// account's rows. No activation, enrollment or restore time judges the
// session, and the restart-status path said nothing, as if it did not run.
// It now names the session's restart status unknown and keeps security
// incomplete until the process exits.
func TestWindowsStandaloneNamesTheSessionOfADeletedAccountRestartStatusUnknown(t *testing.T) {
	const sid = "S-1-5-21-2566694559-2372738039-4094494201-1115"
	started := time.Date(2026, 10, 14, 22, 17, 18, 0, time.UTC)
	metadata := filepath.Join(t.TempDir(), "deployment.json")
	previousMetadata, previousProcesses := windowsEnterpriseActivationMetadata, windowsEnterpriseAgentProcesses
	previousConnectors, previousTargets := windowsEnterpriseEnrolledConnectors, windowsEnterpriseEnrolledTargets
	previousRestores, previousSID := windowsEnterpriseGuardianRestores, windowsEnterpriseAccountSID
	t.Cleanup(func() {
		windowsEnterpriseActivationMetadata, windowsEnterpriseAgentProcesses = previousMetadata, previousProcesses
		windowsEnterpriseEnrolledConnectors, windowsEnterpriseEnrolledTargets = previousConnectors, previousTargets
		windowsEnterpriseGuardianRestores, windowsEnterpriseAccountSID = previousRestores, previousSID
	})
	windowsEnterpriseActivationMetadata = func() (string, bool) { return metadata, true }
	windowsEnterpriseEnrolledConnectors = func() ([]string, error) { return []string{"codex"}, nil }
	windowsEnterpriseGuardianRestores = func() (map[string]time.Time, error) { return nil, nil }
	lookups := 0
	windowsEnterpriseAccountSID = func(string) string { lookups++; return "" }
	running := []inventory.AgentProcess{{PID: 11888, Connector: "codex", OwnerSID: sid, StartedAt: started}}
	enrolledKey := windowsEnterpriseManifestRowKey(enterprisehooks.ManifestTarget{SID: sid, Connector: "codex"})

	for _, tc := range []struct {
		name        string
		processes   []inventory.AgentProcess
		targets     map[string]bool
		targetsErr  error
		wantUnknown bool
	}{
		{name: "rows revoked", processes: running, targets: map[string]bool{}, wantUnknown: true},
		{name: "manifest unreadable", processes: running, targetsErr: errors.New("access denied"), wantUnknown: true},
		{name: "still enrolled", processes: running, targets: map[string]bool{enrolledKey: true}},
		{name: "process exited", targets: map[string]bool{}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			windowsEnterpriseAgentProcesses = func() ([]inventory.AgentProcess, error) { return tc.processes, nil }
			windowsEnterpriseEnrolledTargets = func() (map[string]bool, error) { return tc.targets, tc.targetsErr }
			result := enterprisestatus.New("status", managed.ProfileStandalone, "windows", "1.0.2")
			result.Installed, result.SecurityComplete = true, true
			applyWindowsEnterpriseAgentSessions(result, &windowsEnterpriseLifecycleOptions{})
			if !tc.wantUnknown {
				if len(result.Warnings) != 0 || !result.SecurityComplete {
					t.Fatalf("warnings = %+v, security_complete = %t, want none and complete", result.Warnings, result.SecurityComplete)
				}
				return
			}
			if len(result.Warnings) != 1 || result.Warnings[0].Code != windowsAgentSessionsRestartCode ||
				!strings.HasPrefix(result.Warnings[0].Message, "restart status unknown:") ||
				!strings.Contains(result.Warnings[0].Message, "codex (pid 11888) as "+sid) ||
				result.SecurityComplete || lookups != 0 {
				t.Fatalf("warnings = %+v, security_complete = %t, lookups = %d, want restart status unknown for pid 11888 and incomplete security",
					result.Warnings, result.SecurityComplete, lookups)
			}
		})
	}
}

// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package cli

import (
	"bytes"
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

// A cycle whose process snapshot could not be read returned no running
// agents, and the cycle rewrote the unprotected record without a single
// running-agent entry: an unenrolled agent that kept running read as covered
// until a later snapshot (rel-1-0-2:GAP-0672). The cycle keeps what the last
// readable snapshot of the enumerator process found, and a first cycle keeps
// the running-agent entries of the previous record (not the install ones).
func TestEnterpriseWindowsEnumerateUnreadableSnapshotKeepsRunningAgents(t *testing.T) {
	const alice = "S-1-5-21-2566694559-2372738039-4094494201-1201"
	stubEnumerateRunningAgents(t, []inventory.AgentProcess{
		{PID: 10, Connector: "codex", OwnerSID: alice},
		{PID: 11, Connector: "codex", User: `DCLAB\gone`},
	}, nil, nil)
	got, unknown := enterpriseWindowsEnumerateRunningAgents(new(bytes.Buffer), []string{"codex"}, "")
	if got[alice]["codex"] != "codex (pid 10)" || len(unknown) != 1 {
		t.Fatalf("readable cycle: rows %+v, unknown %+v", got, unknown)
	}
	enterpriseWindowsEnumerateAgentProcesses = func() ([]inventory.AgentProcess, error) {
		return nil, errors.New("snapshot denied")
	}
	stderr := new(bytes.Buffer)
	got, unknown = enterpriseWindowsEnumerateRunningAgents(stderr, []string{"codex"}, "")
	if got[alice]["codex"] != "codex (pid 10)" || len(unknown) != 1 || unknown[0].User != `DCLAB\gone` {
		t.Fatalf("unreadable cycle after a readable one: rows %+v, unknown %+v", got, unknown)
	}
	if !strings.Contains(stderr.String(), "the running agents of the last readable cycle are kept") {
		t.Fatalf("log %q does not say the last readable cycle's agents are kept", stderr.String())
	}
	// The kept result is a copy: a caller that changes it changes nothing kept.
	got[alice]["codex"] = "changed"
	if again, _ := enterpriseWindowsEnumerateRunningAgents(new(bytes.Buffer), []string{"codex"}, ""); again[alice]["codex"] != "codex (pid 10)" {
		t.Fatalf("the kept snapshot was changed through a returned map: %+v", again)
	}

	// A first cycle (no readable snapshot in this process) keeps the
	// running-agent entries of the previous record and no install entry.
	resetEnumerateLastRunning(t)
	running := enterprisehooks.UnprotectedAgent{User: "alice", SID: alice, Connector: "codex",
		Code:   enterprisehooks.UnprotectedCodeAgentUnprotected,
		Reason: "codex (pid 10) runs for this account, which has no enabled enrollment manifest target; its tool calls are not decided by DefenseClaw"}
	pending := enterprisehooks.UnprotectedAgent{User: "bob", SID: alice + "2", Connector: "codex",
		Code:   enterprisehooks.UnprotectedCodeAgentUnprotected,
		Reason: "codex (pid 12) runs for this account and its enrollment is pending: waiting for a session"}
	install := enterprisehooks.UnprotectedAgent{User: "carol", SID: alice + "3", Connector: "codex",
		Code:   enterprisehooks.UnprotectedCodeAgentUnprotected,
		Reason: "codex is installed for this account, but no enabled row enrolls it"}
	var readPath string
	enterpriseWindowsEnumeratePreviousUnprotected = func(path string) ([]enterprisehooks.UnprotectedAgent, error) {
		readPath = path
		return []enterprisehooks.UnprotectedAgent{running, install, pending}, enterprisehooks.UnprotectedAgentsStaleError{Age: "2h"}
	}
	stderr.Reset()
	got, unknown = enterpriseWindowsEnumerateRunningAgents(stderr, []string{"codex"}, `C:\ProgramData\Cisco\DefenseClaw\enterprise\targets.yaml`)
	if got != nil || len(unknown) != 2 || unknown[0] != running || unknown[1] != pending || readPath == "" {
		t.Fatalf("first unreadable cycle: rows %+v, kept %+v, read %q; want the two running-agent entries of the previous record", got, unknown, readPath)
	}
	if !strings.Contains(stderr.String(), "the 2 running-agent entries of the previous record are kept") {
		t.Fatalf("log %q does not say the previous record's entries are kept", stderr.String())
	}
}

// The direct session scan names the restart status unknown when the
// snapshot cannot be read, also when the restore record can, instead of
// saying nothing (rel-1-0-2:GAP-0672).
func TestWindowsAgentSessionsNameRestartStatusUnknownOnAnUnreadableSnapshot(t *testing.T) {
	previousProcesses, previousRestores := windowsEnterpriseAgentProcesses, windowsEnterpriseGuardianRestores
	previousMetadata, previousConnectors := windowsEnterpriseActivationMetadata, windowsEnterpriseEnrolledConnectors
	t.Cleanup(func() {
		windowsEnterpriseAgentProcesses, windowsEnterpriseGuardianRestores = previousProcesses, previousRestores
		windowsEnterpriseActivationMetadata, windowsEnterpriseEnrolledConnectors = previousMetadata, previousConnectors
	})
	metadata := filepath.Join(t.TempDir(), "deployment.json")
	windowsEnterpriseActivationMetadata = func() (string, bool) { return metadata, true }
	windowsEnterpriseEnrolledConnectors = func() ([]string, error) { return []string{"codex"}, nil }
	windowsEnterpriseGuardianRestores = func() (map[string]time.Time, error) { return nil, nil }
	windowsEnterpriseAgentProcesses = func() ([]inventory.AgentProcess, error) { return nil, errors.New("snapshot denied") }
	result := enterprisestatus.New("status", managed.ProfileStandalone, "windows", "1.0.6")
	result.Installed, result.SecurityComplete = true, true
	applyWindowsEnterpriseAgentSessions(result, &windowsEnterpriseLifecycleOptions{})
	if len(result.Warnings) != 1 || result.Warnings[0].Code != windowsAgentSessionsRestartCode ||
		!strings.HasPrefix(result.Warnings[0].Message, "restart status unknown: the running agent sessions could not be read") ||
		result.SecurityComplete {
		t.Fatalf("warnings = %+v, security_complete = %t, want restart status unknown and incomplete security", result.Warnings, result.SecurityComplete)
	}
}

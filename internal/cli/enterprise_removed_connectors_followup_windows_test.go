// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package cli

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/managed"
)

// The guardian publishes an off-roster marker for each of Claude Code and
// Codex exactly when the loaded config does not publish it, and a failure is
// logged without stopping the other.
func TestPublishWindowsStandaloneOffRosterMarkers(t *testing.T) {
	previous := enterpriseHookWindowsOffRosterPublisher
	t.Cleanup(func() { enterpriseHookWindowsOffRosterPublisher = previous })
	got := map[string]bool{}
	enterpriseHookWindowsOffRosterPublisher = func(name string, off bool) error {
		got[name] = off
		if name == "claudecode" {
			return errors.New("directory busy")
		}
		return nil
	}
	var log bytes.Buffer
	publishWindowsStandaloneOffRosterMarkers(&log, func(name string) bool { return name == "claudecode" })
	if len(got) != 2 || got["claudecode"] || !got["codex"] {
		t.Fatalf("markers published = %v, want claudecode on the roster and codex off it", got)
	}
	if !strings.Contains(log.String(), "claudecode") || !strings.Contains(log.String(), "directory busy") {
		t.Fatalf("the failure was not logged: %q", log.String())
	}
}

// A removed-connector entry whose connector is back on the roster is not shown
// while the guardian has not yet dropped it: the manifest admits the pair, or
// the loaded config publishes the connector.
func TestWindowsEnterpriseEnrollmentHidesAnEntryBackOnTheRoster(t *testing.T) {
	restoreRead, restorePublished := windowsEnterpriseRemovedConnectorsForStatus, windowsEnterpriseConnectorPublishedForStatus
	t.Cleanup(func() {
		windowsEnterpriseRemovedConnectorsForStatus, windowsEnterpriseConnectorPublishedForStatus = restoreRead, restorePublished
	})
	const alice, bob = "S-1-5-21-1-2-3-1001", "S-1-5-21-1-2-3-1002"
	windowsEnterpriseRemovedConnectorsForStatus = func() ([]managed.RemovedConnector, error) {
		return []managed.RemovedConnector{
			{Connector: "cursor", SID: alice, RemovedAt: "t"}, // the manifest admits it again
			{Connector: "cursor", SID: bob, RemovedAt: "t"},   // the config publishes cursor again
			{Connector: "codex", SID: alice, RemovedAt: "t"},  // still removed
		}, nil
	}
	windowsEnterpriseConnectorPublishedForStatus = func(name string) bool { return false }
	dir := t.TempDir()
	manifest := filepath.Join(dir, "targets.yaml")
	body := "version: 1\ntargets:\n  - connector: cursor\n    sid: " + alice + "\n    enabled: true\n"
	if err := os.WriteFile(manifest, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	enrollment, err := readWindowsEnterpriseStandaloneEnrollmentAt(manifest, dir)
	if err != nil {
		t.Fatal(err)
	}
	shown := map[string]string{}
	for _, account := range enrollment.RemovedConnectors {
		for name := range account.Connectors {
			shown[account.SID+" "+name] = account.Connectors[name]
		}
	}
	if len(shown) != 2 || shown[alice+" codex"] == "" || shown[bob+" cursor"] == "" {
		t.Fatalf("shown = %v, want alice's codex and bob's cursor", shown)
	}
	windowsEnterpriseConnectorPublishedForStatus = func(name string) bool { return name == "cursor" }
	enrollment, _ = readWindowsEnterpriseStandaloneEnrollmentAt(manifest, dir)
	if len(enrollment.RemovedConnectors) != 1 || enrollment.RemovedConnectors[0].SID != alice {
		t.Fatalf("after the config publishes cursor again: %+v", enrollment.RemovedConnectors)
	}
}

// The doctor and TUI answers call the own-status pipe only for a standard
// account of a standalone managed computer: not on Secure Client or an
// unmanaged host, not from an elevated prompt.
func TestOwnRemovedConnectorLinesCallsThePipeOnlyOnStandalone(t *testing.T) {
	restoreStandalone, restoreFetch, restoreElevated := managedHostWindowsStandalone, ownStatusPipeFetch, windowsEnterpriseIsElevated
	t.Cleanup(func() {
		managedHostWindowsStandalone, ownStatusPipeFetch, windowsEnterpriseIsElevated = restoreStandalone, restoreFetch, restoreElevated
	})
	t.Setenv(managed.DeploymentModeEnv, "")
	t.Setenv(managed.ConfigPathEnv, "")
	calls := 0
	ownStatusPipeFetch = func(context.Context) ([]byte, error) {
		calls++
		return []byte(`{"connectors":{"cursor":{"state":"not managed (removed from roster)"}}}`), nil
	}
	windowsEnterpriseIsElevated = func() bool { return false }
	managedHostWindowsStandalone = func() (string, bool) { return "", false }
	if lines := ownRemovedConnectorLines(); lines != nil || calls != 0 {
		t.Fatalf("a computer that is not a standalone managed one read the pipe: %v %d", lines, calls)
	}
	managedHostWindowsStandalone = func() (string, bool) { return `HKLM\SOFTWARE\Cisco\DefenseClaw\Enterprise`, true }
	windowsEnterpriseIsElevated = func() bool { return true }
	if lines := ownRemovedConnectorLines(); lines != nil || calls != 0 {
		t.Fatalf("an elevated prompt read the pipe: %v %d", lines, calls)
	}
	windowsEnterpriseIsElevated = func() bool { return false }
	if lines := ownRemovedConnectorLines(); len(lines) != 1 || calls != 1 {
		t.Fatalf("a standard account on a standalone computer: %v %d", lines, calls)
	}
}

// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/enterprisestatus"
	"github.com/defenseclaw/defenseclaw/internal/managed"
)

// status and verify print and report the record without counting it as an
// enrolled or pending account.
func TestWindowsEnterpriseEnrollmentReportsRemovedConnectors(t *testing.T) {
	restore := windowsEnterpriseRemovedConnectorsForStatus
	t.Cleanup(func() { windowsEnterpriseRemovedConnectorsForStatus = restore })
	windowsEnterpriseRemovedConnectorsForStatus = func() ([]managed.RemovedConnector, error) { return removedConnectorFixture(), nil }
	dir := t.TempDir()
	manifest := filepath.Join(dir, "targets.yaml")
	if err := os.WriteFile(manifest, []byte("version: 1\ntargets: []\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	enrollment, err := readWindowsEnterpriseStandaloneEnrollmentAt(manifest, dir)
	if err != nil {
		t.Fatal(err)
	}
	if enrollment.Targets != 0 || enrollment.Pending != 0 || enrollment.Failed != 0 || len(enrollment.Accounts) != 0 {
		t.Fatalf("a removed connector was counted: %+v", enrollment)
	}
	if len(enrollment.RemovedConnectors) != 2 {
		t.Fatalf("removed connectors = %+v", enrollment.RemovedConnectors)
	}
	body, err := json.Marshal(enrollment)
	if err != nil || !strings.Contains(string(body), `"removed_connectors"`) || !strings.Contains(string(body), managed.NotManagedRemovedFromRoster) {
		t.Fatalf("json = %s, %v", body, err)
	}
	for _, action := range []string{"status", "verify"} {
		result := enterprisestatus.New(action, managed.ProfileStandalone, "windows", "1.0.0")
		result.OK = true
		result.Enrollment = enrollment
		var out bytes.Buffer
		writeWindowsEnterpriseStandaloneSummary(&out, result)
		if !strings.Contains(out.String(), "codex not managed (removed from roster), cursor not managed (removed from roster)") {
			t.Fatalf("%s summary does not render the removed connectors:\n%s", action, out.String())
		}
	}
	// An unreadable record leaves the lists out.
	windowsEnterpriseRemovedConnectorsForStatus = func() ([]managed.RemovedConnector, error) { return nil, os.ErrPermission }
	if enrollment, err = readWindowsEnterpriseStandaloneEnrollmentAt(manifest, dir); err != nil || len(enrollment.RemovedConnectors) != 0 {
		t.Fatalf("unreadable record: %+v, %v", enrollment, err)
	}
}

// The own-status pipe answer is what doctor and the TUI answer read.
func TestRemovedConnectorLinesFromOwnStatus(t *testing.T) {
	body := []byte(`{"own":true,"connectors":{"claudecode":{"protected":true,"state":"protected"},` +
		`"cursor":{"protected":false,"state":"not managed (removed from roster)"},` +
		`"codex":{"protected":false,"state":"not managed (removed from roster)"},` +
		`"hermes":{"protected":false,"state":"not confirmed: x"}}}`)
	got := removedConnectorLinesFromOwnStatus(body)
	if strings.Join(got, "|") != "codex: not managed (removed from roster)|cursor: not managed (removed from roster)" {
		t.Fatalf("lines = %v", got)
	}
	if removedConnectorLinesFromOwnStatus([]byte("not json")) != nil || removedConnectorLinesFromOwnStatus([]byte(`{"connectors":{}}`)) != nil {
		t.Fatal("an answer without removed connectors gave lines")
	}
}

func TestOwnRemovedConnectorLinesNeedsAStandardAccount(t *testing.T) {
	restoreOwn, restoreFetch := statusShowsOwnState, ownStatusPipeFetch
	t.Cleanup(func() { statusShowsOwnState, ownStatusPipeFetch = restoreOwn, restoreFetch })
	called := 0
	ownStatusPipeFetch = func(context.Context) ([]byte, error) {
		called++
		return []byte(`{"connectors":{"cursor":{"state":"not managed (removed from roster)"}}}`), nil
	}
	statusShowsOwnState = func() bool { return false }
	if lines := ownRemovedConnectorLines(); lines != nil || called != 0 {
		t.Fatalf("an elevated or non-standalone caller read the pipe: %v %d", lines, called)
	}
	statusShowsOwnState = func() bool { return true }
	if lines := ownRemovedConnectorLines(); len(lines) != 1 || called != 1 {
		t.Fatalf("standard account lines = %v (%d reads)", lines, called)
	}
	ownStatusPipeFetch = func(context.Context) ([]byte, error) { return nil, os.ErrNotExist }
	if lines := ownRemovedConnectorLines(); lines != nil {
		t.Fatalf("a pipe failure gave lines: %v", lines)
	}
}

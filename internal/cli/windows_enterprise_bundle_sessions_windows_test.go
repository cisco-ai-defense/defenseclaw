// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package cli

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/inventory"
	"github.com/defenseclaw/defenseclaw/internal/managed"
)

// Sidecar F04: sessions_restart_required counts only the connectors the
// installed config enables. Claude Code sessions on a Codex-only device load
// no DefenseClaw hook before or after any bundle, so they never need a
// restart and must not keep the device from reporting fully enforcing.
func TestWindowsBundleSessionsCountOnlyEnabledConnectors(t *testing.T) {
	dir := t.TempDir()
	metadata := filepath.Join(dir, "deployment.json")
	if err := os.WriteFile(metadata, []byte(`{"installed":true}`), 0o600); err != nil {
		t.Fatal(err)
	}
	activated := time.Now().UTC().Add(-time.Hour)
	if err := os.WriteFile(filepath.Join(dir, windowsEnterpriseActivationFileName),
		[]byte(`{"activated_at":"`+activated.Format(time.RFC3339Nano)+`"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	layout, err := windowsManagedLayout.standalone()
	if err != nil {
		t.Fatal(err)
	}
	layout.LifecycleDir = filepath.Join(dir, "install")
	previousMetadata, previousProcesses := windowsEnterpriseActivationMetadata, windowsEnterpriseAgentProcesses
	previousEnrolled, previousLayout := windowsEnterpriseEnrolledConnectors, windowsBundleLayout
	t.Cleanup(func() {
		windowsEnterpriseActivationMetadata, windowsEnterpriseAgentProcesses = previousMetadata, previousProcesses
		windowsEnterpriseEnrolledConnectors, windowsBundleLayout = previousEnrolled, previousLayout
	})
	windowsBundleLayout = func() (managed.StandaloneLayout, error) { return layout, nil }
	windowsEnterpriseActivationMetadata = func() (string, bool) { return metadata, true }
	windowsEnterpriseEnrolledConnectors = func() ([]string, error) { return []string{"codex"}, nil }
	old := activated.Add(-24 * time.Hour)
	windowsEnterpriseAgentProcesses = func() ([]inventory.AgentProcess, error) {
		rows := []inventory.AgentProcess{{PID: 601, Connector: "codex", User: `DCFC\dcw-std1`, StartedAt: old}}
		for pid := 501; pid <= 508; pid++ {
			rows = append(rows, inventory.AgentProcess{PID: pid, Connector: "claudecode", User: `DCFC\dcw-std1`, StartedAt: old})
		}
		// An unmanaged agent whose owner cannot be read turned the whole
		// scan unknown before.
		return append(rows, inventory.AgentProcess{PID: 701, Connector: "cursor", StartedAt: old}), nil
	}
	status := platformBundleSessionStatus(context.Background())
	if status.State != "known" || status.Count != 1 || len(status.Entries) != 1 || status.Entries[0].Agent != "codex" {
		t.Fatalf("sessions on a Codex-only device = %+v, want only the old Codex session", status)
	}
}

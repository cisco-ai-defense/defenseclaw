// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package cli

import (
	"strings"
	"testing"
)

// A standalone uninstall removes the machine state (owner decision,
// GAP-1277), so the help must not promise to keep it (GAP-1566).
func TestWindowsEnterpriseUninstallSummaryNamesMachineStateRemoval(t *testing.T) {
	got := windowsEnterpriseLifecycleSummary("uninstall")
	if strings.Contains(got, "preserving state") || !strings.Contains(got, "machine state") || !strings.Contains(got, "--purge") {
		t.Fatalf("uninstall summary = %q", got)
	}
}

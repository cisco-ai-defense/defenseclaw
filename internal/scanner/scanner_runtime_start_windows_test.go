// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package scanner

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/managed"
)

// GAP-0490 with the real trust check: a scanner runtime under a folder that
// standard users can change (the test's temp folder) stops the standalone
// gateway from starting; an absent one, or another install, does not.
func TestStandaloneGatewayStartRunsTheScannerRuntimeTrustCheck(t *testing.T) {
	root := filepath.Join(t.TempDir(), "DefenseClaw-ScannerRuntime")
	oldRoot := scannerRuntimeRoot
	scannerRuntimeRoot = func() (string, error) { return root, nil }
	t.Cleanup(func() { scannerRuntimeRoot = oldRoot })
	t.Setenv(managed.DeploymentModeEnv, managed.DeploymentModeManagedEnterprise)
	t.Setenv(managed.EnterpriseProfileEnv, managed.ProfileStandalone)
	if err := StandaloneRuntimeStartProblem(); err != nil {
		t.Fatalf("an absent runtime refused the start: %v", err)
	}
	if err := os.MkdirAll(filepath.Join(root, "0123", "python"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := StandaloneRuntimeStartProblem(); err == nil || !strings.Contains(err.Error(), "does not start on the untrusted scanner runtime") {
		t.Fatalf("an untrusted runtime did not refuse the start: %v", err)
	}
	t.Setenv(managed.EnterpriseProfileEnv, "")
	if err := StandaloneRuntimeStartProblem(); err != nil {
		t.Fatalf("a non-standalone gateway checked the scanner runtime: %v", err)
	}
}

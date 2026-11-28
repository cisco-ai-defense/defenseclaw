// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package cli

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/gateway/connector"
)

// The Linux and macOS fixture of the key custody tests; the Windows one is in
// enterprise_hooks_token_fixture_windows_test.go (rel-1-0-10:GAP-1514,
// GAP-1515).

// enterpriseHookTestKeyRotationStages: the root guardian stages the next
// per-user credential key during a rotation.
const enterpriseHookTestKeyRotationStages = true

// enterpriseHookTokenTestDataDir is an owner-only managed data_dir.
func enterpriseHookTokenTestDataDir(t *testing.T) string {
	t.Helper()
	dataDir := filepath.Join(t.TempDir(), "data")
	if err := os.Mkdir(dataDir, 0o700); err != nil {
		t.Fatal(err)
	}
	return dataDir
}

// enterpriseHookTestUserIdentities are two uids.
func enterpriseHookTestUserIdentities() (string, string) {
	return "1001", "1002"
}

// publishEnterpriseHookTestRouteEpoch: Linux and macOS derive the route
// credential from the per-user key alone.
func publishEnterpriseHookTestRouteEpoch(*testing.T, string) *connector.RouteEpoch {
	return nil
}

// assertEnterpriseHookSecretCustody: the credential file is owner-only.
func assertEnterpriseHookSecretCustody(t *testing.T, _, path, label string) {
	t.Helper()
	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat %s: %v", label, err)
	}
	if got := info.Mode().Perm(); got != 0o600 {
		t.Fatalf("%s mode = %o, want 600", label, got)
	}
}

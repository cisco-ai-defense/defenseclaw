// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package cli

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/managed"
)

// GAP-1733 review (live k2c, TST-11933): status runs as an administrator
// without the service pins, so its enrolled-accounts reader looked for the
// ledger at <DataDir>-hook-guardian, found nothing, and named the planted
// entry of an enrolled account enrollment_skipped_per_user_install instead
// of per_user_install_tamper. The real reader (not stubbed) must find the
// ledger at the layout's authorization folder.
func TestGAP1733StatusEnrolledAccountsReadTheLayoutLedgerWithoutTheServicePins(t *testing.T) {
	stubEnterpriseHookAuthorizationTrustForTempDir(t)
	previousStateTrust, previousOwnership, previousLayout := enterpriseHookGuardianStateFileTrustCheck,
		enterpriseHookAuthorizationOwnershipSetter, windowsEnterpriseHotConfigLayout
	previousCfg := cfg
	t.Cleanup(func() {
		enterpriseHookGuardianStateFileTrustCheck, enterpriseHookAuthorizationOwnershipSetter = previousStateTrust, previousOwnership
		windowsEnterpriseHotConfigLayout, cfg = previousLayout, previousCfg
	})
	enterpriseHookGuardianStateFileTrustCheck = func(string) error { return nil }
	enterpriseHookAuthorizationOwnershipSetter = func(string) error { return nil }
	cfg = nil

	root := t.TempDir()
	layout, err := managed.StandaloneWindowsLayoutForRoots(filepath.Join(root, "Program Files"), filepath.Join(root, "ProgramData"))
	if err != nil {
		t.Fatal(err)
	}
	for _, dir := range []string{layout.DataDir, layout.GuardianAuthDir} {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	const enrolled, other = "S-1-5-21-7-7-7-1001", "S-1-5-21-7-7-7-1002"
	home := filepath.Join(root, "Users", "std1")
	rows := []enterpriseHookReconcileRow{
		{SID: enrolled, UserHome: home, Connector: "copilot", OK: true},
		{SID: enrolled, UserHome: home, Connector: "codex", OK: true},
	}
	// The guardian publishes with its service pins.
	t.Setenv(hookGuardianAuthorizationDirEnv, layout.GuardianAuthDir)
	if err := writeEnterpriseHookGuardianState(layout.DataDir, layout.ManifestPath, strings.Repeat("a", 64), rows, 0, true); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(layout.GuardianAuthDir, managed.HookGuardianAuthorizationFile)); err != nil {
		t.Fatalf("the guardian did not publish its ledger in the layout folder: %v", err)
	}
	// Status runs without them.
	t.Setenv(hookGuardianAuthorizationDirEnv, "")
	windowsEnterpriseHotConfigLayout = func() (managed.StandaloneLayout, error) { return layout, nil }
	isEnrolled := windowsEnterpriseEnrolledAccounts()
	if !isEnrolled(enrolled) {
		t.Fatalf("status read no ledger row of the enrolled account (ledger %s): it would name its planted entry a per-user install, not tamper",
			filepath.Join(layout.GuardianAuthDir, managed.HookGuardianAuthorizationFile))
	}
	if isEnrolled(other) {
		t.Fatal("status counted an account the ledger has no row of as enrolled: the ledger was not read")
	}
}

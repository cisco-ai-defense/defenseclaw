//go:build windows

// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"path/filepath"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/enterprisestatus"
	"github.com/defenseclaw/defenseclaw/internal/managed"
)

// Status names the one account whose DefenseClaw folder is a link it made
// itself (GAP-0193), and only that account; the other account gets no
// warning and the computer no error.
func TestWindowsStandaloneStatusNamesAnAccountOwnDataDirLink(t *testing.T) {
	previousAccounts, previousDeleted, previousFolder, previousLink := windowsEnterpriseManifestAccounts, windowsEnterpriseAccountDeleted, windowsEnterpriseAccountCreatedDataDir, windowsEnterpriseAccountOwnedDataDirLink
	t.Cleanup(func() {
		windowsEnterpriseManifestAccounts, windowsEnterpriseAccountDeleted, windowsEnterpriseAccountCreatedDataDir, windowsEnterpriseAccountOwnedDataDirLink = previousAccounts, previousDeleted, previousFolder, previousLink
	})
	linked, plain := t.TempDir(), t.TempDir()
	windowsEnterpriseManifestAccounts = func() ([]windowsEnterpriseManifestAccount, error) {
		return []windowsEnterpriseManifestAccount{
			{User: "alice", SID: "S-1-5-21-1-2-3-1001", Home: linked, Rows: 1},
			{User: "bob", SID: "S-1-5-21-1-2-3-1002", Home: plain, Rows: 1},
		}, nil
	}
	windowsEnterpriseAccountDeleted = func(string) bool { return false }
	windowsEnterpriseAccountCreatedDataDir = func(string, string) bool { return false }
	windowsEnterpriseAccountOwnedDataDirLink = func(home, sid string) bool {
		return home == linked && sid == "S-1-5-21-1-2-3-1001"
	}
	status := enterprisestatus.New("status", managed.ProfileStandalone, "windows", "1.0.6")
	applyWindowsEnterpriseAccountFolders(status)
	var found []string
	for _, warning := range status.Warnings {
		if warning.Code == "enrollment_pending_account_link" {
			found = append(found, warning.Message)
		}
	}
	if len(found) != 1 || !strings.Contains(found[0], "alice (S-1-5-21-1-2-3-1001)") ||
		!strings.Contains(found[0], filepath.Join(linked, ".defenseclaw")) || strings.Contains(found[0], "bob") {
		t.Fatalf("warnings = %+v, want one enrollment_pending_account_link naming only alice", status.Warnings)
	}
	if len(status.Errors) != 0 {
		t.Fatalf("errors = %+v, want none for one account's link", status.Errors)
	}
}

// GAP-0585: a link another principal owns at one account's folder gets its
// own named warning for that account only, not an error for the computer.
func TestWindowsStandaloneStatusNamesAnAccountForeignDataDirLink(t *testing.T) {
	previousAccounts, previousDeleted, previousFolder, previousOwned, previousForeign := windowsEnterpriseManifestAccounts, windowsEnterpriseAccountDeleted, windowsEnterpriseAccountCreatedDataDir, windowsEnterpriseAccountOwnedDataDirLink, windowsEnterpriseAccountForeignDataDirLink
	t.Cleanup(func() {
		windowsEnterpriseManifestAccounts, windowsEnterpriseAccountDeleted, windowsEnterpriseAccountCreatedDataDir, windowsEnterpriseAccountOwnedDataDirLink, windowsEnterpriseAccountForeignDataDirLink = previousAccounts, previousDeleted, previousFolder, previousOwned, previousForeign
	})
	linked, plain := t.TempDir(), t.TempDir()
	windowsEnterpriseManifestAccounts = func() ([]windowsEnterpriseManifestAccount, error) {
		return []windowsEnterpriseManifestAccount{
			{User: "alice", SID: "S-1-5-21-1-2-3-1001", Home: linked, Rows: 1},
			{User: "bob", SID: "S-1-5-21-1-2-3-1002", Home: plain, Rows: 1},
		}, nil
	}
	windowsEnterpriseAccountDeleted = func(string) bool { return false }
	windowsEnterpriseAccountCreatedDataDir = func(string, string) bool { return false }
	windowsEnterpriseAccountOwnedDataDirLink = func(string, string) bool { return false }
	windowsEnterpriseAccountForeignDataDirLink = func(home, sid string) bool {
		return home == linked && sid == "S-1-5-21-1-2-3-1001"
	}
	status := enterprisestatus.New("status", managed.ProfileStandalone, "windows", "1.0.9")
	applyWindowsEnterpriseAccountFolders(status)
	var found []string
	for _, warning := range status.Warnings {
		if warning.Code == "enrollment_skipped_account_link" {
			found = append(found, warning.Message)
		}
		if warning.Code == "enrollment_pending_account_link" {
			t.Fatalf("a link the account does not own was reported as its own: %+v", warning)
		}
	}
	if len(found) != 1 || !strings.Contains(found[0], "alice (S-1-5-21-1-2-3-1001)") ||
		!strings.Contains(found[0], filepath.Join(linked, ".defenseclaw")) || strings.Contains(found[0], "bob") {
		t.Fatalf("warnings = %+v, want one enrollment_skipped_account_link naming only alice", status.Warnings)
	}
	if len(status.Errors) != 0 {
		t.Fatalf("errors = %+v, want none for one account's link", status.Errors)
	}
}

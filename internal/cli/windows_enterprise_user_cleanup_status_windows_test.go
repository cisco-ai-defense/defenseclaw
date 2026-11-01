//go:build windows

// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/enterprisestatus"
)

// GAP-2380: a per-user cleanup the guardian keeps failing is named in status
// and verify; a new failure, or a cleanup waiting for a signed-out account,
// is not.
func TestWindowsEnterpriseStatusNamesAPerUserCleanupThatKeepsFailing(t *testing.T) {
	previous := windowsEnterpriseUserCleanupsForStatus
	t.Cleanup(func() { windowsEnterpriseUserCleanupsForStatus = previous })
	ledger := []enterpriseHookUserCleanup{
		{Connector: "opencode", SID: userCleanupSIDA, UserHome: `C:\Users\dcw-std1`, Attempts: 7,
			LastError: `enterprise hooks: removal file trust check failed: enterprise hooks: managed Windows DACL on C:\Users\dcw-std1\.config has 9 ACEs, expected 7`},
		{Connector: "amp", SID: userCleanupSIDA, UserHome: `C:\Users\dcw-std1`, Attempts: 1, LastError: "file in use"},
		{Connector: "hermes", SID: userCleanupSIDA, UserHome: `C:\Users\dcw-std2`},
	}
	windowsEnterpriseUserCleanupsForStatus = func() ([]enterpriseHookUserCleanup, error) { return ledger, nil }
	for _, action := range []string{"status", "verify"} {
		result := enterprisestatus.New(action, "standalone", "windows", "test")
		applyWindowsEnterpriseUserCleanupFailures(result)
		if len(result.Errors) != 0 || len(result.Warnings) != 1 || result.Warnings[0].Code != "user_cleanup_failing" {
			t.Fatalf("%s: errors %+v warnings %+v", action, result.Errors, result.Warnings)
		}
		message := result.Warnings[0].Message
		if !strings.Contains(message, `opencode for C:\Users\dcw-std1 (7 passes)`) || !strings.Contains(message, "has 9 ACEs, expected 7") ||
			strings.Contains(message, "amp for") || strings.Contains(message, "hermes for") || !strings.Contains(message, "repair") {
			t.Fatalf("%s warning = %q", action, message)
		}
	}
	ledger = ledger[1:]
	result := enterprisestatus.New("status", "standalone", "windows", "test")
	applyWindowsEnterpriseUserCleanupFailures(result)
	if len(result.Warnings) != 0 {
		t.Fatalf("no cleanup failing: warnings %+v", result.Warnings)
	}
}

// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package enterprisehooks

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"golang.org/x/sys/windows"
)

// The rollback of a failed first install puts a signed-out account's agent
// files back as the account from an S4U logon, unless the switch is "0".
func TestRestoreWindowsStandaloneUserAgentConfigsSignedOutAccount(t *testing.T) {
	sid := currentWindowsTestSID(t)
	home := t.TempDir()
	dataDir := filepath.Join(home, ".defenseclaw")
	backups := filepath.Join(dataDir, "connector_backups", "amp")
	for _, dir := range []string{backups, filepath.Join(home, ".amp")} {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	record := fmt.Sprintf(
		`{"version":1,"connector":"amp","logical_name":"settings","path":%q,"existed":false,"pristine_sha256":"missing"}`,
		filepath.Join(home, ".amp", "settings.json"),
	)
	writeRecord := func() {
		if err := os.WriteFile(filepath.Join(backups, "settings.json"), []byte(record), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	originalSession, originalS4U := windowsEnterpriseTargetImpersonation, windowsEnterpriseS4UTargetImpersonation
	t.Cleanup(func() {
		windowsEnterpriseTargetImpersonation, windowsEnterpriseS4UTargetImpersonation = originalSession, originalS4U
	})
	windowsEnterpriseTargetImpersonation = func(*windows.SID, string, func() error) error {
		return &WindowsTargetSessionUnavailableError{SID: sid.String()}
	}
	s4uCalls := 0
	windowsEnterpriseS4UTargetImpersonation = func(target *windows.SID, _ string, fn func() error) error {
		if !target.Equals(sid) {
			t.Fatalf("S4U logon for %s, want %s", target, sid)
		}
		s4uCalls++
		return fn()
	}

	writeRecord()
	if _, _, err := RestoreWindowsStandaloneUserAgentConfigs(home, sid.String(), ""); err != nil || s4uCalls != 1 {
		t.Fatalf("signed-out restore: err %v, S4U logons %d", err, s4uCalls)
	}
	t.Setenv(windowsStandaloneSignedOutRollbackSwitch, "0")
	writeRecord()
	if _, _, err := RestoreWindowsStandaloneUserAgentConfigs(home, sid.String(), ""); !IsWindowsTargetSessionUnavailable(err) || s4uCalls != 1 {
		t.Fatalf("switched off: err %v, S4U logons %d", err, s4uCalls)
	}
}

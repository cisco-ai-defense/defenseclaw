//go:build windows

// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"golang.org/x/sys/windows"
)

func TestAuditExportWindowsCreatesProtectedFileInSharedDirectory(t *testing.T) {
	shared := filepath.Join(t.TempDir(), "shared")
	if err := os.Mkdir(shared, 0o700); err != nil {
		t.Fatal(err)
	}
	sd, err := windows.SecurityDescriptorFromString("D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;FR;;;BU)")
	if err != nil {
		t.Fatal(err)
	}
	dacl, _, err := sd.DACL()
	if err != nil {
		t.Fatal(err)
	}
	if err := windows.SetNamedSecurityInfo(shared, windows.SE_FILE_OBJECT,
		windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION,
		nil, nil, dacl, nil); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(shared, "export.jsonl")
	database := auditWindowTestDatabase(t, "2026-09-27T15:53:00Z")
	previousConfig, previousOut, previousForce := cfg, auditExportOut, auditExportForce
	t.Cleanup(func() {
		cfg, auditExportOut, auditExportForce = previousConfig, previousOut, previousForce
	})
	cfg = &config.Config{AuditDB: database}
	auditExportOut, auditExportForce = path, false
	if err := runAuditExport(nil, nil); err != nil {
		t.Fatal(err)
	}
	created, err := windows.GetNamedSecurityInfo(path, windows.SE_FILE_OBJECT,
		windows.OWNER_SECURITY_INFORMATION|windows.DACL_SECURITY_INFORMATION)
	if err != nil {
		t.Fatal(err)
	}
	control, _, err := created.Control()
	if err != nil {
		t.Fatal(err)
	}
	if control&windows.SE_DACL_PROTECTED == 0 {
		t.Fatal("audit export inherited the shared directory's peer-read ACE")
	}
}

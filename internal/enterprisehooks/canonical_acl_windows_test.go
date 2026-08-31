//go:build windows

// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package enterprisehooks

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/winpath"
	"golang.org/x/sys/windows"
)

func TestWindowsUserPathProtectionACLIsExact(t *testing.T) {
	target := currentWindowsTestSID(t)
	path := filepath.Join(t.TempDir(), "managed")
	if err := os.Mkdir(path, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := setWindowsUserPathProtection(path, target, true); err != nil {
		t.Fatalf("set canonical DACL: %v", err)
	}
	if err := validateWindowsUserPathElement(path, target, true, true, true); err != nil {
		extended, _ := winpath.Extended(path)
		sd, _ := windows.GetNamedSecurityInfo(
			extended,
			windows.SE_FILE_OBJECT,
			windows.OWNER_SECURITY_INFORMATION|windows.DACL_SECURITY_INFORMATION,
		)
		if sd != nil {
			t.Logf("security descriptor: %s", sd.String())
		}
		t.Fatalf("validate canonical DACL: %v", err)
	}
}

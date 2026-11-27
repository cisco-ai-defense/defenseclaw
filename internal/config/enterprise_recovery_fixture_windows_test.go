// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package config

import (
	"os"
	"path/filepath"
	"testing"

	"golang.org/x/sys/windows"
)

// managedRecoveryRoot is a folder a managed config can sit in. On Windows the
// managed trust walk accepts the folder of an elevated test process (its
// owner is Administrators, GAP-0627), the counterpart of the root-owned path
// on Linux. A standard-user token owns nothing the walk trusts, so that leg
// skips and the elevated native leg runs the test (GAP-1821).
func managedRecoveryRoot(t *testing.T) string {
	t.Helper()
	if !windows.GetCurrentProcessToken().IsElevated() {
		t.Skip("needs an elevated token on Windows: a managed config must sit on an administrator-owned path; the elevated native leg runs this test")
	}
	return t.TempDir()
}

// untrustedRulePackDir makes a rule pack folder BUILTIN\Users can write, which
// a standalone managed config must refuse as a policy input: the Windows form
// of a folder a standard user owns.
func untrustedRulePackDir(t *testing.T, root string) string {
	t.Helper()
	pack := filepath.Join(root, "pack")
	if err := os.Mkdir(pack, 0o755); err != nil {
		t.Fatal(err)
	}
	descriptor, err := windows.SecurityDescriptorFromString("D:P(A;;FA;;;SY)(A;;FA;;;BA)(A;;FW;;;BU)")
	if err != nil {
		t.Fatal(err)
	}
	dacl, _, err := descriptor.DACL()
	if err != nil {
		t.Fatal(err)
	}
	if err := windows.SetNamedSecurityInfo(pack, windows.SE_FILE_OBJECT,
		windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION, nil, nil, dacl, nil); err != nil {
		t.Fatalf("grant Users write on %s: %v", pack, err)
	}
	return pack
}

// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package cli

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"testing"

	"golang.org/x/sys/windows"

	"github.com/defenseclaw/defenseclaw/internal/enterprisehooks"
	"github.com/defenseclaw/defenseclaw/internal/managed"
)

// GAP-1733 review P3: a token that is neither an elevated Administrator nor
// LocalSystem reads the folders by path. It cannot read another account's
// folder, and access denied there is unknown, not a per-user install. A
// non-elevated status named every other manifest account as having one. An
// entry the token can see is still named.
func TestWindowsPerUserInstallProbeWithoutBackupIntentNamesOnlyWhatItSees(t *testing.T) {
	token := windows.GetCurrentProcessToken()
	if token.IsElevated() {
		t.Skip("runs under a token without backup intent (the Limited leg)")
	}
	user, err := token.GetTokenUser()
	if err != nil {
		t.Fatal(err)
	}
	self := user.User.Sid.String()
	t.Setenv(managed.TrustStrictAncestorsEnv, "")

	visible := t.TempDir()
	if err := os.MkdirAll(filepath.Join(visible, ".defenseclaw", "installer"), 0o700); err != nil {
		t.Fatal(err)
	}
	if got := enterprisehooks.WindowsPerUserInstallDataDir(visible, self); got != "installer" {
		t.Fatalf("a per-user entry the token can see = %q, want installer", got)
	}

	// Another account's folder, as this token sees it: a DACL that grants
	// LocalSystem only. The owner keeps READ_CONTROL and WRITE_DAC, so the
	// cleanup can give the folder back.
	denied := t.TempDir()
	data := filepath.Join(denied, ".defenseclaw")
	if err := os.MkdirAll(data, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(data, "config.yaml"), []byte("gateway:\n  port: 18970\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	setDACL := func(sddl string) error {
		descriptor, err := windows.SecurityDescriptorFromString(sddl)
		if err != nil {
			return err
		}
		dacl, _, err := descriptor.DACL()
		if err != nil {
			return err
		}
		return windows.SetNamedSecurityInfo(data, windows.SE_FILE_OBJECT,
			windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION, nil, nil, dacl, nil)
	}
	if err := setDACL("D:P(A;OICI;FA;;;SY)"); err != nil {
		t.Fatalf("restrict the folder: %v", err)
	}
	t.Cleanup(func() {
		if err := setDACL("D:P(A;OICI;FA;;;OW)(A;OICI;FA;;;SY)"); err != nil {
			t.Errorf("give the folder back: %v", err)
		}
	})
	if _, err := os.Lstat(filepath.Join(data, "config.yaml")); !errors.Is(err, fs.ErrPermission) {
		t.Fatalf("the fixture's config.yaml reads as %v to this token, want access denied", err)
	}
	if got := enterprisehooks.WindowsPerUserInstallDataDir(denied, self); got != "" {
		t.Fatalf("a folder this token cannot read = %q, want unknown (none named)", got)
	}
}

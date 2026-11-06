//go:build windows

// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/managed"
	"golang.org/x/sys/windows"
)

// GAP-0652 E5 and g582 review 6 S1: on standalone the secrets folder repair
// refuses a folder an untrusted principal can write before any stamp, and
// stamps a trusted-only drift through managed.StampStandaloneTrustedObject,
// which judges the folder again on the handle it writes. Secure Client keeps
// the base stamp.
func TestWindowsSecretsDirStandaloneRefusesThenStampsOnTheSameHandle(t *testing.T) {
	if !windows.GetCurrentProcessToken().IsElevated() {
		t.Skip("needs an elevated token to stamp the fixture descriptors")
	}
	t.Setenv(managed.TrustStrictAncestorsEnv, "")
	reader, err := windows.CreateWellKnownSid(windows.WinLocalServiceSid)
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name       string
		standalone bool
		sddl       string
		wantSame   int
		wantErr    string
	}{
		{name: "standalone, trusted-only drift", standalone: true, sddl: "O:BAD:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;;0x1200a9;;;BU)", wantSame: 1},
		{name: "standalone, untrusted writer refused before any stamp", standalone: true, sddl: "O:BAD:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;;FA;;;BG)", wantErr: "the secrets folder was not repaired"},
		{name: "Secure Client keeps the base stamp", sddl: "O:BAD:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;;0x1200a9;;;BU)"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if tc.standalone {
				t.Setenv(managed.EnterpriseProfileEnv, managed.ProfileStandalone)
			} else {
				t.Setenv(managed.EnterpriseProfileEnv, "")
			}
			if managed.StandaloneRefusesContentDrift() != tc.standalone {
				t.Skip("the trust profile cannot be pinned on this host")
			}
			dir := filepath.Join(t.TempDir(), "secrets")
			if err := os.Mkdir(dir, 0o700); err != nil {
				t.Fatal(err)
			}
			descriptor, err := windows.SecurityDescriptorFromString(tc.sddl)
			if err != nil {
				t.Fatal(err)
			}
			owner, _, _ := descriptor.Owner()
			dacl, _, _ := descriptor.DACL()
			if err := managed.RunWithWindowsRepairPrivileges(func() error {
				return windows.SetNamedSecurityInfo(dir, windows.SE_FILE_OBJECT, windowsSDDLApplied, owner, nil, dacl, nil)
			}); err != nil {
				t.Fatal(err)
			}
			store, err := openWindowsSecretStore(dir, false)
			if err != nil {
				t.Fatal(err)
			}
			defer store.close()
			previous := windowsSecretsDirStandaloneStamp
			t.Cleanup(func() { windowsSecretsDirStandaloneStamp = previous })
			same := 0
			windowsSecretsDirStandaloneStamp = func(path string, kind managed.ObjectKind, sddl string) error {
				same++
				if kind != managed.ObjectAdminDirectory || !strings.Contains(sddl, reader.String()) {
					t.Errorf("same-handle stamp of %s as %s with %s", path, kind, sddl)
				}
				return previous(path, kind, sddl)
			}

			err = ensureWindowsSecretsDir(store, reader)

			if same != tc.wantSame {
				t.Fatalf("same-handle stamps = %d, want %d", same, tc.wantSame)
			}
			if tc.wantErr != "" {
				var refused *managed.StandaloneContentDriftError
				if err == nil || !strings.Contains(err.Error(), tc.wantErr) || !errors.As(err, &refused) {
					t.Fatalf("err = %v, want the standalone refusal", err)
				}
				return
			}
			if err != nil {
				t.Fatalf("ensureWindowsSecretsDir = %v", err)
			}
		})
	}
}

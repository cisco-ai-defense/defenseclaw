//go:build windows

// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package redaction

import (
	"path/filepath"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/managed"
	"golang.org/x/sys/windows"
)

// g582 review 4 S1: on standalone a correlation key whose DACL let another
// account read it (no write) was re-stamped and kept its material, which may
// already have been read. It is rotated; Secure Client keeps the re-stamp.
func TestWindowsCorrelationKeyUntrustedReaderIsRotatedOnStandalone(t *testing.T) {
	skipCorrelationKeyAsLocalSystem(t)
	if !windows.GetCurrentProcessToken().IsElevated() {
		t.Skip("needs an elevated token (the Windows CI runners and the native test hosts run elevated)")
	}
	for _, standalone := range []bool{true, false} {
		name := "standalone"
		if !standalone {
			name = "twin: Secure Client"
		}
		t.Run(name, func(t *testing.T) {
			t.Setenv(managed.TrustStrictAncestorsEnv, "")
			current, err := windows.GetCurrentProcessToken().GetTokenUser()
			if err != nil || current == nil || current.User.Sid == nil {
				t.Fatalf("resolve current Windows user: %v", err)
			}
			expected := current.User.Sid
			pinWindowsCorrelationExpectedOwner(t, &expected)
			previous := windowsCorrelationStandaloneRotates
			windowsCorrelationStandaloneRotates = func() bool { return standalone }
			t.Cleanup(func() { windowsCorrelationStandaloneRotates = previous })

			dir := t.TempDir()
			original, err := LoadOrCreateCorrelationKey(dir)
			if err != nil {
				t.Fatal(err)
			}
			path := filepath.Join(dir, correlationKeyFilename)
			descriptor, err := windows.SecurityDescriptorFromString(
				"D:P(A;;FA;;;SY)(A;;FA;;;BA)(A;;FA;;;" + expected.String() + ")(A;;FR;;;BG)")
			if err != nil {
				t.Fatal(err)
			}
			dacl, _, err := descriptor.DACL()
			if err != nil {
				t.Fatal(err)
			}
			if err := managed.RunWithWindowsRepairPrivileges(func() error {
				return windows.SetNamedSecurityInfo(path, windows.SE_FILE_OBJECT,
					windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION, nil, nil, dacl, nil)
			}); err != nil {
				t.Fatalf("grant Guests read: %v", err)
			}
			var rotated string
			realRotate := windowsCorrelationKeyRotate
			stubWindowsCorrelationOwnerRecovery(t,
				func(string, windows.Handle) error { return nil },
				func(target string, identity windows.ByHandleFileInformation) error {
					rotated = target
					return realRotate(target, identity)
				},
			)
			loaded, err := LoadOrCreateCorrelationKey(dir)
			if err != nil {
				t.Fatalf("load: %v", err)
			}
			if standalone {
				if rotated != path || loaded.ID() == original.ID() {
					t.Fatalf("rotated %q (want %q), same key %t: a key Guests could read stayed in use",
						rotated, path, loaded.ID() == original.ID())
				}
				return
			}
			if rotated != "" || loaded.ID() != original.ID() {
				t.Fatalf("Secure Client rotated %q (same key %t), want the re-stamp", rotated, loaded.ID() == original.ID())
			}
		})
	}
}

// g582 review 5 L2: a key with a null DACL, which every account can read,
// failed closed on standalone before the rotation was judged. It is rotated
// like any other key another account could read. Secure Client keeps its
// base path and never rotates.
func TestWindowsCorrelationKeyWithANullDACLIsRotatedOnStandalone(t *testing.T) {
	skipCorrelationKeyAsLocalSystem(t)
	if !windows.GetCurrentProcessToken().IsElevated() {
		t.Skip("needs an elevated token (the Windows CI runners and the native test hosts run elevated)")
	}
	for _, standalone := range []bool{true, false} {
		name := "standalone"
		if !standalone {
			name = "twin: Secure Client"
		}
		t.Run(name, func(t *testing.T) {
			t.Setenv(managed.TrustStrictAncestorsEnv, "")
			current, err := windows.GetCurrentProcessToken().GetTokenUser()
			if err != nil || current == nil || current.User.Sid == nil {
				t.Fatalf("resolve current Windows user: %v", err)
			}
			expected := current.User.Sid
			pinWindowsCorrelationExpectedOwner(t, &expected)
			previous := windowsCorrelationStandaloneRotates
			windowsCorrelationStandaloneRotates = func() bool { return standalone }
			t.Cleanup(func() { windowsCorrelationStandaloneRotates = previous })

			dir := t.TempDir()
			original, err := LoadOrCreateCorrelationKey(dir)
			if err != nil {
				t.Fatal(err)
			}
			path := filepath.Join(dir, correlationKeyFilename)
			if err := managed.RunWithWindowsRepairPrivileges(func() error {
				return windows.SetNamedSecurityInfo(path, windows.SE_FILE_OBJECT,
					windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION, nil, nil, nil, nil)
			}); err != nil {
				t.Fatalf("set a null DACL: %v", err)
			}
			var rotated string
			realRotate := windowsCorrelationKeyRotate
			stubWindowsCorrelationOwnerRecovery(t,
				func(string, windows.Handle) error { return nil },
				func(target string, identity windows.ByHandleFileInformation) error {
					rotated = target
					return realRotate(target, identity)
				},
			)
			loaded, err := LoadOrCreateCorrelationKey(dir)
			if standalone {
				if err != nil || rotated != path || loaded.ID() == original.ID() {
					t.Fatalf("load = %v, rotated %q (want %q): a key with a null DACL was not rotated", err, rotated, path)
				}
				return
			}
			if rotated != "" {
				t.Fatalf("Secure Client rotated %q (load err %v), want its base path", rotated, err)
			}
		})
	}
}

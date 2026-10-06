//go:build windows

// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"errors"
	"strings"
	"testing"

	"golang.org/x/sys/windows"

	"github.com/defenseclaw/defenseclaw/internal/managed"
)

func TestAlignEnterpriseWindowsTokenOwnerRejectsReparseChainBeforeACLWrites(t *testing.T) {
	originalCheck := enterpriseWindowsReparseChainCheck
	originalWriter := enterpriseWindowsProtectionWriter
	t.Cleanup(func() {
		enterpriseWindowsReparseChainCheck = originalCheck
		enterpriseWindowsProtectionWriter = originalWriter
	})

	enterpriseWindowsReparseChainCheck = func(string) error {
		return errors.New("reparse point in path")
	}
	writes := 0
	enterpriseWindowsProtectionWriter = func(string, *windows.SID, *windows.SID, windows.ACCESS_MASK, bool) error {
		writes++
		return nil
	}

	err := alignEnterpriseWindowsTokenOwner(`C:\managed`, `C:\managed\hooks\.hook-claudecode.token`, "hook token")
	if err == nil || !strings.Contains(err.Error(), "reparse point") {
		t.Fatalf("alignEnterpriseWindowsTokenOwner error = %v, want reparse refusal", err)
	}
	if writes != 0 {
		t.Fatalf("ACL writes = %d, want zero before reparse-chain rejection", writes)
	}
}

// TestRepairEnterpriseHookManagedRuntimePlatformWrapsPrivilegedWrite pins the
// managed runtime repair contract: the reparse-chain refusal still runs before
// any ACL write, the write goes through the shared runtime-protection helper
// with the service-modify mask, and a failed write keeps its cause.
func TestRepairEnterpriseHookManagedRuntimePlatformWrapsPrivilegedWrite(t *testing.T) {
	const serviceAccount = `NT SERVICE\DefenseClawTestGateway`

	stubOwnerAndSID := func(t *testing.T) {
		t.Helper()
		originalOwner := enterpriseWindowsManagedPathOwner
		originalSID := enterpriseWindowsGatewaySID
		t.Cleanup(func() {
			enterpriseWindowsManagedPathOwner = originalOwner
			enterpriseWindowsGatewaySID = originalSID
		})
		system, err := windows.CreateWellKnownSid(windows.WinLocalSystemSid)
		if err != nil {
			t.Fatal(err)
		}
		serviceSID, err := windows.StringToSid("S-1-5-80-11-22-33-44-55")
		if err != nil {
			t.Fatal(err)
		}
		enterpriseWindowsManagedPathOwner = func(string) (*windows.SID, error) { return system, nil }
		enterpriseWindowsGatewaySID = func() (*windows.SID, error) { return serviceSID, nil }
	}

	driftedDir := func(t *testing.T) string {
		t.Helper()
		dir := t.TempDir()
		if err := managed.ValidateTrustedServiceRuntimeDir(dir, "managed data_dir", serviceAccount); err == nil {
			t.Skip("temp directory already satisfies the managed runtime contract")
		}
		return dir
	}

	t.Run("reparse chain is refused before any ACL write", func(t *testing.T) {
		dir := driftedDir(t)
		originalCheck := enterpriseWindowsReparseChainCheck
		originalWriter := enterpriseWindowsProtectionWriter
		t.Cleanup(func() {
			enterpriseWindowsReparseChainCheck = originalCheck
			enterpriseWindowsProtectionWriter = originalWriter
		})
		enterpriseWindowsReparseChainCheck = func(string) error {
			return errors.New("reparse point in path")
		}
		writes := 0
		enterpriseWindowsProtectionWriter = func(string, *windows.SID, *windows.SID, windows.ACCESS_MASK, bool) error {
			writes++
			return nil
		}

		err := repairEnterpriseHookManagedRuntimePlatform(dir, serviceAccount)
		if err == nil || !strings.Contains(err.Error(), "refusing unsafe managed data_dir") {
			t.Fatalf("repair error = %v, want reparse refusal", err)
		}
		if writes != 0 {
			t.Fatalf("ACL writes = %d, want zero before reparse-chain rejection", writes)
		}
	})

	t.Run("write uses the service-modify mask and keeps its cause", func(t *testing.T) {
		dir := driftedDir(t)
		stubOwnerAndSID(t)
		originalCheck := enterpriseWindowsReparseChainCheck
		originalWriter := enterpriseWindowsProtectionWriter
		t.Cleanup(func() {
			enterpriseWindowsReparseChainCheck = originalCheck
			enterpriseWindowsProtectionWriter = originalWriter
		})
		enterpriseWindowsReparseChainCheck = func(string) error { return nil }

		writes := 0
		var gotMask windows.ACCESS_MASK
		gotDirectory := false
		enterpriseWindowsProtectionWriter = func(
			_ string,
			_ *windows.SID,
			_ *windows.SID,
			mask windows.ACCESS_MASK,
			directory bool,
		) error {
			writes++
			gotMask = mask
			gotDirectory = directory
			return errors.New("injected managed ACL failure")
		}

		err := repairEnterpriseHookManagedRuntimePlatform(dir, serviceAccount)
		if err == nil {
			t.Fatal("repair error = nil, want the injected write failure")
		}
		if !strings.Contains(err.Error(), "repair managed data_dir ACL") ||
			!strings.Contains(err.Error(), "injected managed ACL failure") {
			t.Fatalf("repair error = %v, want a wrapped write failure", err)
		}
		if writes != 1 {
			t.Fatalf("ACL writes = %d, want exactly one", writes)
		}
		const wantMask = windows.ACCESS_MASK(
			windows.GENERIC_READ |
				windows.GENERIC_WRITE |
				windows.GENERIC_EXECUTE |
				windows.DELETE,
		)
		if gotMask != wantMask {
			t.Fatalf("service mask = %#x, want %#x", gotMask, wantMask)
		}
		if !gotDirectory {
			t.Fatal("repair applied the file contract, want the directory contract")
		}
	})

	t.Run("untrusted owner is never adopted", func(t *testing.T) {
		dir := driftedDir(t)
		originalOwner := enterpriseWindowsManagedPathOwner
		originalSID := enterpriseWindowsGatewaySID
		originalCheck := enterpriseWindowsReparseChainCheck
		originalWriter := enterpriseWindowsProtectionWriter
		t.Cleanup(func() {
			enterpriseWindowsManagedPathOwner = originalOwner
			enterpriseWindowsGatewaySID = originalSID
			enterpriseWindowsReparseChainCheck = originalCheck
			enterpriseWindowsProtectionWriter = originalWriter
		})
		enterpriseWindowsReparseChainCheck = func(string) error { return nil }
		untrusted, err := windows.StringToSid("S-1-5-21-1000-2000-3000-1001")
		if err != nil {
			t.Fatal(err)
		}
		serviceSID, err := windows.StringToSid("S-1-5-80-11-22-33-44-55")
		if err != nil {
			t.Fatal(err)
		}
		enterpriseWindowsManagedPathOwner = func(string) (*windows.SID, error) { return untrusted, nil }
		enterpriseWindowsGatewaySID = func() (*windows.SID, error) { return serviceSID, nil }
		writes := 0
		enterpriseWindowsProtectionWriter = func(string, *windows.SID, *windows.SID, windows.ACCESS_MASK, bool) error {
			writes++
			return nil
		}

		err = repairEnterpriseHookManagedRuntimePlatform(dir, serviceAccount)
		if err == nil || !strings.Contains(err.Error(), "owner is not trusted") {
			t.Fatalf("repair error = %v, want an untrusted-owner refusal", err)
		}
		if writes != 0 {
			t.Fatalf("ACL writes = %d, want zero for an untrusted owner", writes)
		}
	})
}

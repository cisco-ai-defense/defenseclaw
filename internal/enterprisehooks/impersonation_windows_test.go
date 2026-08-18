//go:build windows

// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package enterprisehooks

import (
	"errors"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/sys/windows"
)

func TestWindowsEnterpriseTokenSecurityFactsRejectPrivilege(t *testing.T) {
	tests := []struct {
		name    string
		facts   windowsEnterpriseTokenSecurityFacts
		wantErr string
	}{
		{
			name:  "standard_default_medium",
			facts: windowsEnterpriseTokenSecurityFacts{elevationType: 1, integrityRID: 0x2000},
		},
		{
			name:  "filtered_admin_limited_medium",
			facts: windowsEnterpriseTokenSecurityFacts{elevationType: 3, integrityRID: 0x2000},
		},
		{
			name:    "elevated_flag",
			facts:   windowsEnterpriseTokenSecurityFacts{elevated: 1, elevationType: 2, integrityRID: 0x3000},
			wantErr: "elevated token",
		},
		{
			name:    "full_admin",
			facts:   windowsEnterpriseTokenSecurityFacts{elevationType: 2, integrityRID: 0x2000},
			wantErr: "full administrator token",
		},
		{
			name:    "high_integrity",
			facts:   windowsEnterpriseTokenSecurityFacts{elevationType: 1, integrityRID: 0x3000},
			wantErr: "high-integrity token",
		},
		{
			name:    "ui_access",
			facts:   windowsEnterpriseTokenSecurityFacts{elevationType: 1, integrityRID: 0x2000, uiAccess: 1},
			wantErr: "UIAccess token",
		},
		{
			name:    "unknown_elevation_type",
			facts:   windowsEnterpriseTokenSecurityFacts{elevationType: 99, integrityRID: 0x2000},
			wantErr: "unknown token elevation type",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			err := validateWindowsEnterpriseTokenSecurityFacts(tc.facts)
			if tc.wantErr == "" {
				if err != nil {
					t.Fatalf("validation failed: %v", err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("validation error = %v, want %q", err, tc.wantErr)
			}
		})
	}
}

func TestWindowsEnterpriseImpersonationHasNoLocalSystemFallback(t *testing.T) {
	target, err := windows.StringToSid("S-1-5-21-1-2-3-1001")
	if err != nil {
		t.Fatal(err)
	}
	sentinel := errors.New("not LocalSystem")
	originalIdentity := windowsEnterpriseMutationIdentityCheck
	originalResolver := windowsEnterpriseTargetTokenResolver
	windowsEnterpriseMutationIdentityCheck = func() error { return sentinel }
	resolverCalled := false
	windowsEnterpriseTargetTokenResolver = func(*windows.SID) (windows.Token, error) {
		resolverCalled = true
		return 0, errors.New("must not resolve")
	}
	t.Cleanup(func() {
		windowsEnterpriseMutationIdentityCheck = originalIdentity
		windowsEnterpriseTargetTokenResolver = originalResolver
	})

	mutationCalled := false
	err = withWindowsEnterpriseTargetImpersonation(target, `C:\Users\alice`, func() error {
		mutationCalled = true
		return nil
	})
	if !errors.Is(err, sentinel) {
		t.Fatalf("withWindowsEnterpriseTargetImpersonation error = %v, want %v", err, sentinel)
	}
	if resolverCalled || mutationCalled {
		t.Fatalf("identity failure fell through: resolver=%v mutation=%v", resolverCalled, mutationCalled)
	}
}

func TestWindowsEnterpriseTokenSIDMustExactlyMatchManifest(t *testing.T) {
	target, err := windows.StringToSid("S-1-5-21-1-2-3-1001")
	if err != nil {
		t.Fatal(err)
	}
	err = validateWindowsEnterpriseTokenSID(windows.GetCurrentProcessToken(), target)
	if err == nil || !strings.Contains(err.Error(), "does not match manifest SID") {
		t.Fatalf("validateWindowsEnterpriseTokenSID error = %v, want exact SID mismatch", err)
	}
}

func TestWindowsEnterpriseTokenProfileMustMatchManifestHome(t *testing.T) {
	originalProfile := windowsEnterpriseTokenProfileDirectory
	t.Cleanup(func() { windowsEnterpriseTokenProfileDirectory = originalProfile })

	expected := filepath.Join(`C:\Users`, "Alice")
	windowsEnterpriseTokenProfileDirectory = func(windows.Token) (string, error) {
		return filepath.Join(`c:\users`, "ALICE"), nil
	}
	if err := validateWindowsEnterpriseTokenProfile(0, expected); err != nil {
		t.Fatalf("case-insensitive canonical profile match failed: %v", err)
	}

	windowsEnterpriseTokenProfileDirectory = func(windows.Token) (string, error) {
		return `C:\Users\Mallory`, nil
	}
	err := validateWindowsEnterpriseTokenProfile(0, expected)
	if err == nil || !strings.Contains(err.Error(), "does not match active target token profile") {
		t.Fatalf("profile mismatch error = %v, want distinct manifest/token profile refusal", err)
	}
}

func TestWindowsEnterpriseRevertFailureNeverUnlocksImpersonatedThread(t *testing.T) {
	target, err := windows.StringToSid("S-1-5-21-1-2-3-1001")
	if err != nil {
		t.Fatal(err)
	}
	originalSet := windowsEnterpriseSetThreadToken
	originalRevert := windowsEnterpriseRevertThreadToken
	originalLock := windowsEnterpriseLockOSThread
	originalUnlock := windowsEnterpriseUnlockOSThread
	originalEffectiveCheck := windowsEnterpriseEffectiveTokenCheck
	revertFailure := errors.New("forced RevertToSelf failure")
	lockCalls := 0
	unlockCalls := 0
	windowsEnterpriseSetThreadToken = func(*windows.Handle, windows.Token) error { return nil }
	windowsEnterpriseRevertThreadToken = func() error { return revertFailure }
	windowsEnterpriseLockOSThread = func() { lockCalls++ }
	windowsEnterpriseUnlockOSThread = func() { unlockCalls++ }
	windowsEnterpriseEffectiveTokenCheck = func(*windows.SID) error { return nil }
	t.Cleanup(func() {
		windowsEnterpriseSetThreadToken = originalSet
		windowsEnterpriseRevertThreadToken = originalRevert
		windowsEnterpriseLockOSThread = originalLock
		windowsEnterpriseUnlockOSThread = originalUnlock
		windowsEnterpriseEffectiveTokenCheck = originalEffectiveCheck
	})

	callbackCalled := false
	err = runWindowsEnterpriseImpersonatedCallback(1, target, func() error {
		callbackCalled = true
		return nil
	})
	if err == nil || !strings.Contains(err.Error(), "revert target SID impersonation") {
		t.Fatalf("runWindowsEnterpriseImpersonatedCallback error = %v, want revert failure", err)
	}
	if !callbackCalled || lockCalls != 1 {
		t.Fatalf("callback=%v lockCalls=%d, want callback and one dedicated lock", callbackCalled, lockCalls)
	}
	if unlockCalls != 0 {
		t.Fatalf("UnlockOSThread called %d time(s) after failed revert; leaked identity could re-enter the thread pool", unlockCalls)
	}
}

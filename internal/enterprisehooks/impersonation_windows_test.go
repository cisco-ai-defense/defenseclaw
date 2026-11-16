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

func TestWindowsEnterpriseTokenSecurityFactsAdvisory(t *testing.T) {
	tests := []struct {
		name         string
		facts        windowsEnterpriseTokenSecurityFacts
		wantAdvisory string // empty = clean pass (non-admin session)
		wantErr      string // set only for real integrity failures
	}{
		{
			name:  "standard_default_medium",
			facts: windowsEnterpriseTokenSecurityFacts{elevationType: 1, integrityRID: 0x2000},
		},
		{
			name:  "filtered_admin_limited_medium",
			facts: windowsEnterpriseTokenSecurityFacts{elevationType: 3, integrityRID: 0x2000},
		},
		// Cases that USED to be hard-rejected now produce a non-empty
		// advisory but no error. Enrollment proceeds; caller logs the
		// advisory. Reconciler restores drift.
		{
			name:         "elevated_flag_now_advisory",
			facts:        windowsEnterpriseTokenSecurityFacts{elevated: 1, elevationType: 2, integrityRID: 0x3000},
			wantAdvisory: "elevated+full-administrator+high-integrity(RID=0x3000)",
		},
		{
			name:         "full_admin_now_advisory",
			facts:        windowsEnterpriseTokenSecurityFacts{elevationType: 2, integrityRID: 0x2000},
			wantAdvisory: "full-administrator",
		},
		{
			name:         "high_integrity_now_advisory",
			facts:        windowsEnterpriseTokenSecurityFacts{elevationType: 1, integrityRID: 0x3000},
			wantAdvisory: "high-integrity(RID=0x3000)",
		},
		{
			name:         "ui_access_now_advisory",
			facts:        windowsEnterpriseTokenSecurityFacts{elevationType: 1, integrityRID: 0x2000, uiAccess: 1},
			wantAdvisory: "UIAccess",
		},
		// Unknown elevation type stays a hard error — that's a real
		// integrity failure of the token itself, not "user is admin."
		{
			name:    "unknown_elevation_type",
			facts:   windowsEnterpriseTokenSecurityFacts{elevationType: 99, integrityRID: 0x2000},
			wantErr: "unknown token elevation type",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			advisory, err := assessWindowsEnterpriseTokenSecurityFacts(tc.facts)
			if tc.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
					t.Fatalf("assess error = %v, want %q", err, tc.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("assess failed: %v", err)
			}
			if advisory != tc.wantAdvisory {
				t.Fatalf("advisory = %q, want %q", advisory, tc.wantAdvisory)
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

// GAP-0585: an install under WindowsTargetLogonAnyWithS4U acts as the user
// under the active or disconnected session, else an S4U logon, and a refused
// S4U logon is ErrEnrolledUserSignedOut before anything runs as the user.
// Every other install keeps the active session only.
func TestWindowsEnterpriseInstallLogonSelectsTheTargetToken(t *testing.T) {
	target, err := windows.StringToSid("S-1-5-21-1-2-3-1001")
	if err != nil {
		t.Fatal(err)
	}
	originalIdentity := windowsEnterpriseMutationIdentityCheck
	originalActive, originalSignedIn, originalS4U := windowsEnterpriseTargetTokenResolver, windowsEnterpriseSignedInTargetTokenResolver, windowsEnterpriseS4UTargetTokenResolver
	t.Cleanup(func() {
		windowsEnterpriseMutationIdentityCheck = originalIdentity
		windowsEnterpriseTargetTokenResolver, windowsEnterpriseSignedInTargetTokenResolver, windowsEnterpriseS4UTargetTokenResolver = originalActive, originalSignedIn, originalS4U
	})
	windowsEnterpriseMutationIdentityCheck = func() error { return nil }
	var calls []string
	signedInErr := error(&WindowsTargetSessionUnavailableError{SID: target.String()})
	windowsEnterpriseTargetTokenResolver = func(*windows.SID) (windows.Token, error) {
		calls = append(calls, "active")
		return 0, &WindowsTargetSessionUnavailableError{SID: target.String()}
	}
	windowsEnterpriseSignedInTargetTokenResolver = func(*windows.SID) (windows.Token, error) {
		calls = append(calls, "signed-in")
		return 0, signedInErr
	}
	windowsEnterpriseS4UTargetTokenResolver = func(*windows.SID) (windows.Token, error) {
		calls = append(calls, "s4u")
		return 0, errors.New("No credentials are available in the security package")
	}
	ran := false
	impersonate := func() error {
		calls, ran = nil, false
		return withWindowsEnterpriseTargetImpersonation(target, `C:\Users\alice`, func() error {
			ran = true
			return nil
		})
	}

	if err := impersonate(); !IsWindowsTargetSessionUnavailable(err) || ran || strings.Join(calls, ",") != "active" {
		t.Fatalf("default install: err=%v ran=%v calls=%v, want the active session only", err, ran, calls)
	}
	release := useWindowsEnterpriseInstallLogon(target.String(), WindowsTargetLogonAnyWithS4U)
	if err := impersonate(); !errors.Is(err, ErrEnrolledUserSignedOut) || ran || strings.Join(calls, ",") != "signed-in,s4u" {
		t.Fatalf("closing install: err=%v ran=%v calls=%v, want signed-in then S4U, refused", err, ran, calls)
	}
	calls = nil
	if err := RequireWindowsEnterpriseTargetLogon(target.String(), `C:\Users\alice`, WindowsTargetLogonAnyWithS4U); !errors.Is(err, ErrEnrolledUserSignedOut) ||
		strings.Join(calls, ",") != "signed-in,s4u" {
		t.Fatalf("closing logon check: err=%v calls=%v, want signed-in then S4U, refused", err, calls)
	}
	signedInErr = errors.New("WTSQueryUserToken: access denied")
	if err := impersonate(); err == nil || errors.Is(err, ErrEnrolledUserSignedOut) || strings.Join(calls, ",") != "signed-in" {
		t.Fatalf("closing install, session query failed: err=%v calls=%v, want that failure and no S4U", err, calls)
	}
	release()
	if err := impersonate(); !IsWindowsTargetSessionUnavailable(err) || strings.Join(calls, ",") != "active" {
		t.Fatalf("after the install: err=%v calls=%v, want the active session only", err, calls)
	}
}

//go:build windows

// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"errors"
	"os/user"
	"path/filepath"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/enterprisehooks"
	"github.com/defenseclaw/defenseclaw/internal/gateway/connector"
)

func TestDeferredTargetSessionAvailabilityDowngradesOnlyTypedAbsence(t *testing.T) {
	previous := enterpriseHookWindowsTargetSessionCheck
	previousPending := enterpriseHookWindowsDeferredPendingCheck
	t.Cleanup(func() {
		enterpriseHookWindowsTargetSessionCheck = previous
		enterpriseHookWindowsDeferredPendingCheck = previousPending
	})
	target := enterprisehooks.ManifestTarget{
		SID:      "S-1-5-21-1-2-3-1001",
		UserHome: `C:\Users\alice`,
	}
	enterpriseHookWindowsDeferredPendingCheck = func(enterprisehooks.ManifestTarget) error {
		return nil
	}

	enterpriseHookWindowsTargetSessionCheck = func(string, string) error {
		return &enterprisehooks.WindowsTargetSessionUnavailableError{SID: target.SID}
	}
	available, err := enterpriseHookDeferredTargetSessionAvailable(target)
	if err != nil || available {
		t.Fatalf("typed absence = available %t err %v, want false/nil", available, err)
	}

	sentinel := errors.New("WTS token query denied")
	enterpriseHookWindowsTargetSessionCheck = func(string, string) error {
		return sentinel
	}
	available, err = enterpriseHookDeferredTargetSessionAvailable(target)
	if available || !errors.Is(err, sentinel) {
		t.Fatalf("ordinary WTS failure = available %t err %v, want hard error", available, err)
	}

	enterpriseHookWindowsTargetSessionCheck = func(string, string) error {
		return &enterprisehooks.WindowsTargetSessionUnavailableError{SID: target.SID}
	}
	selectorErr := errors.New("selected runtime lacks protected authorization")
	enterpriseHookWindowsDeferredPendingCheck = func(enterprisehooks.ManifestTarget) error {
		return selectorErr
	}
	available, err = enterpriseHookDeferredTargetSessionAvailable(target)
	if available || !errors.Is(err, selectorErr) {
		t.Fatalf("stale runtime = available %t err %v, want hard error", available, err)
	}

	available, err = enterpriseHookTargetSessionAvailable(target)
	if err != nil || available {
		t.Fatalf("protected-runtime session absence = available %t err %v, want false/nil", available, err)
	}
}

func TestDeferredPendingRaceRechecksSessionAndSelectorState(t *testing.T) {
	previousSession := enterpriseHookWindowsTargetSessionCheck
	previousPending := enterpriseHookWindowsDeferredPendingCheck
	t.Cleanup(func() {
		enterpriseHookWindowsTargetSessionCheck = previousSession
		enterpriseHookWindowsDeferredPendingCheck = previousPending
	})
	target := enterprisehooks.ManifestTarget{
		SID:       "S-1-5-21-1-2-3-1001",
		UserHome:  `C:\Users\alice`,
		Connector: "codex",
		Deferred:  true,
	}
	original := &enterprisehooks.WindowsTargetSessionUnavailableError{SID: target.SID}
	enterpriseHookWindowsTargetSessionCheck = func(string, string) error { return original }
	enterpriseHookWindowsDeferredPendingCheck = func(enterprisehooks.ManifestTarget) error { return nil }

	pending, err := enterpriseHookDeferredPendingAfterSessionError(target, false, original)
	if err != nil || !pending {
		t.Fatalf("stable absence = pending %t err %v, want true/nil", pending, err)
	}

	enterpriseHookWindowsTargetSessionCheck = func(string, string) error { return nil }
	pending, err = enterpriseHookDeferredPendingAfterSessionError(target, false, original)
	if pending || !errors.Is(err, original) {
		t.Fatalf("session reappeared = pending %t err %v, want original hard error", pending, err)
	}
}

// TestSignedOutEnumeratorRowIsPendingOnlyWhenDeferred pins the reconcile
// classification issue #894 depends on: a never-protected target whose user
// has no active session is pending (not a failure that withholds the
// enrollment publication for every SID) only when the manifest row carries the
// deferred bit, which the enumerator now writes on every new row.
func TestSignedOutEnumeratorRowIsPendingOnlyWhenDeferred(t *testing.T) {
	previousSession := enterpriseHookWindowsTargetSessionCheck
	previousPending := enterpriseHookWindowsDeferredPendingCheck
	t.Cleanup(func() {
		enterpriseHookWindowsTargetSessionCheck = previousSession
		enterpriseHookWindowsDeferredPendingCheck = previousPending
	})
	enabled := true
	target := enterprisehooks.ManifestTarget{
		SID:          "S-1-5-21-1-2-3-1001",
		UserHome:     `C:\Users\alice`,
		Connector:    "claudecode",
		AgentVersion: "2.1.152",
		Enabled:      &enabled,
		Deferred:     true,
	}
	absent := &enterprisehooks.WindowsTargetSessionUnavailableError{SID: target.SID}
	enterpriseHookWindowsTargetSessionCheck = func(string, string) error { return absent }
	enterpriseHookWindowsDeferredPendingCheck = func(enterprisehooks.ManifestTarget) error { return nil }

	available, err := enterpriseHookDeferredTargetSessionAvailable(target)
	if err != nil || available {
		t.Fatalf("deferred signed-out row pre-check = available %t err %v, want false/nil (pending)", available, err)
	}
	pending, err := enterpriseHookDeferredPendingAfterSessionError(target, false, absent)
	if err != nil || !pending {
		t.Fatalf("deferred signed-out row = pending %t err %v, want true/nil", pending, err)
	}

	legacy := target
	legacy.Deferred = false
	pending, err = enterpriseHookDeferredPendingAfterSessionError(legacy, false, absent)
	if pending || !errors.Is(err, absent) {
		t.Fatalf("non-deferred signed-out row = pending %t err %v, want hard session error", pending, err)
	}
}

// TestTargetAwaitingFirstSignInRequiresTypedAbsenceAndNoSelection pins the
// #894 classifier: only the typed WTS absence for the exact SID, with no
// managed runtime selected for the target, lets a failed never-protected
// target stop withholding everyone else's enrollment publication.
func TestTargetAwaitingFirstSignInRequiresTypedAbsenceAndNoSelection(t *testing.T) {
	previousSession := enterpriseHookWindowsTargetSessionCheck
	previousUnselected := enterpriseHookWindowsTargetUnselectedCheck
	t.Cleanup(func() {
		enterpriseHookWindowsTargetSessionCheck = previousSession
		enterpriseHookWindowsTargetUnselectedCheck = previousUnselected
	})
	enabled := true
	target := enterprisehooks.ManifestTarget{
		SID:          "S-1-5-21-1-2-3-1105",
		UserHome:     `C:\Users\bob`,
		Connector:    "claudecode",
		AgentVersion: "2.1.152",
		Enabled:      &enabled,
		Deferred:     true,
	}
	absent := &enterprisehooks.WindowsTargetSessionUnavailableError{SID: target.SID}
	selected := errors.New("enterprise hooks: target already has a selected managed runtime")
	for _, tc := range []struct {
		name       string
		session    error
		unselected error
		want       bool
	}{
		{"signed_out_and_unselected", absent, nil, true},
		{"signed_in", nil, nil, false},
		{"wts_query_failed", errors.New("WTS token query denied"), nil, false},
		{"signed_out_but_runtime_selected", absent, selected, false},
	} {
		enterpriseHookWindowsTargetSessionCheck = func(string, string) error { return tc.session }
		enterpriseHookWindowsTargetUnselectedCheck = func(enterprisehooks.ManifestTarget) error { return tc.unselected }
		if got := enterpriseHookTargetAwaitingFirstSignIn(target); got != tc.want {
			t.Errorf("%s: awaiting first sign-in = %t, want %t", tc.name, got, tc.want)
		}
	}
}

// TestReconcileSignedOutEnumeratorRowWithoutRootDoesNotBlockOthers is the
// reviewer's #894 scenario on the real deferred pending proof: an enumerator
// row discovered after install (deferred, never protected) whose user is
// signed out and whose canonical <home>\.defenseclaw root was never created.
// The pending proof rejects the absent root, so the row is a failure, but it
// no longer withholds the exact enrollment publication for the other SIDs.
func TestReconcileSignedOutEnumeratorRowWithoutRootDoesNotBlockOthers(t *testing.T) {
	stubSignInIsolationReconcile(t)
	previousSession := enterpriseHookWindowsTargetSessionCheck
	previousPending := enterpriseHookWindowsDeferredPendingCheck
	previousUnselected := enterpriseHookWindowsTargetUnselectedCheck
	t.Cleanup(func() {
		enterpriseHookWindowsTargetSessionCheck = previousSession
		enterpriseHookWindowsDeferredPendingCheck = previousPending
		enterpriseHookWindowsTargetUnselectedCheck = previousUnselected
	})
	const signedOutSID = "S-1-5-21-1000-2000-3000-1105"
	enterpriseHookWindowsTargetSessionCheck = func(sid, _ string) error {
		if strings.EqualFold(sid, signedOutSID) {
			return &enterprisehooks.WindowsTargetSessionUnavailableError{SID: sid}
		}
		return nil
	}
	// Keep the production pending proof; only the machine selector read is
	// isolated from this host (enterprisehooks tests cover it directly).
	enterpriseHookWindowsDeferredPendingCheck = enterprisehooks.RequireWindowsEnterpriseDeferredTargetPending
	enterpriseHookWindowsTargetUnselectedCheck = func(enterprisehooks.ManifestTarget) error { return nil }

	fixture, run := runSignInIsolationReconcileWithOptions(t, []signInIsolationTarget{
		{name: "alice", sid: "S-1-5-21-1000-2000-3000-1101", connector: "claudecode"},
		{name: "newuser", sid: signedOutSID, connector: "claudecode", deferred: true},
	}, signInIsolationOptions{realClassifier: true})
	if run.Failures != 1 || run.Pending != 0 {
		t.Fatalf("run failures=%d pending=%d, want the rootless signed-out row as the only failure", run.Failures, run.Pending)
	}
	for _, row := range run.Rows {
		if row.UserHome != fixture.homes["newuser"] {
			continue
		}
		// An elevated test token owns the fixture home as Administrators, so
		// the proof reaches the absent data root; a non-elevated token is
		// refused one step earlier at the profile anchor. Both are the
		// pending proof failing for a never-installed profile.
		if row.OK || row.Pending ||
			!(strings.Contains(row.Error, "deferred target data directory is untrusted") ||
				strings.Contains(row.Error, "user home anchor owner")) {
			t.Fatalf("rootless signed-out row = %+v, want the pending proof's refusal", row)
		}
		t.Logf("rootless signed-out row error: %s", row.Error)
	}
	if got := exactPublications(fixture); len(got) != 1 || strings.Join(got[0], ",") != "alice" {
		t.Fatalf("exact enrollment publications = %v, want one publication of alice", got)
	}
	if strings.Join(fixture.classified, ",") != "newuser" {
		t.Fatalf("sign-in classifier consulted for %v, want only newuser", fixture.classified)
	}
}

func TestExpandEnterpriseHookProfileImagePathUsesTrustedSystemDrive(t *testing.T) {
	previous := enterpriseHookWindowsSystemDirectory
	t.Cleanup(func() { enterpriseHookWindowsSystemDirectory = previous })
	enterpriseHookWindowsSystemDirectory = func() (string, error) {
		return `D:\Windows\System32`, nil
	}
	t.Setenv("SystemDrive", `Z:`)

	got, err := expandEnterpriseHookProfileImagePath(`%SystemDrive%\Users\managed`)
	if err != nil {
		t.Fatalf("expand ProfileImagePath: %v", err)
	}
	want := filepath.Clean(`D:\Users\managed`)
	if filepath.Clean(got) != want {
		t.Fatalf("expanded ProfileImagePath = %q, want %q", got, want)
	}
}

func TestExpandEnterpriseHookProfileImagePathRejectsOtherVariables(t *testing.T) {
	if _, err := expandEnterpriseHookProfileImagePath(`%USERPROFILE%\managed`); err == nil {
		t.Fatal("ProfileImagePath with user-controlled expansion was accepted")
	}
}

func TestWindowsEnterpriseDesiredEnrollmentsResolvesLocalUser(t *testing.T) {
	current, err := user.Current()
	if err != nil {
		t.Fatalf("resolve current user: %v", err)
	}
	manifest := enterprisehooks.Manifest{Targets: []enterprisehooks.ManifestTarget{{
		User:      current.Username,
		Connector: "codex",
	}}}

	_, codex, err := windowsEnterpriseDesiredEnrollments(manifest)
	if err != nil {
		t.Fatalf("resolve desired enrollments: %v", err)
	}
	if len(codex) != 1 {
		t.Fatalf("Codex enrollment count = %d, want 1", len(codex))
	}
	if !strings.EqualFold(codex[0].SID, current.Uid) {
		t.Fatalf("Codex enrollment SID = %q, want %q", codex[0].SID, current.Uid)
	}
	wantDataDir := filepath.Join(filepath.Clean(current.HomeDir), ".defenseclaw")
	if !sameWindowsEnterprisePathCLI(codex[0].DataDir, wantDataDir) {
		t.Fatalf("Codex enrollment data dir = %q, want %q", codex[0].DataDir, wantDataDir)
	}
}

func TestManagedEnrollmentIdentityRejectsStaleDeploymentWithSameSID(t *testing.T) {
	previousClaude := enterpriseHookClaudePolicyIdentityVerifier
	previousCursor := enterpriseHookCursorPolicyIdentityVerifier
	t.Cleanup(func() {
		enterpriseHookClaudePolicyIdentityVerifier = previousClaude
		enterpriseHookCursorPolicyIdentityVerifier = previousCursor
	})
	opts := connector.WindowsCodexMachineRequirementsOptions{
		HookBinary:         `C:\Program Files\Cisco\DefenseClaw\defenseclaw-hook.exe`,
		GatewayAddr:        "127.0.0.1:32109",
		GatewayServiceName: "DefenseClawGateway",
	}
	current := connector.WindowsCodexManagedRuntimeRegistry{
		Active:             true,
		GatewayAddr:        opts.GatewayAddr,
		GatewayServiceName: opts.GatewayServiceName,
		Targets: []connector.WindowsCodexManagedRuntimeTarget{{
			SID:     "S-1-5-21-1-2-3-1001",
			DataDir: `C:\Users\alice\.defenseclaw`,
		}},
	}
	enterpriseHookClaudePolicyIdentityVerifier = func(string, string, string) error { return nil }
	enterpriseHookCursorPolicyIdentityVerifier = func(string, string, string) error { return nil }
	if err := verifyWindowsEnterpriseManagedPolicyIdentities(
		opts, true, current, true,
	); err != nil {
		t.Fatalf("exact identity: %v", err)
	}

	staleClaude := errors.New("stale Claude gateway identity")
	enterpriseHookClaudePolicyIdentityVerifier = func(string, string, string) error { return staleClaude }
	if err := verifyWindowsEnterpriseManagedPolicyIdentities(
		opts, true, current, true,
	); !errors.Is(err, staleClaude) {
		t.Fatalf("stale Claude identity error = %v, want %v", err, staleClaude)
	}

	enterpriseHookClaudePolicyIdentityVerifier = func(string, string, string) error { return nil }
	staleCursor := errors.New("stale Cursor gateway identity")
	enterpriseHookCursorPolicyIdentityVerifier = func(string, string, string) error { return staleCursor }
	if err := verifyWindowsEnterpriseManagedPolicyIdentities(
		opts, true, current, true,
	); !errors.Is(err, staleCursor) {
		t.Fatalf("stale Cursor identity error = %v, want %v", err, staleCursor)
	}

	enterpriseHookCursorPolicyIdentityVerifier = func(string, string, string) error { return nil }
	current.GatewayServiceName = "DefenseClawGateway_Old"
	if err := verifyWindowsEnterpriseManagedPolicyIdentities(
		opts, true, current, true,
	); err == nil {
		t.Fatal("stale Codex gateway identity was accepted because the SID set matched")
	}
}

// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package enterprisehooks

import (
	"errors"
	"os"
	"testing"
	"time"

	"golang.org/x/sys/windows"
)

func setWindowsRelaxWaitForTest(t *testing.T, wait time.Duration) {
	t.Helper()
	originalWait, originalPoll := windowsManagedRuntimeSetupRelaxWait, windowsManagedRuntimeSetupRelaxPoll
	windowsManagedRuntimeSetupRelaxWait, windowsManagedRuntimeSetupRelaxPoll = wait, 10*time.Millisecond
	t.Cleanup(func() {
		windowsManagedRuntimeSetupRelaxWait, windowsManagedRuntimeSetupRelaxPoll = originalWait, originalPoll
	})
}

// GAP-1502 bounds: only the guardian's exact target-owned setup shape waits.
// A DACL that differs from it in any way (an extra grant, a missing protected
// flag, another owner) is tampered or invalid state and is refused at once;
// a setup shape that does not return to canonical within the bound is
// refused too. None of these ever resolves.
func TestWindowsManagedRuntimeResolveRefusesNonSetupRootsWithoutWaiting(t *testing.T) {
	setWindowsRelaxWaitForTest(t, 5*time.Second)
	for _, tc := range []struct {
		name  string
		sddl  string
		owner bool
	}{
		// The setup shape plus a write grant to Everyone.
		{"extra grant", "D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;OW)(A;OICI;FA;;;WD)", false},
		// The setup ACEs, not protected (inherits from the parent).
		{"unprotected", "D:(A;OICI;FA;;;SY)(A;OICI;FA;;;OW)", false},
		// One ACE of the two.
		{"system only", "D:P(A;OICI;FA;;;SY)", false},
		// The exact setup shape on a folder another principal owns.
		{"administrators owner", windowsSetupRelaxedDirectorySDDL, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			fixture := newWindowsRelaxResolveFixture(t)
			if tc.owner {
				administrators, err := windows.CreateWellKnownSid(windows.WinBuiltinAdministratorsSid)
				if err != nil {
					t.Fatal(err)
				}
				setWindowsTestPathExactOwner(t, fixture.hookDir, administrators)
			}
			setWindowsRelaxTestDACL(t, fixture.hookDir, tc.sddl)
			t.Cleanup(func() {
				setWindowsTestPathExactOwner(t, fixture.hookDir, fixture.target)
				_ = setWindowsUserPathProtection(fixture.hookDir, fixture.target, true)
			})
			started := time.Now()
			_, err := ResolveWindowsManagedRuntimeGeneration(fixture.resolve)
			if !errors.Is(err, ErrWindowsManagedRuntimeGenerationDirectoryUntrusted) {
				t.Fatalf("resolve error = %v, want untrusted directory", err)
			}
			if elapsed := time.Since(started); elapsed > time.Second {
				t.Fatalf("non-setup DACL waited %s before refusing", elapsed)
			}
		})
	}
}

func TestWindowsManagedRuntimeResolveFailsClosedWhenSetupRelaxPersists(t *testing.T) {
	setWindowsRelaxWaitForTest(t, 200*time.Millisecond)
	fixture := newWindowsRelaxResolveFixture(t)
	setWindowsRelaxTestDACL(t, fixture.hookDir, windowsSetupRelaxedDirectorySDDL)
	t.Cleanup(func() { _ = setWindowsUserPathProtection(fixture.hookDir, fixture.target, true) })
	started := time.Now()
	_, err := ResolveWindowsManagedRuntimeGeneration(fixture.resolve)
	if !errors.Is(err, ErrWindowsManagedRuntimeGenerationDirectoryUntrusted) {
		t.Fatalf("resolve error = %v, want untrusted directory", err)
	}
	if elapsed := time.Since(started); elapsed < 200*time.Millisecond || elapsed > 3*time.Second {
		t.Fatalf("persistent setup relax refused after %s, want about the 200ms bound", elapsed)
	}
}

// GAP-1502 class: the reconcile that repaired a connector publishes its new
// generation and retires the bundle the previous selector named. A hook that
// read the old selector just before must take the new generation, not refuse
// the call; a selector that did not change keeps a missing bundle a refusal
// (TestWindowsManagedRuntimeGenerationOldOrNewPublication).
func TestWindowsManagedRuntimeResolveFollowsPublicationThatRetiredItsBundle(t *testing.T) {
	fixture := newWindowsRelaxResolveFixture(t)
	next := fixture.desired
	next.GatewayAddr = "127.0.0.1:18971"
	next.ScopedToken = "next-scoped-test-token"
	originalRead := windowsManagedRuntimeResolveSelectorRead
	t.Cleanup(func() { windowsManagedRuntimeResolveSelectorRead = originalRead })
	var publishErr error
	published := ""
	windowsManagedRuntimeResolveSelectorRead = func() {
		windowsManagedRuntimeResolveSelectorRead = func() {}
		publication, err := PrepareWindowsManagedRuntimeGeneration(next)
		if err != nil {
			publishErr = err
			return
		}
		commit, err := CommitWindowsManagedRuntimeGeneration(publication)
		if err == nil {
			err = commit.Finalize()
		}
		publishErr = err
		published = publication.GenerationID()
	}
	runtime, err := ResolveWindowsManagedRuntimeGeneration(fixture.resolve)
	if publishErr != nil {
		t.Fatalf("publish next generation: %v", publishErr)
	}
	if _, statErr := os.Lstat(fixture.first.BundlePath()); !os.IsNotExist(statErr) {
		t.Fatalf("previous bundle was not retired: %v", statErr)
	}
	if err != nil {
		t.Fatalf("resolve across a publication that retired its bundle was refused: %v", err)
	}
	if runtime.GenerationID != published || runtime.GatewayAddr != next.GatewayAddr {
		t.Fatalf("resolved generation %q (%s), want the new %q", runtime.GenerationID, runtime.GatewayAddr, published)
	}
}

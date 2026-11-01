// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package enterprisehooks

import (
	"testing"

	"golang.org/x/sys/windows"
)

// An administrator (or any account) can read the session list without
// LocalSystem: an account nobody is signed in as has no session, and a SID
// that cannot be parsed is an error, never a sign-out.
func TestWindowsTargetHasNoSessionReadsTheSessionList(t *testing.T) {
	signedOut, err := WindowsTargetHasNoSession("S-1-5-21-1-2-3-424242")
	if err != nil || !signedOut {
		t.Fatalf("unknown account: signedOut=%v err=%v, want signed out", signedOut, err)
	}
	if signedOut, err := WindowsTargetHasNoSession("not-a-sid"); err == nil || signedOut {
		t.Fatalf("malformed SID: signedOut=%v err=%v, want an error", signedOut, err)
	}
}

// GAP-1533, GAP-1564: only an active session is signed in for the wait, as
// for the guardian; a disconnected one waits for its account.
func TestWindowsSessionStateSignedInOnlyWhenActive(t *testing.T) {
	if !windowsSessionStateSignedIn(windows.WTSActive) {
		t.Fatal("an active session is not signed in")
	}
	for _, state := range []uint32{windows.WTSDisconnected, windows.WTSConnected, windows.WTSListen} {
		if windowsSessionStateSignedIn(state) {
			t.Fatalf("session state %d counted as signed in", state)
		}
	}
}

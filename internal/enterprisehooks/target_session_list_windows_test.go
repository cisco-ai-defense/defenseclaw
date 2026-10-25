// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package enterprisehooks

import "testing"

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

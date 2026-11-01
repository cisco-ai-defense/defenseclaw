// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package connector

import "testing"

// GAP-2021: a marker owned by another account is not a marker.
func TestNativeOTLPTakeBackPendingMarkerOwnerRule(t *testing.T) {
	for _, tc := range []struct {
		owner, dirOwner, euid uint32
		want                  bool
	}{
		{1001, 1001, 0, true},
		{0, 1001, 0, true},
		{1002, 1001, 1002, true},
		{1002, 1001, 0, false},
	} {
		if got := nativeOTLPTakeBackOwnerUIDTrusted(tc.owner, tc.dirOwner, tc.euid); got != tc.want {
			t.Fatalf("owner %d dir %d euid %d: trusted=%v, want %v", tc.owner, tc.dirOwner, tc.euid, got, tc.want)
		}
	}
}

// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package connector

import "testing"

func TestHookAPITrustedRuntimeOwnerAcceptsPrivilegeDropEffectiveUID(t *testing.T) {
	tests := []struct {
		name         string
		owner        uint32
		realUID      int
		effectiveUID int
		want         bool
	}{
		{name: "root", owner: 0, realUID: 1000, effectiveUID: 1001, want: true},
		{name: "real uid", owner: 1000, realUID: 1000, effectiveUID: 1001, want: true},
		{name: "effective target uid", owner: 1001, realUID: 0, effectiveUID: 1001, want: true},
		{name: "unrelated uid", owner: 2002, realUID: 0, effectiveUID: 1001, want: false},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if got := hookAPITrustedRuntimeOwner(test.owner, test.realUID, test.effectiveUID); got != test.want {
				t.Fatalf(
					"hookAPITrustedRuntimeOwner(%d, %d, %d) = %v, want %v",
					test.owner, test.realUID, test.effectiveUID, got, test.want,
				)
			}
		})
	}
}

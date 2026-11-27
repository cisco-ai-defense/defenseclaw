// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package effects

import "testing"

func TestDET111R3LocalhostTripleSlashIsDriveAbsolute(t *testing.T) {
	got, ok, reason := placePath("localhost:///C:/Users/alice/.ssh/authorized_keys", Options{
		Flavor: FlavorWindows, Dialect: DialectPowerShell, Drive: "C", CaseInsensitive: true,
	})
	if !ok || reason != "" {
		t.Fatalf("placePath returned %q, %v, %q; want a placed local path", got, ok, reason)
	}
	if got != `c:\users\alice\.ssh\authorized_keys` {
		t.Fatalf("placePath = %q, want local drive path", got)
	}
}

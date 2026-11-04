//go:build darwin

// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package audit

import "testing"

// An untrusted owner on a Secure Client or OS-root ancestor folder is
// advisory, the same verdict the config walk reaches; the store's own folder
// and files keep the strict verdict.
func TestAuditDBAncestorOwnerAdvisoryDarwin(t *testing.T) {
	cases := []struct {
		path      string
		directory bool
		strict    bool
		want      bool
	}{
		{path: "/opt/cisco/secureclient", directory: true, want: true},
		{path: "/opt", directory: true, want: true},
		{path: "/opt/cisco/secureclient/defenseclaw/runtime", directory: true, strict: true, want: false},
		{path: "/opt/cisco/secureclient/defenseclaw/runtime/audit.db", directory: false, want: false},
		{path: "/Users/someone", directory: true, want: false},
	}
	for _, tc := range cases {
		if got := auditDBAncestorOwnerAdvisory(tc.path, tc.directory, tc.strict); got != tc.want {
			t.Errorf("%s directory=%v strict=%v: advisory %v, want %v", tc.path, tc.directory, tc.strict, got, tc.want)
		}
	}
}

// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package enterprisehooks

import (
	"strings"
	"testing"
)

// An account can start Hermes with HERMES_HOME set only for one shell. No
// persistent setting or hook record names that unhooked home, so managed
// Hermes coverage is reported incomplete on every OS. It is a coverage
// message and never a verification failure.
func TestManagedHermesSessionHomeIsACoverageLimit(t *testing.T) {
	for _, tc := range []struct {
		name, goos, connector  string
		managed, secure, limit bool
	}{
		{"standalone Hermes", "windows", "hermes", true, false, true},
		{"Secure Client Hermes", "windows", "hermes", true, true, false},
		{"per-user Hermes", "windows", "hermes", false, false, false},
		{"standalone Kiro", "windows", "kiro", true, false, false},
		{"Linux standalone Hermes", "linux", "hermes", true, false, true},
		{"macOS standalone Hermes", "darwin", "hermes", true, false, true},
		{"Linux per-user Hermes", "linux", "hermes", false, false, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			limit := ManagedHermesSessionHomeCoverageLimit(tc.goos, tc.connector, tc.managed, tc.secure)
			if tc.limit != strings.Contains(limit, "session-only HERMES_HOME") || !tc.limit && limit != "" {
				t.Fatalf("coverage limit = %q, want limit=%t", limit, tc.limit)
			}
		})
	}
}

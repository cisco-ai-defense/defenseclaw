// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package enterprisehooks

import (
	"strings"
	"testing"
)

// A Windows account can start Hermes with HERMES_HOME set only for one shell.
// No persistent setting or hook record names that unhooked home, so a live
// managed Verify must refuse attestation even if the default home is hooked.
func TestManagedHermesWindowsSessionHomeCannotBeAttested(t *testing.T) {
	for _, tc := range []struct {
		name, goos, connector   string
		managed, secure, refuse bool
	}{
		{"standalone Hermes", "windows", "hermes", true, false, true},
		{"Secure Client Hermes", "windows", "hermes", true, true, false},
		{"per-user Hermes", "windows", "hermes", false, false, false},
		{"standalone Kiro", "windows", "kiro", true, false, false},
		{"Unix Hermes", "linux", "hermes", true, false, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			err := managedHermesSessionHomeAttestation(tc.goos, tc.connector, tc.managed, tc.secure)
			if tc.refuse {
				if err == nil || !strings.Contains(err.Error(), "session-only HERMES_HOME") {
					t.Fatalf("attestation = %v, want the unobservable home named", err)
				}
			} else if err != nil {
				t.Fatalf("attestation = %v, want no new restriction", err)
			}
		})
	}
}

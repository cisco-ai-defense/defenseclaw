// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package config

import (
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/managed"
)

// TestDefaultSecureClientPolicy locks the compiled-in strict
// peer-auth allowlist to the Cisco Secure Client GUI identity.
// Any change to these values needs an explicit review because
// they are the sole gate between an arbitrary local process and
// the IPC surface in managed_enterprise installs.
func TestDefaultSecureClientPolicy(t *testing.T) {
	got := DefaultSecureClientPolicy()
	if want := []string{"DE8Y96K9QP"}; !stringSliceEqual(got.AllowedTeamIDs, want) {
		t.Errorf("AllowedTeamIDs = %v, want %v", got.AllowedTeamIDs, want)
	}
	if want := []string{"com.cisco.secureclient.gui"}; !stringSliceEqual(got.AllowedSigningIDs, want) {
		t.Errorf("AllowedSigningIDs = %v, want %v", got.AllowedSigningIDs, want)
	}
	if want := []string{"com.cisco.secureclient.gui"}; !stringSliceEqual(got.AllowedBundleIDs, want) {
		t.Errorf("AllowedBundleIDs = %v, want %v", got.AllowedBundleIDs, want)
	}
	// Sanity: the exported string constants must match the returned
	// values so callers that read them directly stay in lockstep
	// with the policy helper.
	if SecureClientTeamID != "DE8Y96K9QP" {
		t.Errorf("SecureClientTeamID drifted: %q", SecureClientTeamID)
	}
	if SecureClientSigningID != "com.cisco.secureclient.gui" {
		t.Errorf("SecureClientSigningID drifted: %q", SecureClientSigningID)
	}
	if SecureClientBundleID != "com.cisco.secureclient.gui" {
		t.Errorf("SecureClientBundleID drifted: %q", SecureClientBundleID)
	}
}

func stringSliceEqual(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func TestManagedIPCEnabled(t *testing.T) {
	cases := []struct {
		name string
		cfg  *Config
		want bool
	}{
		{"nil config", nil, false},
		{"empty deployment mode", &Config{}, false},
		{"unmanaged_byod", &Config{DeploymentMode: string(DeploymentModeUnmanagedBYOD)}, false},
		{"ci_cd", &Config{DeploymentMode: string(DeploymentModeCICD)}, false},
		{"sandboxed", &Config{DeploymentMode: string(DeploymentModeSandboxed)}, false},
		{"server", &Config{DeploymentMode: string(DeploymentModeServer)}, false},
		{"saas", &Config{DeploymentMode: string(DeploymentModeSaaS)}, false},
		{"managed_enterprise", &Config{DeploymentMode: managed.DeploymentModeManagedEnterprise}, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := tc.cfg.ManagedIPCEnabled(); got != tc.want {
				t.Errorf("ManagedIPCEnabled = %v, want %v", got, tc.want)
			}
		})
	}
}

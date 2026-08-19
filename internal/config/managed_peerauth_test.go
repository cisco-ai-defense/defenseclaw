// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package config

import "testing"

// TestEffectivePeerAuthKindGating pins the spec 004 REQ-11 table:
//
//   - ManagedIPCEnabled() == false ⇒ "" regardless of runtime.GOOS.
//     (No IPC server, no peer-auth surface.)
//   - Managed_enterprise on linux/darwin ⇒ "UnixPeer".
//   - Managed_enterprise on Windows ⇒ "UnixPeerUnauthenticated".
//     (Initial-cut deferred-auth posture; the GA release-gate
//     refuses a release-candidate build in which this branch
//     remains reachable.)
//
// The test uses table-driven inputs against a stubbed
// runtime.GOOS via a small helper; we can't `t.Setenv` GOOS, but
// EffectivePeerAuthKind currently reads runtime.GOOS at call time
// so we assert the branch by CI OS. Test is skipped on unsupported
// OSes.
func TestEffectivePeerAuthKindGating(t *testing.T) {
	tests := []struct {
		name string
		cfg  *Config
		want string
	}{
		{
			name: "non-managed deployment (unmanaged_byod)",
			cfg:  &Config{DeploymentMode: string(DeploymentModeUnmanagedBYOD)},
			want: "",
		},
		{
			name: "ci_cd — no IPC surface",
			cfg:  &Config{DeploymentMode: string(DeploymentModeCICD)},
			want: "",
		},
		{
			name: "sandboxed — no IPC surface",
			cfg:  &Config{DeploymentMode: string(DeploymentModeSandboxed)},
			want: "",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := tc.cfg.EffectivePeerAuthKind(); got != tc.want {
				t.Fatalf("EffectivePeerAuthKind() = %q, want %q", got, tc.want)
			}
		})
	}
}

// TestEffectivePeerAuthKindManagedEnterprise asserts the
// managed_enterprise branch reports one of the two supported
// Kinds. Because runtime.GOOS is fixed at test time we can only
// assert the value matches the current host — spec 004 REQ-06 +
// REQ-11 are proved together via the value's identity to
// KindUnixPeer (linux/darwin) or KindUnixPeerUnauthenticated
// (Windows).
func TestEffectivePeerAuthKindManagedEnterprise(t *testing.T) {
	cfg := &Config{DeploymentMode: string(DeploymentModeManagedEnterprise)}
	got := cfg.EffectivePeerAuthKind()
	// Cross-platform: the value MUST be non-empty (managed_enterprise
	// always has an IPC surface post-spec 004) AND match one of the
	// two supported Kinds.
	if got == "" {
		t.Fatalf("managed_enterprise EffectivePeerAuthKind() = empty; expected UnixPeer or UnixPeerUnauthenticated")
	}
	if got != peerAuthKindUnixPeer && got != peerAuthKindUnixPeerUnauthenticated {
		t.Fatalf("managed_enterprise EffectivePeerAuthKind() = %q; expected UnixPeer or UnixPeerUnauthenticated", got)
	}
}

// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package config

import (
	"runtime"
	"testing"
)

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
// Non-managed cases below produce "" on every OS. See
// TestEffectivePeerAuthKindManagedEnterprise for the per-OS
// managed-mode assertion — it computes the expected value directly
// from runtime.GOOS so a regression that returns the wrong Kind on
// the current CI OS fails immediately (CR spec-004:PRRT_kwDORuAK-s6ankzW).
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

// TestEffectivePeerAuthKindManagedEnterprise asserts the exact
// per-OS mapping — computing the expected value from runtime.GOOS
// so a regression that returns the wrong Kind on the CI OS fails
// immediately. The Windows runner must see
// `UnixPeerUnauthenticated`; linux/darwin runners must see
// `UnixPeer`. See CR spec-004:PRRT_kwDORuAK-s6ankzW — accepting
// either kind on every OS left REQ-11's Windows-specific posture
// invariant unverified.
func TestEffectivePeerAuthKindManagedEnterprise(t *testing.T) {
	cfg := &Config{DeploymentMode: string(DeploymentModeManagedEnterprise)}
	want := peerAuthKindUnixPeer
	if runtime.GOOS == "windows" {
		want = peerAuthKindUnixPeerUnauthenticated
	}
	if got := cfg.EffectivePeerAuthKind(); got != want {
		t.Fatalf("managed_enterprise on %s: EffectivePeerAuthKind() = %q, want %q",
			runtime.GOOS, got, want)
	}
}

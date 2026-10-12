// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package sandboxcli

import (
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/openshell/sandboxapi"
)

// GAP-0571: status and list name the sandbox's network separately from the
// caller's assigned organization profile.
func TestStatusAndListDistinguishNetworkFromOrganizationProfile(t *testing.T) {
	sb := sampleSandbox("box")
	sb.Pack, sb.Profile, sb.NetworkMode, sb.Approvals = "contractors", "balanced", "allowlist", "manual"
	ta := newTestApp(t, "", sb)
	ta.daemon.status.Pack, ta.daemon.status.Profile = sb.Pack, sb.Profile
	ta.daemon.status.Managed = &sandboxapi.ManagedStatus{Profile: "contractors"}
	ta.ok(t, ta.Status(bg, "", OutputText))
	out := strings.Join(strings.Fields(ta.output()), " ")
	has(t, out, "Policy pack contractors, network balanced", "Your policy organization profile contractors")
	lacks(t, out, "profile balanced")

	ta.ok(t, ta.fresh().Status(bg, "box", OutputText))
	out = strings.Join(strings.Fields(ta.output()), " ")
	has(t, out, "pack contractors", "network allowlist (balanced)", "approvals manual")
	lacks(t, out, "profile balanced")

	ta.ok(t, ta.fresh().List(bg, OutputText))
	has(t, ta.output(), "NETWORK", "balanced (pack contractors)")
	lacks(t, ta.output(), "PROFILE", "profile")
}

// GAP-0597: an incomplete policy during create must not look like open
// defaults; once resolved, even an open policy is displayed as supplied.
func TestCreatingSandboxPolicyIsPendingUntilResolved(t *testing.T) {
	for _, tc := range []struct {
		name, pack, profile, network, approvals string
		pending                                 bool
	}{
		{name: "no policy", pending: true},
		{name: "no pack", profile: "balanced", network: "allowlist", approvals: "manual", pending: true},
		{name: "no network profile", pack: "contractors", network: "allowlist", approvals: "manual", pending: true},
		{name: "no network mode", pack: "contractors", profile: "balanced", approvals: "manual", pending: true},
		{name: "no approvals", pack: "contractors", profile: "balanced", network: "allowlist", pending: true},
		{name: "resolved", pack: "contractors", profile: "balanced", network: "allowlist", approvals: "manual"},
		{name: "resolved open", pack: "open", profile: "open", network: "open", approvals: "auto"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			sb := sandboxapi.Sandbox{Name: "box", Harness: "claudecode", Phase: "creating", WorkdirMode: "copy",
				Pack: tc.pack, Profile: tc.profile, NetworkMode: tc.network, Approvals: tc.approvals}
			ta := newTestApp(t, "", sb)
			ta.ok(t, ta.Status(bg, "box", OutputText))
			out := strings.Join(strings.Fields(ta.output()), " ")
			if tc.pending {
				has(t, out, "Policy pending (resolving policy)")
				lacks(t, out, "pack open", "network open", "approvals")
			} else {
				has(t, out, "pack "+tc.pack, "approvals "+tc.approvals)
				lacks(t, out, "pending")
			}
			ta.ok(t, ta.fresh().List(bg, OutputText))
			if tc.pending {
				has(t, ta.output(), "pending")
				lacks(t, ta.output(), "pack open", "balanced")
			} else {
				has(t, ta.output(), tc.profile)
				lacks(t, ta.output(), "pending")
			}
		})
	}
}

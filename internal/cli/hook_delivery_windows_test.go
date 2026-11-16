// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0
//go:build windows

package cli

import (
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/enterprisehooks"
)

func TestManagedHookDeliveryUsesAuthenticatedGenerationPolicy(t *testing.T) {
	for _, agent := range []string{"codex", "claudecode", "cursor"} {
		for _, mode := range []string{"open", "closed"} {
			t.Run(agent+"/"+mode, func(t *testing.T) {
				_, home := stageTrustedNativeHookForTest(t, "closed")
				stubEnterpriseManagedRuntimeResolver(t, func(string, string) (enterprisehooks.WindowsManagedHookRuntime, error) {
					return enterprisehooks.WindowsManagedHookRuntime{
						Connector: agent, DataDir: home, PolicyActive: true, Registered: true,
						GatewayAddr: "127.0.0.1:18970", GatewayServiceName: "DefenseClawGateway-Test",
						ScopedToken: "scoped-token", GenerationID: strings.Repeat("a", 32), FailMode: mode,
					}, nil
				})
				t.Setenv("DEFENSECLAW_FAIL_MODE", "open")
				t.Setenv("DEFENSECLAW_STRICT_AVAILABILITY", "0")
				savedSecureClient := secureClientHost
				t.Cleanup(func() { secureClientHost = savedSecureClient })
				if prepareEnterpriseManagedHookRuntime(agent) {
					t.Fatal("active authenticated generation no-opped")
				}
				// The administrator chooses the fail mode (owner 2026-10-20):
				// outside Secure Client too, the authenticated generation's
				// mode is the managed hook's mode, and only an open one
				// relaxes strict availability.
				for _, sc := range []bool{false, true} {
					secureClientHost = func() bool { return sc }
					opts := buildHookOptionsForRuntime(agent, "PreToolUse", "", "open", true)
					if opts.FailMode != mode || opts.StrictAvailability != (mode != "open") || opts.ManagedRuntimeFailure != "" {
						t.Fatalf("hook policy did not match authenticated %s mode (secure client %v): %+v", mode, sc, opts)
					}
				}
				t.Setenv("DEFENSECLAW_STRICT_AVAILABILITY", "1")
				if opts := buildHookOptionsForRuntime(agent, "PreToolUse", "", "open", true); !opts.StrictAvailability {
					t.Fatal("strict availability override was lost")
				}
			})
		}
	}
}

// 1.0.4 lead directive: a managed hook's fail mode is the authenticated
// generation's (the administrator's config) and nothing else. No
// DEFENSECLAW_FAIL_MODE in the agent's environment opens a closed generation
// or closes an open one, so status and runtime agree on every OS.
func TestManagedWindowsHookIgnoresTheEnvironmentFailMode(t *testing.T) {
	savedSecureClient := secureClientHost
	t.Cleanup(func() { secureClientHost = savedSecureClient })
	for _, agent := range []string{"claudecode", "codex", "cursor"} {
		for _, tc := range []struct {
			env, generation, want string
		}{
			{env: "closed", generation: "open", want: "open"},
			{env: "CLOSED", generation: "open", want: "open"},
			{env: " Closed ", generation: "open", want: "open"},
			{env: "open", generation: "open", want: "open"},
			{env: "", generation: "open", want: "open"},
			{env: "bogus", generation: "open", want: "open"},
			{env: "open", generation: "closed", want: "closed"},
		} {
			t.Run(agent+"/env="+tc.env+"/generation="+tc.generation, func(t *testing.T) {
				_, home := stageTrustedNativeHookForTest(t, "open")
				generation := tc.generation
				stubEnterpriseManagedRuntimeResolver(t, func(string, string) (enterprisehooks.WindowsManagedHookRuntime, error) {
					return enterprisehooks.WindowsManagedHookRuntime{
						Connector: agent, DataDir: home, PolicyActive: true, Registered: true,
						GatewayAddr: "127.0.0.1:18970", GatewayServiceName: "DefenseClawGateway-Test",
						ScopedToken: "scoped-token", GenerationID: strings.Repeat("b", 32), FailMode: generation,
					}, nil
				})
				t.Setenv("DEFENSECLAW_FAIL_MODE", tc.env)
				t.Setenv("DEFENSECLAW_STRICT_AVAILABILITY", "0")
				if prepareEnterpriseManagedHookRuntime(agent) {
					t.Fatal("active authenticated generation no-opped")
				}
				for _, sc := range []bool{false, true} {
					secureClientHost = func() bool { return sc }
					opts := buildHookOptionsForRuntime(agent, "PreToolUse", "", "open", true)
					if opts.ManagedRuntimeFailure != "" || !opts.ManagedEnterprise {
						t.Fatalf("secure client %v: authenticated generation was not used: %+v", sc, opts)
					}
					// hookexec blocks every outage of a closed, strict hook
					// and lets an open one through only on an outage.
					if opts.FailMode != tc.want || opts.StrictAvailability != (tc.want == "closed") {
						t.Fatalf("secure client %v: fail mode %q strict %v, want %q", sc, opts.FailMode, opts.StrictAvailability, tc.want)
					}
				}
			})
		}
	}
}

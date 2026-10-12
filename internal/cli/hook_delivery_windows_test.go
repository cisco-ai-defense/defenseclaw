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
				if enterpriseManagedHookRuntimeNoop(agent) {
					t.Fatal("active authenticated generation no-opped")
				}
				opts := buildHookOptionsForRuntime(agent, "PreToolUse", "", "open", true)
				if opts.FailMode != mode || opts.StrictAvailability || opts.ManagedRuntimeFailure != "" {
					t.Fatalf("hook policy did not match authenticated %s mode: %+v", mode, opts)
				}
				t.Setenv("DEFENSECLAW_STRICT_AVAILABILITY", "1")
				if opts := buildHookOptionsForRuntime(agent, "PreToolUse", "", "open", true); !opts.StrictAvailability {
					t.Fatal("strict availability override was lost")
				}
			})
		}
	}
}

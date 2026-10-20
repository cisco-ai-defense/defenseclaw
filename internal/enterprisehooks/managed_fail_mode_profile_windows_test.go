//go:build windows

// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package enterprisehooks

import (
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/managed"
)

// GAP-0014: status reports the fail mode the pinned guardian renders for the
// profile the loaded config resolves, whatever the caller's own profile pin.
// An unpinned administrator shell reading a standalone install sees the
// administrator's mode for every connector: Amp's explicit open, closed for
// every connector without one (owner decision 2026-10-20), Copilot and
// Hermes included (their managed hooks block through the native deny). A
// Secure Client install keeps #1163 (unset is open, Codex and Claude Code
// included) even from a standalone-pinned process.
func TestWindowsManagedHookFailModeFollowsTheConfigProfile(t *testing.T) {
	for _, tc := range []struct {
		profile string
		pin     string
		want    map[string]string
	}{
		{managed.ProfileStandalone, "", map[string]string{
			"codex": "closed", "claudecode": "closed", "cursor": "closed",
			"opencode": "closed", "copilot": "closed", "amp": "open", "hermes": "closed",
		}},
		{managed.ProfileStandalone, managed.ProfileStandalone, map[string]string{
			"codex": "closed", "opencode": "closed", "amp": "open", "copilot": "closed", "hermes": "closed",
		}},
		{managed.ProfileSecureClient, managed.ProfileStandalone, map[string]string{
			"codex": "open", "claudecode": "open", "opencode": "open",
		}},
	} {
		t.Run(tc.profile+"/pin="+tc.pin, func(t *testing.T) {
			t.Setenv(managed.EnterpriseProfileEnv, tc.pin)
			cfg := &config.Config{DeploymentMode: managed.DeploymentModeManagedEnterprise}
			cfg.Enterprise.Profile = tc.profile
			cfg.Guardrail.Mode = "observe"
			cfg.Guardrail.Connectors = map[string]config.PerConnectorGuardrailConfig{"amp": {HookFailMode: "open"}}
			for name, want := range tc.want {
				if got := ManagedHookFailMode(cfg, name); got != want {
					t.Errorf("%s: ManagedHookFailMode = %q, want %q", name, got, want)
				}
			}
		})
	}
	if got := ManagedHookFailMode(nil, "codex"); got != "closed" {
		t.Errorf("a config that resolves no profile reports %q, want closed", got)
	}
}

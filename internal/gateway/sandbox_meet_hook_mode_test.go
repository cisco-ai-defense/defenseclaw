// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package gateway

import (
	"context"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/sandboxreg"
)

// Review of r104 Q-identity (continuation 4, loop round 2): in a sandbox a
// profile that sets no mode of its own blocks (action), and one that sets
// observe observes. The strictest combination of profiles took its mode from
// its own settings, which name a mode for every connector, so a member that
// inherits its mode, or blocks only by its hook mode, was observed in the
// combination. It now observes in a sandbox only where every member sets
// observe itself.
func TestSandboxHookModeOfAMeetIsItsStrictestMember(t *testing.T) {
	profiles := map[string]config.GuardrailProfile{
		"watch":       {Mode: "observe", Sandbox: &config.OpenShellAdminConfig{RequiredFor: []string{"codex"}}},
		"also-watch":  {Mode: "observe", BlockAt: "LOW"},
		"inherits":    {BlockAt: "LOW"},
		"codex-block": {Mode: "observe", Connectors: map[string]config.PerConnectorGuardrailConfig{"codex": {Mode: "action"}}},
	}
	for _, tc := range []struct {
		other, want string
	}{
		{"also-watch", "observe"}, {"inherits", "action"}, {"codex-block", "action"},
	} {
		t.Run(tc.other, func(t *testing.T) {
			set := surfaceModesSet(t, nil, "watch", profiles)
			name, single := set.meetOf([]string{"watch", tc.other}, "codex")
			if single || !config.IsProfileMeet(name) {
				t.Fatalf("meet of watch and %s is %q (single %t)", tc.other, name, single)
			}
			ctx := context.WithValue(sandboxCtx(sandboxTestBinding("codex")), sandboxRelayRegistrationKey{}, sandboxreg.Registration{ID: "sbx-1", State: sandboxreg.StateLive, UID: 70001})
			ctx = context.WithValue(ctx, managedHookPeerContextKey{}, managedHookPeer{UID: 70001})
			ctx = context.WithValue(ctx, resolvedGuardrailProfileKey{}, &resolvedGuardrailProfile{
				decision: profileDecision{Name: name, SubjectSource: profileSubjectVerified}, set: set, derived: set.profileConfig(name)})
			if got := sandboxHookMode(ctx, "codex", "observe"); got != tc.want {
				t.Fatalf("sandbox hook mode of the meet of watch and %s is %s; want %s", tc.other, got, tc.want)
			}
		})
	}
}

// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/actionfacts"
	"github.com/defenseclaw/defenseclaw/internal/effects"
)

// rel-1-0-10 GAP-0218 / GAP-0219, end to end through the effect lane: a write
// the shell never runs, or a flag the program rejects, is no longer the
// restricted tier, and it falls to the unknown tier (never clean, never an
// allow). The same shapes that do write the file stay restricted and block.
func TestGap0218Gap0219EffectShadowTiers(t *testing.T) {
	effectResolverOverride = func(p string) (string, bool) { return p, true }
	defer func() { effectResolverOverride = nil }()
	rows := []struct {
		cmd        string
		restricted bool
	}{
		{"set -n; echo k >> ~/.ssh/authorized_keys", false},
		{"set -o noexec; echo k >> ~/.ssh/authorized_keys", false},
		{"exit 0; echo k >> ~/.ssh/authorized_keys", false},
		{"exec true; echo k >> ~/.ssh/authorized_keys", false},
		{"false && echo k >> ~/.ssh/authorized_keys", false},
		{"trap exit DEBUG; echo k >> ~/.ssh/authorized_keys", false},
		{"rm -u /home/u/.ssh/authorized_keys", false},
		{"unlink -f /home/u/.ssh/authorized_keys", false}, // unlink is not a listed program: unknown tier before and after
		{"cp -m 600 -t /home/u/.ssh /t/authorized_keys", false},
		// controls
		{"echo k >> ~/.ssh/authorized_keys", true},
		{"set -euo pipefail; echo k >> ~/.ssh/authorized_keys", true},
		{"cd /t/x || exit 1; echo k >> ~/.ssh/authorized_keys", true},
		{"false || echo k >> ~/.ssh/authorized_keys", true},
		{"rm -f /home/u/.ssh/authorized_keys", true},
		{"tee -a /home/u/.ssh/authorized_keys < /t/k", true},
		{"cp -t /home/u/.ssh /t/authorized_keys", true},
	}
	for _, r := range rows {
		req := trustedActionRequest{
			Connector: "claudecode",
			Input: actionfacts.Input{
				Tool: "Bash", Command: r.cmd,
				ActiveHome: "/home/u", CWD: "/home/u/work", DialectHint: actionfacts.DialectPOSIX,
			},
		}
		res := computeEffectShadow(req, effectRulesShadow, tierRestricted)
		if r.restricted {
			if res.Tier != string(effectTierRestricted) || res.Action != guardrailActionBlock {
				t.Errorf("%q: tier %q action %q, want restricted block", r.cmd, res.Tier, res.Action)
			}
			continue
		}
		if res.Tier != string(effectTierUnknown) {
			t.Errorf("%q: tier %q, want unknown (not restricted, not clean)", r.cmd, res.Tier)
		}
		if res.Action == guardrailActionAllow || res.Action == "" {
			t.Errorf("%q: action %q, want alert or block (no fail-open)", r.cmd, res.Action)
		}
	}
}

func TestEffectBSDUserland(t *testing.T) {
	cases := []struct {
		goos   string
		flavor effects.Flavor
		want   bool
	}{
		{"darwin", effects.FlavorPOSIX, true},
		{"linux", effects.FlavorPOSIX, false},
		{"windows", effects.FlavorPOSIX, false},
		{"darwin", effects.FlavorWindows, false},
	}
	for _, c := range cases {
		if got := effectBSDUserland(c.goos, c.flavor); got != c.want {
			t.Errorf("effectBSDUserland(%s, %s) = %v, want %v", c.goos, c.flavor, got, c.want)
		}
	}
}

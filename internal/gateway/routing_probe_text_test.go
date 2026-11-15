// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import "testing"

// A probe turn gives the router "" (delta 4's behaviour), banner and time
// footer included, so system noise never picks a model; typed text next to
// a probe is routed on; agent-injected user text gives "". The canonical
// sentences are found with the guardrail's one rule (stripCanonicalProbes,
// GAP-0248), which keeps inspecting the rest of the turn.
func TestRouterUserTextProbeTurns(t *testing.T) {
	banner := "System: [2026-04-22 08:07:05 EDT] WhatsApp gateway connected."
	plainBanner := "System: gateway connected as test."
	footer := "Current time: Monday, May 4th, 2026 - 3:17 PM (America/New_York) / 2026-05-04 19:17 UTC"
	for _, c := range []struct{ name, in, want string }{
		{"bare heartbeat", probeHeartbeatFull, ""},
		{"bare short heartbeat", probeHeartbeatMin, ""},
		{"bare session startup", canonicalSessionStartupProbe, ""},
		{"bare bootstrap startup", probeBootstrapOnly, ""},
		{"banner then heartbeat", banner + "\n\n" + probeHeartbeatFull, ""},
		{"plain banner then heartbeat", plainBanner + "\n\n" + probeHeartbeatShort, ""},
		{"heartbeat then footer", probeHeartbeatShort + "\n" + footer, ""},
		{"session startup then footer", canonicalSessionStartupProbe + "\n" + footer, ""},
		{"banner, startup, footer", banner + "\n" + canonicalSessionStartupProbe + "\n" + footer, ""},
		{"typed text next to a probe", probeHeartbeatMin + "\ndeploy the api", "deploy the api"},
		{"typed text with banner and probe", banner + "\n" + probeHeartbeatFull + "\nrefactor the parser\n" + footer, "refactor the parser"},
		{"injected text next to a probe", probeHeartbeatMin + "\n<bash-stdout>out</bash-stdout>", ""},
		{"injected instruction file", "# CLAUDE.md\nrules", ""},
		{"injected command output", "<bash-stdout>out</bash-stdout>", ""},
		{"reminder only", "<system-reminder>x</system-reminder>", ""},
		{"typed text", "deploy the api", "deploy the api"},
		{"banner without a probe is typed text", plainBanner, plainBanner},
	} {
		if got := routerUserText(c.in); got != c.want {
			t.Errorf("%s: routerUserText = %q, want %q", c.name, got, c.want)
		}
	}
}

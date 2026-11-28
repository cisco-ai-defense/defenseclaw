// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package gateway

import (
	"path/filepath"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/guardrail/bounded"
)

// TestGAP1327FindShellChildReadBodyIsNotAStateWriteFiveTiers is
// rel-1-0-10:GAP-1327: find ~/.defenseclaw/hooks -exec sh -c BODY sh {} +
// with a body that only prints and hashes the files it is handed gets the
// verdict of the same find with a reader child (-exec sha256sum {} +), not the
// state-write finding; its write twin (: > "$f") keeps it. Five tiers, the
// Claude Code, Codex and inspect routes, the effects lane on. Fail-before: red
// at a64bfdb931 (the read body is judged as a state write in every tier).
func TestGAP1327FindShellChildReadBodyIsNotAStateWriteFiveTiers(t *testing.T) {
	home := det111R1Home(t)
	cwd := filepath.Join(home, "proj")
	const (
		read    = `find ~/.defenseclaw/hooks -type f -exec sh -c 'for f do printf "%s " "$f"; sha256sum "$f"; done' sh {} +`
		control = `find ~/.defenseclaw/hooks -type f -exec sha256sum {} +`
		write   = `find ~/.defenseclaw/hooks -type f -exec sh -c 'for f do : > "$f"; done' sh {} +`
	)
	rewrite := strings.NewReplacer("~", home)
	for _, tier := range boundedTestTiers {
		for _, route := range det111R1Routes() {
			api := det111R1API(t, route.connector, tier.posture, tier.managed, tier.tier)
			useDefaultEffectsLane(t)
			for _, spell := range []func(string) string{func(s string) string { return s }, rewrite.Replace} {
				where := tier.name + " " + route.name
				got := boundedParse(route.decide(t, api, t.Context(), cwd, spell(read)))
				want := boundedParse(route.decide(t, api, t.Context(), cwd, spell(control)))
				if got != want {
					t.Errorf("%s %q: %s, want the reader child's %s", where, spell(read), got, want)
				}
				if w := boundedParse(route.decide(t, api, t.Context(), cwd, spell(write))); bounded.Stricter(w, bounded.Alert) != w {
					t.Errorf("%s %q: %s, want at least alert (state write)", where, spell(write), w)
				}
			}
		}
	}
}

// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import "testing"

// TestGAP2214XargsLinkRecordsTheSessionAlias: echo SRC DST | xargs ln -s is
// the call ln -s SRC DST (a bare xargs feeds every literal word), so its own
// reading is Known and records the session alias as the plain ln does; a
// later read through the link carries the member read proof. Red at
// det111/t23e6-merge f6e151801a: the reading of the xargs form had an
// unknown and recorded no alias.
func TestGAP2214XargsLinkRecordsTheSessionAlias(t *testing.T) {
	useEffectsRulesMode(t, "on")
	for _, tc := range []struct {
		name, link string
		want       bool
	}{
		{"xargs of two words", "echo /home/u/.npmrc /home/u/work/npm_alias | xargs ln -s", true},
		{"echo -n with -sf", "echo -n /home/u/.npmrc /home/u/work/npm_alias | xargs ln -sf", true},
		{"plain ln (twin)", "ln -sf /home/u/.npmrc /home/u/work/npm_alias", true},
		{"xargs of an ordinary file (benign twin)", "echo /home/u/work/notes /home/u/work/npm_alias | xargs ln -s", false},
	} {
		link := shadowLiveRequest(tc.link)
		link.sessionID = "gap2214-" + tc.name
		effectShadowRun(link, effectRulesOn, tierRestricted)
		use := shadowLiveRequest("cat /home/u/work/npm_alias")
		use.sessionID = link.sessionID
		res := effectShadowRun(use, effectRulesOn, tierRestricted)[0]
		if got := len(res.ReadProofs) > 0; got != tc.want {
			t.Errorf("%s: read through the link has a member read proof = %t, want %t", tc.name, got, tc.want)
		}
	}
}

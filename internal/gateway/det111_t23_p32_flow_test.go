// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

// TestCredentialReadKeepsEachFlowFiveTiers (T23 review P3-2): two reads of
// one effects-only spelling of a home credential in a call, a local count
// and a show in either order (wc -l X; cat X and cat X; wc -l X), get the
// verdict of the show alone (cat X) on
// the Claude Code and Codex hook routes in the five tiers. At ac8b361121 the
// read proofs were deduplicated by class only, so the count's local proof
// stood for both and the call allowed where cat X blocks.
func TestCredentialReadKeepsEachFlowFiveTiers(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX home spellings")
	}
	home := t.TempDir()
	for _, f := range []string{".ssh/id_rsa", ".aws/credentials", "proj/notes.txt"} {
		p := filepath.Join(home, f)
		if err := os.MkdirAll(filepath.Dir(p), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte("x\n"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	t.Setenv("HOME", home)
	cwd := filepath.Join(home, "proj")
	rows := []struct{ call, show string }{
		{`wc -l ${PWD%/proj}/.ssh/id_rsa; cat ${PWD%/proj}/.ssh/id_rsa`, `cat ${PWD%/proj}/.ssh/id_rsa`},
		{`grep -c x ${PWD%/proj}/.ssh/id_rsa && cat ${PWD%/proj}/.ssh/id_rsa`, `cat ${PWD%/proj}/.ssh/id_rsa`},
		{`wc -l ${PWD%/proj}/.aws/credentials; cat ${PWD%/proj}/.aws/credentials`, `cat ${PWD%/proj}/.aws/credentials`},
		{`cat ${PWD%/proj}/.ssh/id_rsa; wc -l ${PWD%/proj}/.ssh/id_rsa`, `cat ${PWD%/proj}/.ssh/id_rsa`},
		{`cat ${PWD%/proj}/.aws/credentials; grep -c x ${PWD%/proj}/.aws/credentials`, `cat ${PWD%/proj}/.aws/credentials`},
	}
	for _, tier := range boundedTestTiers {
		for _, route := range r3PosixRoutesForReadRows() {
			api := gap0589TierAPI(t, route.connector, tier.posture, tier.managed, tier.tier)
			useDefaultEffectsLane(t)
			for _, row := range rows {
				want, wantSev := route.decide(t, api, cwd, row.show)
				if got, sev := route.decide(t, api, cwd, row.call); got != want || sev != wantSev {
					t.Errorf("%s %s %q: %s/%s, want the show alone %q %s/%s", tier.name, route.connector, row.call, got, sev, row.show, want, wantSev)
				}
			}
		}
	}
}

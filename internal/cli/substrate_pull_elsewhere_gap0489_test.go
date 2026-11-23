// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"net/http"
	"slices"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/cliusage"
)

// GAP-0489: pull on a computer that did not start the agent (it keeps no
// record of the folder that was sent) is refused with exit 3, before any
// tunnel to the agent opens, and the refusal says what works: pull on the
// computer that ran it, with the same modes, or connect from here and git
// push from inside the agent. The help says so too. Before the fix it was a
// plain failure (exit 1) that named no pull mode, and the pull help said
// nothing of where it works.
func TestSubstratePullOnAnotherComputerSaysWhatWorksGAP0489(t *testing.T) {
	t.Setenv("DEFENSECLAW_HOME", t.TempDir())
	f := &fakeAdmin{h: map[string]func(http.ResponseWriter, *http.Request){"GET actors": jsonReply(sampleActors())}}
	useFakeAdmin(t, f)
	for _, args := range [][]string{{"fix-tests-1", "--apply", "--yes"}, {"fix-tests-1", "--branch", "agent/x"}, {"fix-tests-1", "--patch-out", "x.patch"}} {
		_, _, err := runSubstrate(t, newSubstratePullCmd(), args...)
		if err == nil || cliusage.ExitCode(err) != substrateExitRefused {
			t.Fatalf("pull %v on a computer without the record: %v (exit %d), want exit %d", args, err, cliusage.ExitCode(err), substrateExitRefused)
		}
		for _, want := range []string{"no record of the folder you sent to eng-web/fix-tests-1",
			`only the computer you ran "defenseclaw substrate run" on keeps it`, "--patch-out FILE",
			"defenseclaw substrate connect fix-tests-1", "git push it from inside the agent"} {
			if !strings.Contains(err.Error(), want) {
				t.Errorf("pull %v refusal lacks %q: %v", args, want, err)
			}
		}
	}
	f.mu.Lock()
	calls := slices.Clone(f.calls)
	f.mu.Unlock()
	for _, c := range calls {
		if !strings.HasPrefix(c, "GET actors") {
			t.Errorf("pull without the record called %s (calls %v)", c, calls)
		}
	}
	if long := newSubstratePullCmd().Long; !strings.Contains(long, "Run it on the computer you started the agent from") {
		t.Errorf("pull help does not say where pull works:\n%s", long)
	}
}

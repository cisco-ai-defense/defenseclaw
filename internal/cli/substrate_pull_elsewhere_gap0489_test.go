// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/cli/substratecli/api"
	"github.com/defenseclaw/defenseclaw/internal/cli/substratecli/workspace"
	"github.com/defenseclaw/defenseclaw/internal/cliusage"
)

// GAP-0489: on a computer without the record, pull takes the checkout it
// runs in as the baseline (workspace TestPullOnAnotherComputerUsesTheCheckoutGAP0489).
// When it cannot (not a checkout, no agent folder of that name) the refusal
// is exit 3 and says why and what works; the help says where pull works.
func TestSubstratePullOnAnotherComputerSaysWhatWorksGAP0489(t *testing.T) {
	a := api.Actor{Atespace: "eng-web", Name: "fix-tests-1"}
	err := substratePullElsewhere(a, &workspace.NoRecordError{Reason: "this folder is not a git checkout with a commit to compare the agent's work with"})
	if cliusage.ExitCode(err) != substrateExitRefused {
		t.Fatalf("exit %d, want %d: %v", cliusage.ExitCode(err), substrateExitRefused, err)
	}
	for _, want := range []string{a.Atespace + "/" + a.Name + ": this computer has no record of the folder you sent", "not a git checkout",
		"Run pull in a git checkout of the folder you sent", "defenseclaw substrate connect " + a.Name, "git push it from inside the agent", "--push-branch works only on the computer you ran \"defenseclaw substrate run\" on"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("refusal lacks %q: %v", want, err)
		}
	}
	// GAP-1111: push-branch pushes only to the origin the run computer
	// recorded, so the refusal shown elsewhere never offers it here.
	if strings.Contains(err.Error(), "pull "+a.Name+" --push-branch") {
		t.Errorf("refusal offers --push-branch on a computer where it exits 3: %v", err)
	}
	if long := newSubstratePullCmd().Long; !strings.Contains(long, "run it in a git checkout of that folder") {
		t.Errorf("pull help does not say where pull works:\n%s", long)
	}
}

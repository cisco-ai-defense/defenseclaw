// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/guardrail/decide"
)

// TestGAP1156OwnCopyAlertLowersOnlyTheKitProofFindings: the own SSH folder
// copy alert past the budget lowers only the key findings the kit proofs
// added in this call (substrate-1 GAP-1156, CHK-1156S1 nit 1). A key
// finding made before, by any reader, keeps its proof, and a non-key
// finding after start is left as it is.
func TestGAP1156OwnCopyAlertLowersOnlyTheKitProofFindings(t *testing.T) {
	keyRule := "persistence.ssh_" + "authorized_keys_command"
	enforce := decide.Proof{Certainty: decide.CertKnown}
	findings := []RuleFinding{
		{RuleID: "ACTION-COMPOUND-LIMIT", Title: "budget", Proof: enforce},
		{RuleID: keyRule, Title: "before", Proof: enforce},
		{RuleID: "PATH-SSH-" + "KEY", Title: "before", Proof: enforce},
		{RuleID: keyRule, Title: "added", Proof: enforce},
		{RuleID: "PATH-SSH-" + "DIR", Title: "added", Proof: enforce},
		{RuleID: "tamper.detector_state_write", Title: "added", Proof: enforce},
	}
	adviseOverBudgetKitKeyFindings(findings, 3)
	for index, finding := range findings {
		advised := finding.Proof == enforce.Advise()
		want := index >= 3 && overBudgetKitKeyFinding(finding)
		if advised != want {
			t.Errorf("finding %d %s (%s): advised %v, want %v", index, finding.RuleID, finding.Title, advised, want)
		}
	}
	if findings[1].Title != "before" || findings[3].Title != ownSSHFolderCopyTitle {
		t.Errorf("titles %q %q: want the one before start kept and the added key-write titled as the own copy", findings[1].Title, findings[3].Title)
	}
}

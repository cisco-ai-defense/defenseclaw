// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"encoding/json"
	"path/filepath"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/guardrail"
)

// GAP-1661: "rulepack validate" without --dir reported "0 files, 0 rules"
// and the empty-input pin. The page and the help say it validates the
// embedded default pack: the shipped default rules, with the same summary
// as validating policies/guardrail/default.
func TestRulePackValidateWithoutDirValidatesTheShippedDefaultPack(t *testing.T) {
	previousDir, previousJSON := rulePackValidateDir, rulePackValidateJSON
	previousOutput := rulePackValidateCmd.OutOrStdout()
	t.Cleanup(func() {
		rulePackValidateDir, rulePackValidateJSON = previousDir, previousJSON
		rulePackValidateCmd.SetOut(previousOutput)
	})
	t.Setenv("DEFENSECLAW_CONFIG", filepath.Join(t.TempDir(), "absent.yaml"))

	shipped, err := guardrail.LoadRulePack(shippedRulePackForCLITest(t, "default"))
	if err != nil {
		t.Fatal(err)
	}
	want := shipped.Summary()

	rulePackValidateDir = ""
	rulePackValidateJSON = true
	output := &strings.Builder{}
	rulePackValidateCmd.SetOut(output)
	if err := rulePackValidateCmd.RunE(rulePackValidateCmd, nil); err != nil {
		t.Fatal(err)
	}
	var response rulePackWireResponse
	if err := json.Unmarshal([]byte(output.String()), &response); err != nil {
		t.Fatal(err)
	}
	if !response.Valid || response.Summary == nil ||
		response.Summary.RuleFileCount != want.RuleFileCount || response.Summary.RuleFileCount == 0 ||
		response.Summary.RuleCount != want.RuleCount ||
		response.Summary.FilesDigest != want.FilesDigest {
		t.Fatalf("validate without --dir = %+v, want the shipped default pack %+v", response.Summary, want)
	}
}

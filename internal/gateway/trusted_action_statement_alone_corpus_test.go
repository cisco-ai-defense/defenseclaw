// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/actionfacts"
)

// A code-owned rule that recognizes one complete POSIX command retains its
// finding and disposition when another statement makes the whole action
// partial. The corpus supplies independent commands across owner families.
func TestTrustedActionOwnersMatchCorpusCommandsAloneAndInLists(t *testing.T) {
	const connector = "statement-local-corpus-test"
	installDefaultProfileConnector(t, connector)
	seen := make(map[string]bool)
	for _, test := range readJSONL[toolCallCorpusCase](t, "toolcall", "corpus.jsonl") {
		if test.Command == "" || len(test.Args) != 0 || len(test.Argv) != 0 ||
			(test.Tool != "" && test.Tool != "shell") ||
			(test.Dialect != "" && test.Dialect != actionfacts.DialectPOSIX) || seen[test.RuleID] {
			continue
		}
		input := toolCallCorpusActionFactsInput(test)
		facts := actionfacts.Analyze(input)
		if !facts.Authoritative() || len(facts.Commands) != 1 ||
			strings.Contains(input.Command, "\n") || strings.Contains(input.Command, "<<") {
			continue
		}
		request := trustedActionRequest{
			Input:              input,
			LegacyText:         input.Command,
			Connector:          connector,
			EnforcementCapable: true,
		}
		alone := findingWithID(dispatchTrustedAction(t.Context(), request), test.RuleID)
		if alone == nil {
			continue
		}
		request.Input.Command += "; echo $HOME"
		request.LegacyText = request.Input.Command
		wrapped := findingWithID(dispatchTrustedAction(t.Context(), request), test.RuleID)
		if wrapped == nil ||
			wrapped.contributesToEnforcement() != alone.contributesToEnforcement() ||
			wrapped.contributesToAlertOnly() != alone.contributesToAlertOnly() {
			t.Errorf("%s (%s): finding in list = %+v, alone = %+v", test.ID, test.RuleID, wrapped, alone)
		}
		seen[test.RuleID] = true
	}
	if len(seen) < 10 {
		t.Fatalf("only %d owners exercised by the corpus", len(seen))
	}
	for _, ruleID := range []string{"PATH-SSH-KEY", "CMD-SYSTEMCTL", "source.git_config_exec"} {
		if !seen[ruleID] {
			t.Errorf("corpus did not exercise %s", ruleID)
		}
	}
}

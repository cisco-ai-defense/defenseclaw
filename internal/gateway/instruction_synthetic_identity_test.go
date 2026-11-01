// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"path"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/actionfacts"
	"github.com/defenseclaw/defenseclaw/internal/hookpaths"
)

// Several cross-OS decision matrices use paths such as /repo and C:\Repo on
// every host. A positive row models an existing startup file with the same
// identity fact the hook client supplies when the gateway cannot stat it.
func syntheticExistingInstructionEvidence(t *testing.T, input actionfacts.Input, rule string) map[string]string {
	t.Helper()
	if rule == "" {
		return nil
	}
	want := instructionRuleFiles[rule]
	if want == "" {
		t.Fatalf("no instruction filename for %s", rule)
	}
	add := func(candidate string) map[string]string {
		if strings.EqualFold(path.Base(strings.ReplaceAll(candidate, `\`, "/")), want) {
			return map[string]string{hookpaths.InstructionIdentityKey: candidate}
		}
		return nil
	}
	for _, candidate := range actionfacts.Analyze(input).Paths {
		if candidate.Access == actionfacts.PathAccessWrite || candidate.Access == actionfacts.PathAccessAppend ||
			candidate.Access == actionfacts.PathAccessDelete {
			if evidence := add(candidate.Resolved); evidence != nil {
				return evidence
			}
		}
	}
	if targets, complete := hookpaths.ApplyPatchWriteTargets(input.Tool, input.Args, input.Command, input.CWD, input.ActiveHome); complete {
		for _, target := range targets {
			if evidence := add(target); evidence != nil {
				return evidence
			}
		}
	}
	t.Fatalf("no resolved write to the simulated existing %s: %+v", want, input)
	return nil
}

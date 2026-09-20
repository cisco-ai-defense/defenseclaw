// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"slices"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/actionfacts"
)

const unboundedCPUFanoutRuleID = "impact.unbounded_cpu_fanout"

func TestExactUnboundedCPUFanoutPosture(t *testing.T) {
	command := `for worker in $(seq 1 64); do (while true; do :; done) & done`
	for _, test := range []struct {
		profile string
		action  string
	}{
		{profile: "default", action: "alert"},
		{profile: "permissive", action: "alert"},
		{profile: "strict", action: "block"},
	} {
		t.Run(test.profile, func(t *testing.T) {
			connector := "cpu-fanout-" + test.profile
			installToolCallCorpusProfileConnector(t, connector, test.profile)
			result := EvaluateDeterministicAction(
				t.Context(),
				actionfacts.Input{Tool: "shell", Command: command},
				command,
				connector,
				test.profile,
			)
			if !slices.Contains(result.RuleIDs, unboundedCPUFanoutRuleID) ||
				result.Action != test.action || result.Severity != "HIGH" {
				t.Fatalf("result=%+v, want exact %s", result, test.action)
			}
		})
	}
}

func TestExactUnboundedCPUFanoutGatewayHardNegatives(t *testing.T) {
	connector := "cpu-fanout-negatives"
	installToolCallCorpusProfileConnector(t, connector, "strict")
	for _, command := range []string{
		`make -j64`,
		`for worker in $(seq 1 64); do (while true; do sleep 1; done) & done`,
		`for worker in $(seq 1 63); do (while true; do :; done) & done`,
		`timeout 10 sh -c 'for worker in $(seq 1 64); do (while true; do :; done) & done'`,
		`for worker in $(seq 1 64); do (while true; do :; done) & done; wait`,
	} {
		result := EvaluateDeterministicAction(
			t.Context(),
			actionfacts.Input{Tool: "shell", Command: command},
			command,
			connector,
			"strict",
		)
		if slices.Contains(result.RuleIDs, unboundedCPUFanoutRuleID) {
			t.Fatalf("hard negative %q matched: %+v", command, result)
		}
	}
}

func TestExactUnboundedCPUFanoutContractIsCodeOwned(t *testing.T) {
	contract, ok := exactFallbackContracts[unboundedCPUFanoutRuleID]
	if !ok || contract.proves == nil || contract.boundedSubgraphProves == nil ||
		!contract.requiresExactDetectionProof || !contract.codeOwnedDetection ||
		contract.detectionOnly || contract.alertOnly {
		t.Fatalf("contract=%+v exists=%t", contract, ok)
	}
}

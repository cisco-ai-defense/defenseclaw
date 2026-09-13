// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/actionfacts"
)

const pkrootSetuidShellGatewayFixture = `/tmp/.build/pkroot/run --cmd 'cp /bin/bash /tmp/.pksh && chmod 4755 /tmp/.pksh'`

func TestPKRootSetuidShellUsesExactActionFactsProof(t *testing.T) {
	input := actionfacts.Input{Tool: "shell", Command: pkrootSetuidShellGatewayFixture, DialectHint: actionfacts.DialectPOSIX}
	facts := actionfacts.Analyze(input)
	if !actionfacts.ExactPKRootSetuidShell(facts) {
		t.Fatalf("fixture lacked exact ActionFacts proof: %+v", facts)
	}
	proof, owned := trustedSemanticOwnerFindingProof(
		"privilege.pkroot_setuid_shell", input, facts,
	)
	if owned || proof.authorizes("privilege.pkroot_setuid_shell") {
		t.Fatalf("partial generic parse unexpectedly became the proof boundary: owned=%v proof=%+v", owned, proof)
	}

	for _, profile := range []string{"default", "permissive", "strict"} {
		t.Run(profile, func(t *testing.T) {
			connector := "pkroot-setuid-shell-" + profile
			installToolCallCorpusProfileConnector(t, connector, profile)
			findings := dispatchTrustedAction(t.Context(), trustedActionRequest{
				Input: input, Connector: connector, EnforcementCapable: true,
			})
			finding := findingWithID(findings, "privilege.pkroot_setuid_shell")
			if finding == nil || !finding.contributesToEnforcement() {
				t.Fatalf("exact bounded proof did not enforce: finding=%+v all=%+v", finding, findings)
			}
			evaluation := EvaluateDeterministicAction(
				t.Context(), input, input.Command, connector, profile,
			)
			if evaluation.Action != "block" {
				t.Fatalf("profile=%s action=%q evaluation=%+v", profile, evaluation.Action, evaluation)
			}
		})
	}
}

func TestPKRootSetuidShellNearMissesDoNotReachRule(t *testing.T) {
	const connector = "pkroot-setuid-shell-negatives"
	installToolCallCorpusProfileConnector(t, connector, "default")
	for name, command := range map[string]string{
		"ordinary wrapper": strings.Replace(pkrootSetuidShellGatewayFixture, "/pkroot/run", "/runner/run", 1),
		"wrong target":     strings.Replace(pkrootSetuidShellGatewayFixture, "/tmp/.pksh", "/tmp/.helper", -1),
		"extra payload":    strings.Replace(pkrootSetuidShellGatewayFixture, "chmod 4755 /tmp/.pksh'", "chmod 4755 /tmp/.pksh && id'", 1),
		"outer sequence":   pkrootSetuidShellGatewayFixture + "; id",
	} {
		t.Run(name, func(t *testing.T) {
			input := actionfacts.Input{Tool: "shell", Command: command, DialectHint: actionfacts.DialectPOSIX}
			findings := dispatchTrustedAction(t.Context(), trustedActionRequest{
				Input: input, Connector: connector, EnforcementCapable: true,
			})
			if finding := findingWithID(findings, "privilege.pkroot_setuid_shell"); finding != nil {
				t.Fatalf("near miss reached exact rule: %+v", *finding)
			}
		})
	}
}

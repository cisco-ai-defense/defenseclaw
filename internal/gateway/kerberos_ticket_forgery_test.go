// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/actionfacts"
)

const kerberosTicketForgeryRuleID = "credential.kerberos_ticket_forgery"

func TestKerberosTicketForgeryProfilePosture(t *testing.T) {
	command := "impacket-ticketer -nthash " + strings.Repeat("a1", 16) +
		" -domain-sid S-1-5-21-1001-1002-1003" +
		" -domain lab.example Administrator"
	for _, test := range []struct {
		profile, severity, action string
	}{
		{"default", "LOW", guardrailActionAllow},
		{"permissive", "LOW", guardrailActionAllow},
		{"strict", "HIGH", guardrailActionBlock},
	} {
		t.Run(test.profile, func(t *testing.T) {
			const connector = "codex"
			installToolCallCorpusProfileConnector(t, connector, test.profile)
			input := actionfacts.Input{
				Tool: "shell", Command: command, DialectHint: actionfacts.DialectPOSIX,
			}
			findings := dispatchTrustedAction(t.Context(), trustedActionRequest{
				Input: input, LegacyText: command, Connector: connector,
				EnforcementCapable: true,
			})
			finding := findingWithID(findings, kerberosTicketForgeryRuleID)
			if finding == nil || finding.Severity != test.severity || finding.Evidence != "" ||
				!finding.contributesToEnforcement() {
				t.Fatalf("finding=%+v all=%v", finding, FindingStrings(findings))
			}
			if action := guardrailFallbackActionForProfile(finding.Severity, test.profile); action != test.action {
				t.Fatalf("action=%s want=%s", action, test.action)
			}
		})
	}
}

func TestKerberosTicketForgeryHardNegatives(t *testing.T) {
	key := strings.Repeat("a1", 16)
	base := "impacket-ticketer -nthash " + key +
		" -domain-sid S-1-5-21-1001-1002-1003 -domain lab.example Administrator"
	for _, command := range []string{
		"impacket-ticketer -h",
		strings.Replace(base, " -domain", " -aesKey "+strings.Repeat("b2", 32)+" -domain", 1),
		base + " -domain other.example",
		"sudo " + base,
		base + " | tee ticket.log",
		base + " 2>&1",
	} {
		for _, profile := range []string{"default", "permissive", "strict"} {
			const connector = "codex"
			installToolCallCorpusProfileConnector(t, connector, profile)
			input := actionfacts.Input{
				Tool: "shell", Command: command, DialectHint: actionfacts.DialectPOSIX,
			}
			if finding := findingWithID(
				dispatchTrustedAction(t.Context(), trustedActionRequest{
					Input: input, LegacyText: command, Connector: connector,
					EnforcementCapable: true,
				}),
				kerberosTicketForgeryRuleID,
			); finding != nil {
				t.Fatalf("profile=%s hard negative=%q finding=%+v", profile, command, finding)
			}
		}
	}
}

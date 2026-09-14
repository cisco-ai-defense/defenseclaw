// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/actionfacts"
	"github.com/defenseclaw/defenseclaw/internal/guardrail/semantic"
)

const posixLiteralPasswordChangeTrailingShellRuleID = "persistence.posix_literal_password_change_trailing_shell"

func TestPOSIXLiteralPasswordChangeTrailingShellSemanticOwnerAndCEL(t *testing.T) {
	compiler, err := semantic.NewCompiler()
	if err != nil {
		t.Fatal(err)
	}
	if _, code := compiler.Compile(semanticPOSIXLiteralPasswordChangeTrailingShellExpression); code != semantic.CompileOK {
		t.Fatalf("compile code=%s", code)
	}
	owner := semanticOwners[posixLiteralPasswordChangeTrailingShellRuleID]
	if owner.prerequisite == nil || owner.suppressFallback == nil || !owner.detectionOnly || owner.alertOnly {
		t.Fatalf("owner posture=%+v", owner)
	}
}

func TestPOSIXLiteralPasswordChangeTrailingShellDetectsWithoutBlocking(t *testing.T) {
	positives := []string{
		`echo -e "service-user\nfixture phrase\nfixture phrase"|passwd|bash`,
		`echo "root:fixture phrase"|chpasswd|bash`,
	}
	for _, profile := range []string{"default", "permissive", "strict"} {
		t.Run(profile, func(t *testing.T) {
			connector := "posix-password-chain-" + profile
			installToolCallCorpusProfileConnector(t, connector, profile)
			for _, command := range positives {
				input := actionfacts.Input{Tool: "shell", Command: command, DialectHint: actionfacts.DialectPOSIX}
				facts := actionfacts.Analyze(input)
				if !actionfacts.ExactPOSIXLiteralPasswordChangeTrailingShell(facts) {
					t.Fatalf("exact predicate rejected positive: %+v", facts)
				}
				findings := dispatchTrustedAction(t.Context(), trustedActionRequest{
					Input: input, Connector: connector, EnforcementCapable: true,
				})
				finding := findingWithID(findings, posixLiteralPasswordChangeTrailingShellRuleID)
				if finding == nil || finding.Severity != "HIGH" || finding.contributesToEnforcement() || finding.Evidence != "" {
					t.Fatalf("profile=%s finding=%+v all=%v", profile, finding, FindingStrings(findings))
				}
				encoded, err := json.Marshal(finding)
				if err != nil {
					t.Fatal(err)
				}
				if strings.Contains(string(encoded), "fixture phrase") || strings.Contains(string(encoded), "service-user") {
					t.Fatalf("finding retained account or password value: %s", encoded)
				}
			}
		})
	}
}

func TestPOSIXLiteralPasswordChangeTrailingShellHardNegativesStayQuiet(t *testing.T) {
	const connector = "posix-password-chain-negatives"
	installToolCallCorpusProfileConnector(t, connector, "default")
	tests := map[string]string{
		"ordinary two-stage passwd automation": `echo "service-user\nfixture phrase\nfixture phrase\n"|passwd`,
		"two-stage chpasswd automation":        `echo "root:fixture phrase"|chpasswd`,
		"interactive passwd":                   `passwd service-user`,
		"dynamic secret":                       `echo -e "service-user\n$PASSWORD\n$PASSWORD"|passwd|bash`,
		"mismatched confirmation":              `echo -e "service-user\nfirst phrase\nsecond phrase"|passwd|bash`,
		"multiple accounts":                    "echo \"root:fixture phrase\\nservice-user:fixture phrase\"|chpasswd|bash",
		"chpasswd options":                     `echo "root:fixture phrase"|chpasswd -R /staging|bash`,
		"sudo wrapper":                         `echo "root:fixture phrase"|sudo chpasswd|bash`,
		"different trailing shell":             `echo "root:fixture phrase"|chpasswd|sh`,
		"extra stage":                          `echo "root:fixture phrase"|chpasswd|bash|cat`,
		"outer sequence":                       `echo "root:fixture phrase"|chpasswd|bash; id`,
		"background pipeline":                  `echo "root:fixture phrase"|chpasswd|bash &`,
		"redirected source":                    `echo "root:fixture phrase" >/tmp/input|chpasswd|bash`,
	}
	for name, command := range tests {
		t.Run(name, func(t *testing.T) {
			input := actionfacts.Input{Tool: "shell", Command: command, DialectHint: actionfacts.DialectPOSIX}
			findings := dispatchTrustedAction(t.Context(), trustedActionRequest{
				Input: input, Connector: connector, EnforcementCapable: true,
			})
			if finding := findingWithID(findings, posixLiteralPasswordChangeTrailingShellRuleID); finding != nil {
				t.Fatalf("hard negative produced finding: %+v", *finding)
			}
		})
	}
}

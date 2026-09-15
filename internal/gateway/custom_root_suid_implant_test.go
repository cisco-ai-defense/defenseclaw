// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/actionfacts"
)

const customRootSUIDGatewayFixture = `cat >/tmp/suidtest.c <<'EOF'
#include <unistd.h>
#include <stdio.h>
int main(){setresuid(0,0,0);printf("euid=%d\n", geteuid());return 0;}
EOF
cc /tmp/suidtest.c -o /usr/local/bin/suidtest && chown root:root /usr/local/bin/suidtest && chmod 4755 /usr/local/bin/suidtest && ls -l /usr/local/bin/suidtest
su - deploybot -c '/usr/local/bin/suidtest'
`

func TestCustomRootSUIDImplantUsesExactActionFactsProof(t *testing.T) {
	input := customRootSUIDGatewayInput(t, customRootSUIDGatewayFixture)
	facts := actionfacts.Analyze(input)
	if !actionfacts.ExactCustomRootSUIDImplant(facts) {
		t.Fatalf("fixture lacked exact ActionFacts proof: %+v", facts)
	}

	proof, owned := trustedSemanticOwnerFindingProof(
		"privilege.custom_root_suid_implant", input, facts,
	)
	if owned || proof.authorizes("privilege.custom_root_suid_implant") {
		t.Fatal("partial generic shell parse unexpectedly became the proof boundary")
	}

	for _, profile := range []string{"default", "permissive", "strict"} {
		t.Run(profile, func(t *testing.T) {
			connector := "custom-root-suid-implant-" + profile
			installToolCallCorpusProfileConnector(t, connector, profile)
			findings := dispatchTrustedAction(t.Context(), trustedActionRequest{
				Input: input, Connector: connector, EnforcementCapable: true,
			})
			finding := findingWithID(findings, "privilege.custom_root_suid_implant")
			if finding == nil || !finding.contributesToEnforcement() {
				t.Fatalf("exact bounded proof did not enforce: finding=%+v all=%+v", finding, findings)
			}
		})
	}
}

func TestCustomRootSUIDImplantNearMissesDoNotReachRule(t *testing.T) {
	const connector = "custom-root-suid-implant-negatives"
	installToolCallCorpusProfileConnector(t, connector, "default")
	for name, command := range map[string]string{
		"chmod only": "chmod 4755 /usr/bin/passwd\n",
		"different output": strings.Replace(
			customRootSUIDGatewayFixture,
			"chown root:root /usr/local/bin/suidtest",
			"chown root:root /usr/local/bin/other",
			1,
		),
		"non-root owner": strings.Replace(
			customRootSUIDGatewayFixture, "chown root:root", "chown build:build", 1,
		),
		"inert source": strings.Replace(
			customRootSUIDGatewayFixture,
			"setresuid(0,0,0);",
			`printf("setresuid(0,0,0)");`,
			1,
		),
	} {
		t.Run(name, func(t *testing.T) {
			findings := dispatchTrustedAction(t.Context(), trustedActionRequest{
				Input:     customRootSUIDGatewayInput(t, command),
				Connector: connector, EnforcementCapable: true,
			})
			if finding := findingWithID(findings, "privilege.custom_root_suid_implant"); finding != nil {
				t.Fatalf("near miss reached exact rule: %+v", *finding)
			}
		})
	}
}

func customRootSUIDGatewayInput(t *testing.T, command string) actionfacts.Input {
	t.Helper()
	args, err := json.Marshal(map[string]any{"duration": 1.0, "keystrokes": command})
	if err != nil {
		t.Fatal(err)
	}
	return actionfacts.Input{Tool: "bash_command", Args: args, Command: command}
}

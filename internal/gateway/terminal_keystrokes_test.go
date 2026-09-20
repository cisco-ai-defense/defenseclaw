// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"encoding/json"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/actionfacts"
)

func TestTerminalKeystrokesSetuidUsesAuthoritativeSemanticRoute(t *testing.T) {
	const connector = "terminal-keystrokes-setuid"
	installToolCallCorpusProfileConnector(t, connector, "default")
	for _, command := range []string{
		"chmod 4755 /var/tmp/.cp\n",
		"chmod 4755 /var/tmp/.chown\n",
		"chmod 4755 /tmp/su-bash\n",
	} {
		args, err := json.Marshal(map[string]any{"duration": 0.1, "keystrokes": command})
		if err != nil {
			t.Fatal(err)
		}
		input := actionfacts.Input{Tool: "bash_command", Args: args}
		facts := actionfacts.Analyze(input)
		proof, owned := trustedSemanticOwnerFindingProof(
			"privilege.temporary_setuid_executable", input, facts,
		)
		if !owned || !proof.authorizes("privilege.temporary_setuid_executable") {
			t.Fatalf("command %q lacked semantic proof: facts=%+v proof=%+v", command, facts, proof)
		}
		findings := dispatchTrustedAction(t.Context(), trustedActionRequest{
			Input: input, Connector: connector, EnforcementCapable: true,
		})
		finding := findingWithID(findings, "privilege.temporary_setuid_executable")
		if finding == nil || finding.Evidence != "" || !finding.contributesToEnforcement() {
			t.Fatalf("command %q finding=%+v all=%+v", command, finding, findings)
		}
	}
}

func TestTerminalKeystrokesSchemaNearMissesDoNotReachSetuidRule(t *testing.T) {
	const connector = "terminal-keystrokes-setuid-negatives"
	installToolCallCorpusProfileConnector(t, connector, "default")
	for _, input := range []actionfacts.Input{
		{Tool: "database_query", Args: json.RawMessage(`{"keystrokes":"chmod 4755 /tmp/helper\n"}`)},
		{Tool: "bash_commands", Args: json.RawMessage(`{"keystrokes":"chmod 4755 /tmp/helper\n"}`)},
		{Tool: "bash_command", Args: json.RawMessage(`{"command":"chmod 4755 /tmp/helper\n"}`)},
		{Tool: "bash_command", Args: json.RawMessage(`{"keystrokes":"id; chmod 4755 /tmp/helper\n"}`)},
		{Tool: "bash_command", Args: json.RawMessage(`{"keystrokes":"chmod 4755 $TARGET\n"}`)},
		{Tool: "bash_command", Args: json.RawMessage(`{"keystrokes":"chmod 4755 /tmp/helper\u001b[A\n"}`)},
		{Tool: "bash_command", Args: json.RawMessage(`{"keystrokes":"chmod 4755 /tmp/helper\n"}`), Command: "id"},
	} {
		findings := dispatchTrustedAction(t.Context(), trustedActionRequest{
			Input: input, Connector: connector, EnforcementCapable: true,
		})
		if finding := findingWithID(findings, "privilege.temporary_setuid_executable"); finding != nil {
			t.Fatalf("near miss reached setuid rule: input=%+v finding=%+v", input, *finding)
		}
	}
}

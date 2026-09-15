// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/actionfacts"
)

const passwordCrackerPotfileRuleID = "PATH-PASSWORD-CRACKER-POTFILE"

func TestPasswordCrackerPotfileReadsDetectWithoutBlocking(t *testing.T) {
	commands := []string{
		`cat ~/.john/john.pot | tail -5`,
		`grep "EXAMPLE" /root/.local/share/hashcat/hashcat.potfile || sudo grep "EXAMPLE" /root/.local/share/hashcat/hashcat.potfile`,
		`sudo cat /root/.local/share/hashcat/hashcat.potfile`,
		`grep -r "account" /root/.john/john.pot 2>/dev/null; cat /root/.john/john.pot 2>/dev/null | grep -i kerb`,
		`cat ~/.john/john.pot | grep -i "account"`,
		`ls /tmp; echo marker; cat /root/.local/share/hashcat/hashcat.potfile 2>/dev/null | head -10; cat ~/.hashcat/hashcat.potfile 2>/dev/null | head -10`,
	}
	for _, profile := range []string{"default", "permissive", "strict"} {
		profile := profile
		t.Run(profile, func(t *testing.T) {
			connector := "potfile-" + profile
			installToolCallCorpusProfileConnector(t, connector, profile)
			for _, command := range commands {
				findings := dispatchTrustedAction(t.Context(), trustedActionRequest{
					Input: actionfacts.Input{
						Tool:       "shell",
						Command:    command,
						ActiveHome: "/home/alice",
					},
					LegacyText:         command,
					Connector:          connector,
					EnforcementCapable: true,
				})
				finding := findingWithID(findings, passwordCrackerPotfileRuleID)
				if finding == nil || finding.contributesToEnforcement() {
					t.Fatalf("command=%q finding=%+v all=%v", command, finding, FindingStrings(findings))
				}
			}
		})
	}
}

func TestPasswordCrackerPotfileNearMissesAbstain(t *testing.T) {
	owner := semanticOwners[passwordCrackerPotfileRuleID]
	for _, input := range []actionfacts.Input{
		{Command: `printf '%s' /root/.john/john.pot`},
		{Command: `ls -l /root/.john/john.pot`},
		{Command: `cat /tmp/fixture/root/.john/john.pot`},
		{Command: `cat /root/.john/john.pot.bak`},
		{Command: `cat /root/.John/john.pot`},
		{Command: `cat "$HOME/.john/john.pot"`, ActiveHome: "/home/alice"},
		{Command: `true && cat /root/.john/john.pot`},
		{Tool: "write_file", Args: []byte(`{"path":"/root/.john/john.pot","content":"fixture"}`)},
	} {
		if owner.eligible(actionfacts.Analyze(input)) {
			t.Fatalf("near miss unexpectedly satisfied owner: %+v", input)
		}
	}
}

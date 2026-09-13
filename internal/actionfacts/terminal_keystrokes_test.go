// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package actionfacts

import (
	"encoding/json"
	"testing"
)

func TestTerminalKeystrokesExactStaticPOSIXCommand(t *testing.T) {
	for _, command := range []string{
		"chmod 4755 /var/tmp/.cp\n",
		"chmod 4755 /var/tmp/.chown\n",
		"chmod 4755 /tmp/su-bash\n",
	} {
		facts := Analyze(Input{
			Tool: "bash_command",
			Args: json.RawMessage(`{"duration":0.1,"keystrokes":` + quotedJSON(t, command) + `}`),
		})
		if facts.Parse.Status != StatusComplete || facts.Parse.Dialect != DialectPOSIX ||
			len(facts.Commands) != 1 || !ExactTemporarySetuidExecutable(facts) {
			t.Fatalf("command %q did not produce an exact setuid proof: %+v", command, facts)
		}
	}
}

func TestTerminalKeystrokesUnknownOperandKeepsSingleCommandBoundary(t *testing.T) {
	const submitted = "history -c\n"
	facts := Analyze(Input{
		Tool:    "bash_command",
		Command: submitted,
		Args:    json.RawMessage(`{"duration":0.1,"keystrokes":"history -c\n"}`),
	})
	if facts.Parse.Status != StatusPartial ||
		containsIssue(facts.Parse.Issues, IssueConflictingSources) ||
		!containsIssue(facts.Parse.Issues, IssueUnknownOperandGrammar) ||
		containsIssue(facts.Parse.Issues, IssueUnsupportedConstruct) ||
		len(facts.Commands) != 1 || facts.Commands[0].Program != "history" {
		t.Fatalf("submitted static command boundary was not retained safely: %+v", facts)
	}
}

func TestTerminalKeystrokesRejectsUntrustedOrUncertainInput(t *testing.T) {
	tests := []struct {
		name string
		tool string
		args string
	}{
		{name: "arbitrary tool field", tool: "database_query", args: `{"keystrokes":"chmod 4755 /tmp/helper\n"}`},
		{name: "nearby tool name", tool: "bash_commands", args: `{"keystrokes":"chmod 4755 /tmp/helper\n"}`},
		{name: "wrong field", tool: "bash_command", args: `{"command":"chmod 4755 /tmp/helper\n"}`},
		{name: "non string", tool: "bash_command", args: `{"keystrokes":["chmod","4755","/tmp/helper"]}`},
		{name: "not submitted", tool: "bash_command", args: `{"keystrokes":"chmod 4755 /tmp/helper"}`},
		{name: "multiple commands", tool: "bash_command", args: `{"keystrokes":"id; chmod 4755 /tmp/helper\n"}`},
		{name: "multiple lines", tool: "bash_command", args: `{"keystrokes":"id\nchmod 4755 /tmp/helper\n"}`},
		{name: "dynamic target", tool: "bash_command", args: `{"keystrokes":"chmod 4755 $TARGET\n"}`},
		{name: "command substitution", tool: "bash_command", args: `{"keystrokes":"chmod 4755 $(cat target)\n"}`},
		{name: "pipeline", tool: "bash_command", args: `{"keystrokes":"printf x | chmod 4755 /tmp/helper\n"}`},
		{name: "redirect", tool: "bash_command", args: `{"keystrokes":"chmod 4755 /tmp/helper 2>/dev/null\n"}`},
		{name: "wrapper", tool: "bash_command", args: `{"keystrokes":"sudo chmod 4755 /tmp/helper\n"}`},
		{name: "terminal escape", tool: "bash_command", args: `{"keystrokes":"chmod 4755 /tmp/helper\u001b[A\n"}`},
		{name: "interactive followup", tool: "bash_command", args: `{"keystrokes":"top\nq\n"}`},
		{name: "unknown metadata", tool: "bash_command", args: `{"keystrokes":"chmod 4755 /tmp/helper\n","input":"yes"}`},
		{name: "conflicting normalized command", tool: "bash_command", args: `{"keystrokes":"chmod 4755 /tmp/helper\n"}`},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			input := Input{Tool: test.tool, Args: json.RawMessage(test.args)}
			if test.name == "conflicting normalized command" {
				input.Command = "id"
			}
			facts := Analyze(input)
			if ExactTemporarySetuidExecutable(facts) || facts.Parse.Status == StatusComplete ||
				(test.name != "conflicting normalized command" && len(facts.Commands) != 0) {
				t.Fatalf("untrusted or uncertain input became authoritative: %+v", facts)
			}
		})
	}
}

func quotedJSON(t *testing.T, value string) string {
	t.Helper()
	encoded, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	return string(encoded)
}

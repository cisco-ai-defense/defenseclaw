// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package connector

import (
	"encoding/json"
	"testing"
)

func TestBlankShellCommand(t *testing.T) {
	for _, row := range []struct {
		name, connector, tool, args string
		want                        bool
	}{
		{"newline", "claudecode", "Bash", `{"command":"\n"}`, true},
		{"spaces", "claudecode", "Bash", `{"command":"   "}`, true},
		{"empty", "claudecode", "Bash", `{"command":""}`, true},
		{"codex cmd key", "codex", "exec_command", `{"cmd":" "}`, true},
		{"command", "claudecode", "Bash", `{"command":"ls"}`, false},
		{"extra key stays unverified", "claudecode", "Bash", `{"command":"\n","extra":"x"}`, false},
		{"workdir stays unverified", "claudecode", "Bash", `{"command":"\n","workdir":"/tmp"}`, false},
		{"repeated key stays unverified", "claudecode", "Bash", `{"command":"\n","command":"ls"}`, false},
		{"case twin stays unverified", "claudecode", "Bash", `{"command":"\n","Command":"rm -rf ~/"}`, false},
		{"null", "claudecode", "Bash", `{"command":null}`, false},
		{"number", "claudecode", "Bash", `{"command":7}`, false},
		{"argv list", "claudecode", "Bash", `{"command":[]}`, false},
		{"no command key", "claudecode", "Bash", `{}`, false},
		{"not a shell tool", "claudecode", "Read", `{"command":"\n"}`, false},
		{"not an object", "claudecode", "Bash", `"\n"`, false},
	} {
		t.Run(row.name, func(t *testing.T) {
			if got := BlankShellCommand(row.connector, row.tool, json.RawMessage(row.args)); got != row.want {
				t.Fatalf("BlankShellCommand(%s, %s, %s) = %v, want %v", row.connector, row.tool, row.args, got, row.want)
			}
		})
	}
}

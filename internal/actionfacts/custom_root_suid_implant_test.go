// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package actionfacts

import (
	"encoding/json"
	"strings"
	"testing"
)

const rootSUIDImplantFixture = `cat >/tmp/suidtest.c <<'EOF'
#include <unistd.h>
#include <stdio.h>
int main(){setuid(0);setgid(0);printf("uid=%d\n", getuid());return 0;}
EOF
cc /tmp/suidtest.c -o /usr/local/bin/suidtest && chown root:root /usr/local/bin/suidtest && chmod 4755 /usr/local/bin/suidtest && ls -l /usr/local/bin/suidtest
su - deploybot -c '/usr/local/bin/suidtest'
`

func TestExactCustomRootSUIDImplant(t *testing.T) {
	facts := Analyze(customRootSUIDInput(t, rootSUIDImplantFixture))
	if !ExactCustomRootSUIDImplant(facts) || len(facts.CustomRootSUIDImplants) != 1 {
		t.Fatalf("closed implant grammar did not produce exact proof: %+v", facts)
	}
}

func TestExactCustomRootSUIDImplantHardNegatives(t *testing.T) {
	tests := map[string]string{
		"ordinary setuid restoration": "chmod 4755 /usr/bin/passwd\n",
		"different compiler output": strings.Replace(
			rootSUIDImplantFixture,
			"cc /tmp/suidtest.c -o /usr/local/bin/suidtest",
			"cc /tmp/suidtest.c -o /usr/local/bin/other",
			1,
		),
		"different owner target": strings.Replace(
			rootSUIDImplantFixture,
			"chown root:root /usr/local/bin/suidtest",
			"chown root:root /usr/local/bin/other",
			1,
		),
		"non-root owner": strings.Replace(
			rootSUIDImplantFixture, "chown root:root", "chown deploybot:deploybot", 1,
		),
		"dynamic source path": strings.Replace(
			rootSUIDImplantFixture, "/tmp/suidtest.c", "$SOURCE", -1,
		),
		"dynamic output path": strings.Replace(
			rootSUIDImplantFixture, "/usr/local/bin/suidtest", "$OUTPUT", -1,
		),
		"inert comment": strings.Replace(
			rootSUIDImplantFixture,
			"setuid(0);setgid(0);",
			"/* setuid(0); */ setgid(0);",
			1,
		),
		"inert string": strings.Replace(
			rootSUIDImplantFixture,
			"setuid(0);setgid(0);",
			`printf("setuid(0)");setgid(0);`,
			1,
		),
		"dead branch": strings.Replace(
			rootSUIDImplantFixture,
			"setuid(0);setgid(0);",
			"if (0) setuid(0);setgid(0);",
			1,
		),
		"non-executable setuid mode": strings.Replace(
			rootSUIDImplantFixture, "chmod 4755", "chmod 4600", 1,
		),
		"setgid only": strings.Replace(
			rootSUIDImplantFixture, "chmod 4755", "chmod 2755", 1,
		),
		"unknown extra action": strings.Replace(
			rootSUIDImplantFixture,
			"su - deploybot -c '/usr/local/bin/suidtest'\n",
			"echo done\n",
			1,
		),
	}
	for name, command := range tests {
		t.Run(name, func(t *testing.T) {
			facts := Analyze(customRootSUIDInput(t, command))
			if ExactCustomRootSUIDImplant(facts) || len(facts.CustomRootSUIDImplants) != 0 {
				t.Fatalf("near miss produced exact proof: %+v", facts)
			}
		})
	}
}

func TestExactCustomRootSUIDImplantRejectsUntrustedSchema(t *testing.T) {
	args := customRootSUIDArgs(t, rootSUIDImplantFixture)
	for name, input := range map[string]Input{
		"wrong tool": {Tool: "shell", Args: args},
		"conflicting command": {
			Tool: "bash_command", Args: args, Command: "id\n",
		},
		"unknown field": {
			Tool: "bash_command",
			Args: json.RawMessage(`{"keystrokes":` + quotedJSON(t, rootSUIDImplantFixture) + `,"duration":1,"result":"succeeded"}`),
		},
		"untrusted failed outcome": {
			Tool: "bash_command",
			Args: json.RawMessage(`{"keystrokes":` + quotedJSON(t, rootSUIDImplantFixture) + `,"duration":1,"outcome":"failed"}`),
		},
		"untrusted unknown outcome": {
			Tool: "bash_command",
			Args: json.RawMessage(`{"keystrokes":` + quotedJSON(t, rootSUIDImplantFixture) + `,"duration":1,"outcome":"unknown"}`),
		},
	} {
		t.Run(name, func(t *testing.T) {
			if facts := Analyze(input); ExactCustomRootSUIDImplant(facts) {
				t.Fatalf("untrusted schema produced exact proof: %+v", facts)
			}
		})
	}
}

// Failed and unknown outcomes are intentionally absent from this same-action
// pre-execution proof. A future multi-event implementation must consume only
// authenticated successful lifecycle events; raw result fields are rejected.
func customRootSUIDInput(t *testing.T, command string) Input {
	t.Helper()
	return Input{Tool: "bash_command", Args: customRootSUIDArgs(t, command), Command: command}
}

func customRootSUIDArgs(t *testing.T, command string) json.RawMessage {
	t.Helper()
	encoded, err := json.Marshal(map[string]any{"duration": 1.0, "keystrokes": command})
	if err != nil {
		t.Fatal(err)
	}
	return encoded
}

// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package actionfacts

import (
	"encoding/json"
	"strings"
	"testing"
)

const pkrootSetuidShellFixture = `/tmp/.build/pkroot/run --cmd 'cp /bin/bash /tmp/.pksh && chmod 4755 /tmp/.pksh'`

func TestExactPKRootSetuidShell(t *testing.T) {
	for _, command := range []string{
		pkrootSetuidShellFixture,
		`/var/tmp/.system-cache/pkroot/run --cmd "cp /bin/bash /tmp/.pksh && chmod 4755 /tmp/.pksh"`,
		`/dev/shm/pkroot/run --cmd 'cp /bin/bash /tmp/.pksh && chmod 4755 /tmp/.pksh'`,
	} {
		facts := Analyze(Input{Tool: "shell", Command: command, DialectHint: DialectPOSIX})
		if !ExactPKRootSetuidShell(facts) || len(facts.PKRootSetuidShells) != 1 {
			t.Fatalf("closed pkroot grammar did not produce exact proof for %q: %+v", command, facts)
		}
	}
	matchingArgs, err := json.Marshal(map[string]any{"command": pkrootSetuidShellFixture})
	if err != nil {
		t.Fatal(err)
	}
	if facts := Analyze(Input{Tool: "shell", Args: matchingArgs, Command: pkrootSetuidShellFixture, DialectHint: DialectPOSIX}); !ExactPKRootSetuidShell(facts) {
		t.Fatalf("matching command envelope did not produce proof: %+v", facts)
	}
}

func TestExactPKRootSetuidShellHardNegatives(t *testing.T) {
	tests := map[string]Input{
		"non-temporary wrapper": {Tool: "shell", Command: strings.Replace(pkrootSetuidShellFixture, "/tmp/.build", "/opt/helper", 1), DialectHint: DialectPOSIX},
		"wrong wrapper":         {Tool: "shell", Command: strings.Replace(pkrootSetuidShellFixture, "/pkroot/run", "/runner/run", 1), DialectHint: DialectPOSIX},
		"unquoted payload":      {Tool: "shell", Command: strings.ReplaceAll(pkrootSetuidShellFixture, "'", ""), DialectHint: DialectPOSIX},
		"dynamic wrapper":       {Tool: "shell", Command: strings.Replace(pkrootSetuidShellFixture, "/tmp/.build", "$ROOT", 1), DialectHint: DialectPOSIX},
		"substitution wrapper":  {Tool: "shell", Command: strings.Replace(pkrootSetuidShellFixture, "/tmp/.build", "$(mktemp -d)", 1), DialectHint: DialectPOSIX},
		"wrong source":          {Tool: "shell", Command: strings.Replace(pkrootSetuidShellFixture, "/bin/bash", "/bin/sh", 1), DialectHint: DialectPOSIX},
		"wrong copy target":     {Tool: "shell", Command: strings.Replace(pkrootSetuidShellFixture, "cp /bin/bash /tmp/.pksh", "cp /bin/bash /tmp/.other", 1), DialectHint: DialectPOSIX},
		"wrong chmod target":    {Tool: "shell", Command: strings.Replace(pkrootSetuidShellFixture, "chmod 4755 /tmp/.pksh", "chmod 4755 /tmp/.other", 1), DialectHint: DialectPOSIX},
		"wrong mode":            {Tool: "shell", Command: strings.Replace(pkrootSetuidShellFixture, "4755", "0755", 1), DialectHint: DialectPOSIX},
		"unknown argument":      {Tool: "shell", Command: pkrootSetuidShellFixture + " --verbose", DialectHint: DialectPOSIX},
		"payload control flow":  {Tool: "shell", Command: strings.Replace(pkrootSetuidShellFixture, "chmod 4755 /tmp/.pksh'", "chmod 4755 /tmp/.pksh && id'", 1), DialectHint: DialectPOSIX},
		"outer control flow":    {Tool: "shell", Command: pkrootSetuidShellFixture + "; id", DialectHint: DialectPOSIX},
		"redirect":              {Tool: "shell", Command: pkrootSetuidShellFixture + " >/dev/null", DialectHint: DialectPOSIX},
		"structured argv": {Tool: "shell", Argv: []string{
			"/tmp/.build/pkroot/run", "--cmd", pkrootSetuidShellPayload,
		}, DialectHint: DialectPOSIX},
	}
	for name, input := range tests {
		t.Run(name, func(t *testing.T) {
			facts := Analyze(input)
			if ExactPKRootSetuidShell(facts) || len(facts.PKRootSetuidShells) != 0 {
				t.Fatalf("near miss produced exact proof: input=%+v facts=%+v", input, facts)
			}
		})
	}
}

func TestExactPKRootSetuidShellRejectsUntrustedEnvelopes(t *testing.T) {
	matchingArgs, err := json.Marshal(map[string]any{"command": pkrootSetuidShellFixture})
	if err != nil {
		t.Fatal(err)
	}
	unknownArgs, err := json.Marshal(map[string]any{"command": pkrootSetuidShellFixture, "unknown": true})
	if err != nil {
		t.Fatal(err)
	}
	for name, input := range map[string]Input{
		"conflicting command sources": {
			Tool: "shell", Args: matchingArgs, Command: "id", DialectHint: DialectPOSIX,
		},
		"unknown argument field": {
			Tool: "shell", Args: unknownArgs, DialectHint: DialectPOSIX,
		},
		"command and argv conflict": {
			Tool: "shell", Command: pkrootSetuidShellFixture, Argv: []string{"id"}, DialectHint: DialectPOSIX,
		},
	} {
		t.Run(name, func(t *testing.T) {
			facts := Analyze(input)
			if ExactPKRootSetuidShell(facts) {
				t.Fatalf("untrusted envelope acquired authority: input=%+v facts=%+v", input, facts)
			}
		})
	}
}

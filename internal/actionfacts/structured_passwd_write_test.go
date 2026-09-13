// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package actionfacts

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestStructuredPasswdWriteProjectsValueFreeNonRootUIDZeroProof(t *testing.T) {
	for _, tool := range []string{"write_file", "write-file", "writefile"} {
		t.Run(tool, func(t *testing.T) {
			facts := Analyze(Input{
				Tool: tool,
				Args: json.RawMessage(`{"path":"/etc/passwd","content":"root:x:0:0:root:/root:/bin/bash\nbackup:x:0:0:Backup:/root:/bin/bash\n"}`),
			})
			if !facts.Authoritative() || !facts.EnforcementEligible() ||
				!ExactPOSIXNonRootUIDZeroAccountWrite(facts) {
				t.Fatalf("facts=%+v", facts)
			}
			if len(facts.POSIXNonRootUIDZeroAccountWrites) != 1 {
				t.Fatalf("proofs=%+v", facts.POSIXNonRootUIDZeroAccountWrites)
			}
			projected := facts.EnforcementProjection()
			if !ExactPOSIXNonRootUIDZeroAccountWrite(projected) {
				t.Fatalf("enforcement projection lost proof: %+v", projected)
			}
			encoded, err := json.Marshal(facts)
			if err != nil {
				t.Fatal(err)
			}
			for _, secret := range []string{"backup", "Backdoor", "/bin/bash"} {
				if strings.Contains(string(encoded), secret) {
					t.Fatalf("serialized facts retained %q: %s", secret, encoded)
				}
			}
		})
	}
}

func TestStructuredPasswdWriteNearMissesAbstain(t *testing.T) {
	oversized := strings.Repeat("a", maxCommandBytes+1)
	tests := []struct {
		name  string
		input Input
	}{
		{name: "root record only", input: passwdWriteInput("/etc/passwd", "root:x:0:0:root:/root:/bin/bash\n")},
		{name: "ordinary account", input: passwdWriteInput("/etc/passwd", "backup:x:1000:1000:Backup:/home/backup:/bin/bash\n")},
		{name: "uid leading zero", input: passwdWriteInput("/etc/passwd", "backup:x:00:0:Backup:/root:/bin/bash\n")},
		{name: "signed uid", input: passwdWriteInput("/etc/passwd", "backup:x:+0:0:Backup:/root:/bin/bash\n")},
		{name: "relative target", input: passwdWriteInput("etc/passwd", "backup:x:0:0:Backup:/root:/bin/bash\n")},
		{name: "normalized alias", input: passwdWriteInput("/etc/../etc/passwd", "backup:x:0:0:Backup:/root:/bin/bash\n")},
		{name: "fixture target", input: passwdWriteInput("/repo/fixtures/etc/passwd", "backup:x:0:0:Backup:/root:/bin/bash\n")},
		{name: "comment", input: passwdWriteInput("/etc/passwd", "# example\nbackup:x:0:0:Backup:/root:/bin/bash\n")},
		{name: "example prose", input: passwdWriteInput("/etc/passwd", "example: backup:x:0:0:Backup:/root:/bin/bash")},
		{name: "ellipsis fixture", input: passwdWriteInput("/etc/passwd", "...\nbackup:x:0:0:Backup:/root:/bin/bash\n")},
		{name: "malformed missing shell", input: passwdWriteInput("/etc/passwd", "backup:x:0:0:Backup:/root\n")},
		{name: "malformed empty home", input: passwdWriteInput("/etc/passwd", "backup:x:0:0:Backup::/bin/bash\n")},
		{name: "dynamic uid", input: passwdWriteInput("/etc/passwd", "backup:x:${UID}:0:Backup:/root:/bin/bash\n")},
		{name: "template record", input: passwdWriteInput("/etc/passwd", "{{username}}:x:0:0:Backup:/root:/bin/bash\n")},
		{name: "duplicate account", input: passwdWriteInput("/etc/passwd", "backup:x:0:0:Backup:/root:/bin/bash\nbackup:x:0:0:Backup:/root:/bin/bash\n")},
		{name: "unknown field", input: Input{Tool: "write_file", Args: json.RawMessage(`{"path":"/etc/passwd","content":"backup:x:0:0:Backup:/root:/bin/bash\n","description":"fixture"}`)}},
		{name: "conflicting command", input: Input{Tool: "write_file", Args: passwdWriteInput("/etc/passwd", "backup:x:0:0:Backup:/root:/bin/bash\n").Args, Command: "echo fixture"}},
		{name: "append schema", input: Input{Tool: "append_file", Args: passwdWriteInput("/etc/passwd", "backup:x:0:0:Backup:/root:/bin/bash\n").Args}},
		{name: "generic mention", input: Input{Tool: "search", Args: json.RawMessage(`{"query":"write backup:x:0:0 to /etc/passwd"}`)}},
		{name: "oversized content", input: passwdWriteInput("/etc/passwd", oversized)},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			facts := Analyze(test.input)
			if ExactPOSIXNonRootUIDZeroAccountWrite(facts) ||
				len(facts.POSIXNonRootUIDZeroAccountWrites) != 0 {
				t.Fatalf("near miss minted proof: %+v", facts)
			}
		})
	}
}

func TestExactStructuredPasswdWriteRejectsUnbackedPrivateFacts(t *testing.T) {
	for _, facts := range []Facts{
		{POSIXNonRootUIDZeroAccountWrites: []POSIXNonRootUIDZeroAccountWriteFact{{}}},
		{
			Parse:                            ParseResult{Status: StatusComplete},
			POSIXNonRootUIDZeroAccountWrites: []POSIXNonRootUIDZeroAccountWriteFact{{}},
		},
		{
			Parse:                            ParseResult{Status: StatusComplete},
			Commands:                         []CommandFact{{Effect: EffectExecute}},
			POSIXNonRootUIDZeroAccountWrites: []POSIXNonRootUIDZeroAccountWriteFact{{}, {}},
		},
	} {
		if ExactPOSIXNonRootUIDZeroAccountWrite(facts) {
			t.Fatalf("unbacked fact was accepted: %+v", facts)
		}
	}
}

func passwdWriteInput(target, content string) Input {
	args, err := json.Marshal(map[string]string{"path": target, "content": content})
	if err != nil {
		panic(err)
	}
	return Input{Tool: "write_file", Args: args}
}

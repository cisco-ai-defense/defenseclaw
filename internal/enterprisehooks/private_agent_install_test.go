package enterprisehooks

import "testing"

func TestUnprotectedAgentRecordKeepsDistinctPrivateCopies(t *testing.T) {
	agents := []UnprotectedAgent{
		{User: "alice", Connector: "claudecode", Version: "2.0.77", InstallPath: "/home/alice/old-a/node_modules/@anthropic-ai/claude-code", Code: UnprotectedCodeHookContractUnverified, Reason: "old copy"},
		{User: "alice", Connector: "claudecode", Version: "1.0.128", InstallPath: "/home/alice/old-b/node_modules/@anthropic-ai/claude-code", Code: UnprotectedCodeHookContractUnverified, Reason: "older copy"},
	}
	encoded, err := MarshalUnprotectedAgents(agents)
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := ParseUnprotectedAgents(encoded)
	if err != nil {
		t.Fatal(err)
	}
	if len(decoded) != 2 || decoded[0].InstallPath == decoded[1].InstallPath || decoded[0].Version == decoded[1].Version {
		t.Fatalf("private copies collapsed in the protected record: %+v", decoded)
	}
}

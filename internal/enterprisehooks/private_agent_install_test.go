package enterprisehooks

import (
	"strings"
	"testing"
	"unicode/utf8"
)

func TestUnprotectedRecordCarriesConfigGeneration(t *testing.T) {
	legacy, err := MarshalUnprotectedAgents(nil)
	if err != nil || UnprotectedAgentsRecordConfigGeneration(legacy) != 0 {
		t.Fatalf("legacy record config generation = %d, %v", UnprotectedAgentsRecordConfigGeneration(legacy), err)
	}
	if UnprotectedAgentsRecordConfigSHA256(legacy) != "" {
		t.Fatalf("legacy record config digest = %q", UnprotectedAgentsRecordConfigSHA256(legacy))
	}
	current, err := MarshalUnprotectedAgentsForConfig(nil, 7, "abc123")
	if err != nil || UnprotectedAgentsRecordConfigGeneration(current) != 7 || UnprotectedAgentsRecordConfigSHA256(current) != "abc123" {
		t.Fatalf("current record config generation = %d digest = %q, %v", UnprotectedAgentsRecordConfigGeneration(current), UnprotectedAgentsRecordConfigSHA256(current), err)
	}
	if _, err := ParseUnprotectedAgents(current); err != nil {
		t.Fatalf("current record is unreadable: %v", err)
	}
}

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

// GAP-0163 (GAP-2479 criterion): a private copy whose version cannot be read
// is reported with its cause and the step that helps, and the Claude Code
// step names its own installer commands.
func TestPrivateInstallUnreadVersionNamesTheStep(t *testing.T) {
	for _, connector := range []string{"claudecode", "codex", "copilot"} {
		agent, ok := privateInstallUnprotected(PrivateAgentInstall{Connector: connector, Path: "copy"})
		if !ok || agent.Code != UnprotectedCodeHookContractUnverified {
			t.Fatalf("%s: %+v, %v", connector, agent, ok)
		}
		for _, want := range []string{"version could not be read", "remove this copy", "reinstall or update", "next enumeration"} {
			if !strings.Contains(agent.Reason, want) {
				t.Fatalf("%s: reason %q does not contain %q", connector, agent.Reason, want)
			}
		}
		if got := strings.Contains(agent.Reason, "claude update"); got != (connector == "claudecode") {
			t.Fatalf("%s: Claude Code step in %q: %v", connector, agent.Reason, got)
		}
		if n := utf8.RuneCountInString(agent.Reason); n > unprotectedReasonMaxRunes {
			t.Fatalf("%s: the reason has %d runes, more than the record keeps", connector, n)
		}
		if strings.Contains(agent.Reason, "PATH") {
			t.Fatalf("%s: runtime-on-PATH advice for an unread version: %q", connector, agent.Reason)
		}
	}
}

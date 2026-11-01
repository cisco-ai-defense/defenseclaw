package enterprisehooks

import (
	"strings"
	"testing"
	"unicode/utf8"
)

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

// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package enterprisehooks

import (
	"fmt"
	"strings"
	"testing"
)

// unversionedOpenCode is the entry the Linux and macOS enumerator writes for
// an account whose run of path printed no version (enumerator_unix.go).
func unversionedOpenCode(user, path string) UnprotectedAgent {
	return UnprotectedAgent{User: user, Connector: "opencode", Code: UnprotectedCodeHookContractUnverified,
		Reason: UnixAgentUnversionedReasonPrefix + path + UnixAgentUnversionedContractSuffix}
}

// rel-1-0-6 GAP-0380: on a 14-account managed RHEL host with a machine-wide
// OpenCode V1 under /opt/dc-agents, status printed the one machine-wide
// opencode_v1_unprotected line and also one hook_contract_unverified line per
// account whose own run of /opt/dc-agents/bin/opencode (the same copy's
// launcher) printed no version. Those join the machine-wide line, which counts
// them; any other per-account problem keeps its own line.
func TestCollapseSharedOpenCodeV1FoldsTheLaunchersUnversionedAccounts(t *testing.T) {
	machine := "/opt/dc-agents/lib/node_modules/opencode-ai"
	launcher := "/opt/dc-agents/bin/opencode"
	var agents []UnprotectedAgent
	for i := 1; i <= 14; i++ {
		agents = append(agents, UnprotectedAgent{User: fmt.Sprintf("u%02d", i), Connector: "opencode", Version: "1.18.34",
			InstallPath: machine, Code: UnprotectedCodeOpenCodeV1, Reason: openCodeV1Reason})
	}
	// 10 of the 14 accounts, and one account the V1 scan did not list, also
	// have the unversioned entry for the launcher.
	var folded []UnprotectedAgent
	for i := 1; i <= 10; i++ {
		folded = append(folded, unversionedOpenCode(fmt.Sprintf("u%02d", i), launcher))
	}
	folded = append(folded, unversionedOpenCode("u15", launcher))
	// Different, real problems that must keep their own lines.
	kept := []UnprotectedAgent{
		unversionedOpenCode("u03", "/home/u03/.local/bin/opencode"), // a private copy
		{User: "u04", Connector: "opencode", Code: UnprotectedCodeHookContractUnverified, // a launcher others can change
			Reason: UnixAgentUnversionedReasonPrefix + launcher + " (not run: accounts other than root and this user can change it; use a root-owned agent_prefixes path)" + UnixAgentUnversionedContractSuffix},
		{User: "u05", Connector: "opencode", Version: "2.0.1", Code: UnprotectedCodeHookContractUnverified, Reason: "version 2.0.1 is not verified against a known hook contract"},
		{User: "u06", Connector: "claudecode", Code: UnprotectedCodeHookContractUnverified, // another agent
			Reason: UnixAgentUnversionedReasonPrefix + "/opt/dc-agents/bin/claude" + UnixAgentUnversionedContractSuffix},
		{User: "u07", Connector: "opencode", Code: UnprotectedCodeInstallScanIncomplete, Reason: "the bounded scan of this account's private agent installs was incomplete"},
		unversionedOpenCode("u08", "/opt/other/bin/opencode"), // another copy
	}
	all := append(append(append([]UnprotectedAgent{}, agents...), folded...), kept...)
	lines, collapsed := CollapseSharedOpenCodeV1(all, "/etc/defenseclaw/hook-guardian/unprotected-agents.json")
	if len(lines) != 1 {
		t.Fatalf("want one machine-wide line, got %+v", lines)
	}
	line := lines[0]
	if len(line.Members) != 15 || line.Unversioned != 11 || line.Launcher != launcher {
		t.Fatalf("line members %d unversioned %d launcher %q, want 15, 11, %q", len(line.Members), line.Unversioned, line.Launcher, launcher)
	}
	message := line.Message()
	for _, want := range []string{"machine-wide copy and is not protected for 15 users", "For 11 of these users the version check of " + launcher,
		"hook_contract_unverified", "the same fix covers them", "npm install -g @opencode/cli@2"} {
		if !strings.Contains(message, want) {
			t.Fatalf("line %q lacks %q", message, want)
		}
	}
	for i := 1; i <= 15; i++ {
		if strings.Contains(message, fmt.Sprintf("u%02d", i)) {
			t.Fatalf("the machine-wide line names an account: %q", message)
		}
	}
	for _, agent := range append(append([]UnprotectedAgent{}, agents...), folded...) {
		if !collapsed(agent) {
			t.Fatalf("%s %s %q is not covered by the machine-wide line", agent.User, agent.Code, agent.Reason)
		}
	}
	for _, agent := range kept {
		if collapsed(agent) {
			t.Fatalf("a different problem was folded into the machine-wide line: %s %s %q", agent.User, agent.Code, agent.Reason)
		}
	}

	// Without a machine-wide V1 line the unversioned entries keep their own
	// lines: nothing names the copy they share.
	if lines, collapsed := CollapseSharedOpenCodeV1(folded, ""); len(lines) != 0 || collapsed(folded[0]) {
		t.Fatalf("unversioned entries with no machine-wide copy must keep their lines: %+v", lines)
	}
	// A V1 copy outside an npm prefix layout has no known launcher.
	odd := []UnprotectedAgent{
		{User: "a", Connector: "opencode", Version: "1.18.34", InstallPath: "/opt/opencode", Code: UnprotectedCodeOpenCodeV1, Reason: openCodeV1Reason},
		{User: "b", Connector: "opencode", Version: "1.18.34", InstallPath: "/opt/opencode", Code: UnprotectedCodeOpenCodeV1, Reason: openCodeV1Reason},
		unversionedOpenCode("a", "/opt/bin/opencode"),
	}
	if lines, collapsed := CollapseSharedOpenCodeV1(odd, ""); len(lines) != 1 || lines[0].Unversioned != 0 || collapsed(odd[2]) {
		t.Fatalf("no launcher, no fold: %+v", lines)
	}
}

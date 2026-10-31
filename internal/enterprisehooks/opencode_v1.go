// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package enterprisehooks

import (
	"fmt"
	"path"
	"strings"

	"github.com/defenseclaw/defenseclaw/internal/gateway/connector"
)

// OpenCode V1 (the opencode-ai package, versions 1.x) loads the OpenCode V2
// plugin DefenseClaw puts in machine policy, but it never registers the
// plugin hooks: every tool call runs unchecked and nothing says so
// (rel-1-0-6 GAP-0037). Per-user setup and the gateway refuse V1; on a
// managed host only status, verify and ensure can tell the administrator.
// The separate-copy scan looks for the V1 package wherever a user can run
// it, and every unprotected-agents entry that is OpenCode V1 gets its own
// code and remedy, so coverage_complete is false while V1 is installed.
// Remove with the 1.0.x upgrade path, once no supported release guards V1.

// openCodeV1Package is the OpenCode V1 npm package; V2 is @opencode/cli.
const openCodeV1Package = "opencode-ai"

// openCodeV1Reason is the reason of every OpenCode V1 entry: what it means
// and the exact remedy.
const openCodeV1Reason = "it is OpenCode V1 (opencode-ai), which cannot run the DefenseClaw OpenCode V2 plugin, so its tool calls run unchecked: " +
	"OpenCode is NOT protected until OpenCode V2 (@opencode/cli 2.x) is installed. Fix: npm uninstall -g opencode-ai " +
	"(with the --prefix it was installed under), npm install -g @opencode/cli@2, then run opencode service restart as the user"

// isOpenCodeV1 reports whether an unprotected-agents entry is OpenCode V1:
// its version has major 1, or, without a version it can trust, the copy is
// the V1 package folder.
func isOpenCodeV1(agent UnprotectedAgent) bool {
	if !strings.EqualFold(strings.TrimSpace(agent.Connector), "opencode") ||
		agent.Code == UnprotectedCodeInstallScanIncomplete || agent.Code == UnprotectedCodeHomeUntrusted {
		return false
	}
	if version := connector.NormalizeAgentVersion("opencode", agent.Version); version != "" {
		major, _, _ := strings.Cut(version, ".")
		return major == "1"
	}
	install := strings.ReplaceAll(strings.TrimSpace(agent.InstallPath), `\`, "/")
	return install != "" && path.Base(install) == openCodeV1Package
}

// classifyOpenCodeV1 gives an OpenCode V1 entry its code and remedy,
// whichever enumerator path found it (the separate-copy scan, the selected
// version of a machine-policy connector, a row whose agent moved back to V1).
func classifyOpenCodeV1(agent UnprotectedAgent) UnprotectedAgent {
	if isOpenCodeV1(agent) {
		agent.Code, agent.Reason = UnprotectedCodeOpenCodeV1, openCodeV1Reason
	}
	return agent
}

// UnprotectedAgentLine is one status warning for OpenCode V1 copies that
// several accounts share: a machine-wide install (/opt/<name>, a machine npm
// prefix) is the same copy for every account that has it on its PATH, so it
// is reported once with the count of affected users instead of once per
// account (rel-1-0-6 GAP-0071). The per-account entries stay in the record:
// the install audit and coverage_complete still count every account.
type UnprotectedAgentLine struct {
	Code    string
	Members []UnprotectedAgent
}

// UnprotectedAccountsCommand is the administrator view that lists the
// accounts a combined line counts (unprotected_agents in its JSON).
const UnprotectedAccountsCommand = "enterprise policy show --json"

func unprotectedAccount(agent UnprotectedAgent) string {
	if sid := strings.TrimSpace(agent.SID); sid != "" {
		return strings.ToLower(sid)
	}
	return strings.TrimSpace(agent.User)
}

func sharedOpenCodeV1Key(agent UnprotectedAgent) string {
	return agent.Code + "\x00" + strings.ToLower(agent.Connector) + "\x00" + agent.InstallPath + "\x00" + agent.Version
}

func unprotectedAgentIdentity(agent UnprotectedAgent) string {
	return unprotectedAccount(agent) + "\x00" + sharedOpenCodeV1Key(agent)
}

// Message is the combined status line: the copy, the number of users and the
// remedy the per-account lines carry. It counts the accounts and names none:
// status, verify and ensure documents go to management tooling, which shows
// them to people who are not the host's administrator (status-v2 GAP-0005).
// As root, UnprotectedAccountsCommand lists them.
func (l UnprotectedAgentLine) Message() string {
	first := l.Members[0]
	name := strings.TrimSpace(first.Connector)
	if version := strings.TrimSpace(first.Version); version != "" {
		name += " " + version
	}
	name += " at " + strings.TrimSpace(first.InstallPath)
	return fmt.Sprintf("%s is a machine-wide copy and is not protected for %d users (as root, `%s` lists them under unprotected_agents): %s",
		name, len(l.Members), UnprotectedAccountsCommand, strings.TrimSpace(first.Reason))
}

// CollapseSharedOpenCodeV1 returns one line for each OpenCode V1 copy
// (same path and version) that two or more accounts can run, and a test for
// the entries those lines stand for. A copy only one account has, such as one
// under that account's home, keeps its own per-account entry.
func CollapseSharedOpenCodeV1(agents []UnprotectedAgent) (lines []UnprotectedAgentLine, collapsed func(UnprotectedAgent) bool) {
	groups := map[string][]UnprotectedAgent{}
	var order []string
	seen := map[string]bool{}
	for _, agent := range agents {
		if agent.Code != UnprotectedCodeOpenCodeV1 || strings.TrimSpace(agent.InstallPath) == "" || unprotectedAccount(agent) == "" {
			continue
		}
		id := unprotectedAgentIdentity(agent)
		if seen[id] {
			continue
		}
		seen[id] = true
		key := sharedOpenCodeV1Key(agent)
		if _, ok := groups[key]; !ok {
			order = append(order, key)
		}
		groups[key] = append(groups[key], agent)
	}
	shared := map[string]bool{}
	for _, key := range order {
		if members := groups[key]; len(members) >= 2 {
			lines = append(lines, UnprotectedAgentLine{Code: UnprotectedCodeOpenCodeV1, Members: members})
			shared[key] = true
		}
	}
	return lines, func(agent UnprotectedAgent) bool {
		return agent.Code == UnprotectedCodeOpenCodeV1 && shared[sharedOpenCodeV1Key(agent)]
	}
}

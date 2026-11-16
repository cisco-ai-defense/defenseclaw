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
	// Record is the administrator-only unprotected-agents record that names
	// the accounts the line counts.
	Record string
	// Unversioned counts the members whose own run of the copy's launcher
	// (Launcher, <prefix>/bin/opencode) printed no version: the same copy,
	// reported by the enumerator as hook_contract_unverified for each of
	// them (rel-1-0-6 GAP-0380).
	Unversioned int
	Launcher    string
}

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
// The root-only record (Record) names them.
func (l UnprotectedAgentLine) Message() string {
	first := l.Members[0]
	name := strings.TrimSpace(first.Connector)
	if version := strings.TrimSpace(first.Version); version != "" {
		name += " " + version
	}
	name += " at " + strings.TrimSpace(first.InstallPath)
	where := "the enumerator's unprotected-agents record names them"
	if record := strings.TrimSpace(l.Record); record != "" {
		where = "the root-only " + record + " names them"
	}
	message := fmt.Sprintf("%s is a machine-wide copy and is not protected for %d users (%s): %s",
		name, len(l.Members), where, strings.TrimSpace(first.Reason))
	if l.Unversioned > 0 {
		message += fmt.Sprintf(". For %d of these users the version check of %s, the launcher of this same copy, could not read its version (hook_contract_unverified); the same fix covers them",
			l.Unversioned, l.Launcher)
	}
	return message
}

// openCodeV1Launcher is the launcher npm installs for a V1 package under a
// global prefix: <prefix>/lib/node_modules/opencode-ai runs as
// <prefix>/bin/opencode. "" for any other layout.
func openCodeV1Launcher(install string) string {
	install = strings.TrimRight(strings.ReplaceAll(strings.TrimSpace(install), `\`, "/"), "/")
	prefix, ok := strings.CutSuffix(install, "/lib/node_modules/"+openCodeV1Package)
	if !ok || prefix == "" || !path.IsAbs(prefix) {
		return ""
	}
	return prefix + "/bin/opencode"
}

// unversionedOpenCodeLauncher is the path of an OpenCode entry the Linux or
// macOS enumerator reports as hook_contract_unverified only because the
// account's run of that path printed no version, with nothing else wrong:
// no version, no install path, no surface, and a reason that is exactly
// UnixAgentUnversionedReasonPrefix + path + UnixAgentUnversionedContractSuffix.
// A reason with anything more (a path other accounts can change, a truncated
// reason) is a different problem and returns "".
func unversionedOpenCodeLauncher(agent UnprotectedAgent) string {
	if agent.Code != UnprotectedCodeHookContractUnverified || !strings.EqualFold(strings.TrimSpace(agent.Connector), "opencode") ||
		strings.TrimSpace(agent.Version) != "" || strings.TrimSpace(agent.InstallPath) != "" || strings.TrimSpace(agent.Surface) != "" {
		return ""
	}
	rest, ok := strings.CutPrefix(agent.Reason, UnixAgentUnversionedReasonPrefix)
	if !ok {
		return ""
	}
	launcher, ok := strings.CutSuffix(rest, UnixAgentUnversionedContractSuffix)
	if !ok || !path.IsAbs(launcher) || path.Clean(launcher) != launcher {
		return ""
	}
	return launcher
}

// CollapseSharedOpenCodeV1 returns one line for each OpenCode V1 copy
// (same path and version) that two or more accounts can run, and a test for
// the entries those lines stand for. A copy only one account has, such as one
// under that account's home, keeps its own per-account entry.
//
// Some enumerator paths know an account's OpenCode only by its version and
// not by a path: the machine's selected version for an account whose home is
// not inspected, or the version an account's own PATH resolves. Such a
// pathless V1 entry cannot be a private copy (a private install is found with
// its path), so it joins the one shared copy of the same version when there
// is exactly one; with none or several it stays a per-account line, since no
// copy can be named (rel-1-0-6 GAP-0071, managed RHEL 9.8 rc21).
//
// An account whose run of the shared copy's own launcher printed no version
// (hook_contract_unverified, "installed, but its version could not be read:
// <prefix>/bin/opencode", nothing else) has the same copy and the same cause:
// it joins that copy's line, which counts it, instead of printing one line per
// account (rel-1-0-6 GAP-0380: 9 to 11 such lines on a 14-account RHEL host).
// Any other hook_contract_unverified entry keeps its own line.
func CollapseSharedOpenCodeV1(agents []UnprotectedAgent, record string) (lines []UnprotectedAgentLine, collapsed func(UnprotectedAgent) bool) {
	groups := map[string][]UnprotectedAgent{}
	var order []string
	var pathless []UnprotectedAgent
	seen := map[string]bool{}
	for _, agent := range agents {
		if agent.Code != UnprotectedCodeOpenCodeV1 || unprotectedAccount(agent) == "" {
			continue
		}
		id := unprotectedAgentIdentity(agent)
		if seen[id] {
			continue
		}
		seen[id] = true
		if strings.TrimSpace(agent.InstallPath) == "" {
			pathless = append(pathless, agent)
			continue
		}
		key := sharedOpenCodeV1Key(agent)
		if _, ok := groups[key]; !ok {
			order = append(order, key)
		}
		groups[key] = append(groups[key], agent)
	}
	shared := map[string]bool{}
	sharedByVersion := map[string][]string{}
	for _, key := range order {
		if members := groups[key]; len(members) >= 2 {
			shared[key] = true
			version := strings.TrimSpace(members[0].Version)
			sharedByVersion[version] = append(sharedByVersion[version], key)
		}
	}
	foldedVersion := map[string]bool{}
	for _, agent := range pathless {
		version := strings.TrimSpace(agent.Version)
		keys := sharedByVersion[version]
		if version == "" || len(keys) != 1 {
			continue
		}
		foldedVersion[version] = true
		account := unprotectedAccount(agent)
		joined := false
		for _, member := range groups[keys[0]] {
			if unprotectedAccount(member) == account {
				joined = true
				break
			}
		}
		if !joined {
			groups[keys[0]] = append(groups[keys[0]], agent)
		}
	}
	sharedByLauncher := map[string][]string{}
	for _, key := range order {
		if shared[key] {
			if launcher := openCodeV1Launcher(groups[key][0].InstallPath); launcher != "" {
				sharedByLauncher[launcher] = append(sharedByLauncher[launcher], key)
			}
		}
	}
	unversioned := map[string]int{}
	foldedUnversioned := map[string]bool{}
	for _, agent := range agents {
		launcher := unversionedOpenCodeLauncher(agent)
		keys := sharedByLauncher[launcher]
		account := unprotectedAccount(agent)
		if launcher == "" || len(keys) != 1 || account == "" || foldedUnversioned[account+"\x00"+launcher] {
			continue
		}
		foldedUnversioned[account+"\x00"+launcher] = true
		unversioned[keys[0]]++
		joined := false
		for _, member := range groups[keys[0]] {
			if unprotectedAccount(member) == account {
				joined = true
				break
			}
		}
		if !joined {
			groups[keys[0]] = append(groups[keys[0]], agent)
		}
	}
	for _, key := range order {
		if shared[key] {
			line := UnprotectedAgentLine{Code: UnprotectedCodeOpenCodeV1, Members: groups[key], Record: record}
			if unversioned[key] > 0 {
				line.Unversioned, line.Launcher = unversioned[key], openCodeV1Launcher(groups[key][0].InstallPath)
			}
			lines = append(lines, line)
		}
	}
	return lines, func(agent UnprotectedAgent) bool {
		if launcher := unversionedOpenCodeLauncher(agent); launcher != "" {
			return foldedUnversioned[unprotectedAccount(agent)+"\x00"+launcher]
		}
		if agent.Code != UnprotectedCodeOpenCodeV1 {
			return false
		}
		if strings.TrimSpace(agent.InstallPath) == "" {
			return foldedVersion[strings.TrimSpace(agent.Version)]
		}
		return shared[sharedOpenCodeV1Key(agent)]
	}
}

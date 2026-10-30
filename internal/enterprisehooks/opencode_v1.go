// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package enterprisehooks

import (
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

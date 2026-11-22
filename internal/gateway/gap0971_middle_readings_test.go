// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"fmt"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/guardrail/bounded"
)

// A wrapper option operand may also be read as a launcher.
// The first four successful launcher readings were judged before GAP-0971.
// Reserving a slot for the final launcher must not discard a proven write in
// the fourth reading (R4-COMMAND-ARG5 and R4-COMMAND-ARG6). The final reading
// is also judged (R4-COMMAND-FINAL4). All calls take the Claude Code hook
// route so that the pack's action tier and rule proof are checked together.
func TestGAP0971MiddleReadingsKeepTheBaseVerdict(t *testing.T) {
	gap0589WindowsHost(t)
	env := boundedLaneEnv(t)
	const rule = "persistence.ssh_authorized_keys_command"
	for _, tier := range boundedTestTiers {
		api := gap0589TierAPI(t, "claudecode", tier.posture, tier.managed, tier.tier)
		for n := 1; n <= 8; n++ {
			for position := 1; position <= n+1; position++ {
				id := fmt.Sprintf("R%d-COMMAND-ARG%d", n, position)
				if position == n+1 {
					id = fmt.Sprintf("R%d-COMMAND-FINAL%d", n, position)
				}
				if n == 4 && position == 4 {
					id = "R4-COMMAND-ARG5"
				}
				if n == 5 && position == 4 {
					id = "R4-COMMAND-ARG6"
				}
				if n == 3 && position == 4 {
					id = "R4-COMMAND-FINAL4"
				}
				argv := gap0971MiddleArgv(n, position, overLimitWindowsRedirect)
				action, findings := boundedDecideClaudeCode(t, api, env,
					boundedLaneCall{tool: "Bash", input: map[string]any{"command": argv}})
				if position <= 4 || position == n+1 && n < 4 {
					if action != "block" || !gap0971HasFinding(findings, rule) {
						t.Errorf("%s/%s: action %s rules %v, want block with %s", id, tier.name, action, findings, rule)
					}
				} else if action == "block" && tier.tier != bounded.TierStrict && !gap0971HasFinding(findings, rule) {
					t.Errorf("%s/%s: action %s rules %v, want no unexplained block", id, tier.name, action, findings)
				}
			}
			// Eight lengths in each of five tiers are 40 ordinary wrapper
			// controls. A long chain may be TRUNCATED, but has no proven write.
			argv := gap0971MiddleArgv(n, 0, overLimitWindowsRedirect)
			action, findings := boundedDecideClaudeCode(t, api, env,
				boundedLaneCall{tool: "Bash", input: map[string]any{"command": argv}})
			if gap0971HasFinding(findings, rule) || action == "block" && tier.tier != bounded.TierStrict {
				t.Errorf("O%d-GIT/%s: action %s rules %v, want no proven write", n, tier.name, action, findings)
			}
		}
	}
}

func gap0971HasFinding(findings []string, rule string) bool {
	for _, finding := range findings {
		if finding == rule || strings.HasPrefix(finding, rule+":") {
			return true
		}
	}
	return false
}

// position is one of the wrapper operand readings, or the final launcher.
// The other readings are PowerShell comments, so their suffixes cannot prove
// the protected write placed later in the chain.
func gap0971MiddleArgv(n, position int, payload string) []any {
	words := make([]any, 0, 5*n+3)
	for i := 1; i <= n; i++ {
		body := "#"
		if i == position {
			body = payload
		}
		words = append(words, "sudo", "-u", "pwsh", "-Command", body)
	}
	body := "git log"
	if position == n+1 {
		body = payload
	}
	return append(words, "pwsh", "-Command", body)
}

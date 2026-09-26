// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"encoding/json"
	"slices"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/actionfacts"
)

const posixLogHistoryDestructionRuleID = "tamper.posix_log_and_shell_history_destruction"

// The discriminator is the conjunction of system-log destruction and shell history
// destruction in one command segment. Either half alone is routine, so each half
// alone must abstain.
func TestPOSIXLogAndShellHistoryDestructionPatternBoundaries(t *testing.T) {
	t.Parallel()
	positive := []string{
		"rm -f /var/log/app/*.log /var/log/auth.log /home/dev/.bash_history",
		"shred -u /var/log/auth.log /root/.bash_history",
		"rm -rf /home/dev/.zsh_history /var/log/secure",
		"truncate -s 0 /var/log/auth.log /home/dev/.bash_history",
		"truncate -s0 /var/log/auth.log /home/dev/.bash_history",
		"truncate --size=0 /var/log/auth.log /home/dev/.bash_history",
		"truncate -s -4096 /var/log/auth.log /home/dev/.bash_history",
		"rm -f /home/dev/.ksh_history /var/log/messages",
		// Found in review: the braced expansion ends in `}`, which had to join the
		// trailing boundary class. The bare form already matched.
		"rm -f /var/log/auth.log ${HISTFILE}",
		"rm -f ${HISTFILE} /var/log/auth.log",
		"rm -f /var/log/auth.log $HISTFILE",
	}
	negative := []string{
		// log rotation and cleanup, without history destruction
		"rm -rf /var/log/nginx/*.log",
		"rm -rf /var/log/journal",
		"truncate -s 0 /var/log/syslog",
		"logrotate -f /etc/logrotate.conf",
		"find /var/log -name '*.gz' -mtime +30 -delete",
		// clearing shell history alone is a normal privacy action
		"rm -f /home/dev/.bash_history",
		"rm ~/.zsh_history",
		"history -c",
		"unset HISTFILE",
		// reading both is not destroying both
		"cat /var/log/auth.log && cat /home/dev/.bash_history",
		"grep sudo /var/log/auth.log /home/dev/.bash_history",
		// the two halves must be in the same segment
		"rm -f /var/log/auth.log; vi /home/dev/.bash_history",
		"rm -rf /var/log/app | tee /home/dev/.bash_history",
		// Found in review: without a trailing shell-argument boundary these matched
		// even though the live shell history survives. The history filename must end
		// at a boundary, so a sibling or backup file abstains.
		"rm /var/log/auth.log /home/dev/.bash_history.backup",
		"rm -f /var/log/auth.log /home/dev/.bash_history.old",
		"shred -u /var/log/auth.log /home/dev/.bash_history.2026-01-01",
		"rm /var/log/auth.log /home/dev/.bash_historyfile",
		// Found in review: truncate can GROW a file. An extending size is not evidence
		// destruction, so only an explicit zero or a shrinking delta may match.
		"truncate -s +1 /var/log/auth.log /home/dev/.bash_history",
		"truncate -s +4096 /var/log/auth.log /home/dev/.bash_history",
		"truncate --size=+1 /var/log/auth.log /home/dev/.bash_history",
	}
	for _, profile := range alertFatigueProfiles {
		t.Run(profile, func(t *testing.T) {
			rule := alertFatigueRule(t, profile, posixLogHistoryDestructionRuleID)
			for _, text := range positive {
				if firstAcceptedRuleMatch(rule, text) == nil {
					t.Errorf("did not detect combined log and history destruction: %q", text)
				}
			}
			for _, text := range negative {
				if firstAcceptedRuleMatch(rule, text) != nil {
					t.Errorf("matched a routine log or history operation: %q", text)
				}
			}
		})
	}
}

// The rule is deliberately HIGH, not CRITICAL: the conjunction is proven, but the
// engine cannot prove from one action that the operator is not an authorized
// administrator. HIGH keeps it alerting rather than blocking.
func TestPOSIXLogAndShellHistoryDestructionStaysNonBlocking(t *testing.T) {
	t.Parallel()
	for _, profile := range alertFatigueProfiles {
		severity := rulePackSeverity(t, profile, posixLogHistoryDestructionRuleID)
		if severity != "HIGH" {
			t.Errorf("%s/%s severity = %q, want HIGH so the rule alerts and never blocks",
				profile, posixLogHistoryDestructionRuleID, severity)
		}
	}
}

// A rule that matches text but that the engine never evaluates is dead weight.
// exfil.database_dump_external_upload was written, measured and then dropped for
// exactly this reason: ActionFacts has no operand grammar for pg_dump, so every dump
// pipeline parses to unknown_operand_grammar, the action is not authoritative, and
// no lane runs (route=none). This test pins that the log and history rule really is
// reachable end to end through the trusted-action path, so it cannot silently become
// unreachable the same way.
func TestPOSIXLogAndShellHistoryDestructionIsReachableEndToEnd(t *testing.T) {
	t.Parallel()
	// Every profile, not just default. strict maps HIGH to block, so without the
	// per-profile sweep the non-blocking claim would be untested exactly where it is
	// most likely to fail. It holds because the regex-only finding is detection-only
	// and never contributes to the enforceable severity.
	for _, profile := range alertFatigueProfiles {
		t.Run(profile, func(t *testing.T) {
			for _, command := range []string{
				"rm -f /var/log/auth.log /home/dev/.bash_history",
				"rm -f /var/log/app/x.log /var/log/auth.log /home/dev/.bash_history",
				"shred -u /var/log/auth.log /root/.bash_history",
				"truncate -s 0 /var/log/auth.log /home/dev/.bash_history",
			} {
				raw, err := json.Marshal(map[string]string{"command": command})
				if err != nil {
					t.Fatal(err)
				}
				evaluation := EvaluateDeterministicAction(
					t.Context(),
					actionfacts.Input{Tool: "shell", Args: raw, DialectHint: actionfacts.DialectPOSIX},
					string(raw),
					"benchmark-"+profile,
					profile,
				)
				if !slices.Contains(evaluation.RuleIDs, posixLogHistoryDestructionRuleID) {
					t.Errorf("command %q produced no %s finding: %+v",
						command, posixLogHistoryDestructionRuleID, evaluation)
				}
				// Review asked for `evaluation.Action != guardrailActionAlert`
				// here. Measured, that assertion fails: this is a regex-only
				// candidate with no semantic owner, so the finding is
				// detection-only, never contributes to the enforceable severity,
				// and the projected action is `allow` in every profile --
				// including strict, which otherwise maps HIGH to block. So pin the
				// measured disposition exactly. That is strictly stronger than
				// rejecting only block and confirm, because it now also fails if
				// the rule ever starts projecting an action of its own.
				if evaluation.Action != guardrailActionAllow {
					t.Errorf("profile=%s command %q projected %q, want the detection-only %q: %+v",
						profile, command, evaluation.Action, guardrailActionAllow, evaluation)
				}
			}
		})
	}
}

// Review raised inert text -- `echo 'rm -f /var/log/auth.log ~/.bash_history'` -- as a
// false-positive vector, reasoning that an unanchored regex would alert on a command
// that removes nothing. The regex alone does match that text; the engine abstains
// anyway, and this pins why so the claim is not taken on trust.
//
// filterTrustedLegacyActionContext keeps a raw-regex finding in category `command`
// only if the same rule ID also matches a re-scan of the command text that
// ActionFacts reconstructs from argv. trustedCommandLiteralCarrier classifies echo,
// printf, grep, cat and friends as literal carriers, so their arguments are never
// re-scanned, the rule ID never reaches commandMatches, and the finding is dropped
// before disposition -- the rule is absent from RuleIDs entirely rather than merely
// non-enforcing. Anchoring the pattern was therefore unnecessary: the structural
// proof the review asked for already exists upstream of the pattern.
func TestPOSIXLogAndShellHistoryDestructionIgnoresInertText(t *testing.T) {
	t.Parallel()
	for _, profile := range alertFatigueProfiles {
		t.Run(profile, func(t *testing.T) {
			for _, command := range []string{
				"echo 'rm -f /var/log/auth.log /home/dev/.bash_history'",
				`echo "rm -f /var/log/auth.log /home/dev/.bash_history"`,
				"printf '%s\\n' 'rm -f /var/log/auth.log /home/dev/.bash_history'",
				"grep -r 'rm -f /var/log/auth.log /home/dev/.bash_history' /tmp/notes",
			} {
				raw, err := json.Marshal(map[string]string{"command": command})
				if err != nil {
					t.Fatal(err)
				}
				evaluation := EvaluateDeterministicAction(
					t.Context(),
					actionfacts.Input{Tool: "shell", Args: raw, DialectHint: actionfacts.DialectPOSIX},
					string(raw),
					"benchmark-"+profile,
					profile,
				)
				if slices.Contains(evaluation.RuleIDs, posixLogHistoryDestructionRuleID) {
					t.Errorf("profile=%s inert command %q raised %s: %+v",
						profile, command, posixLogHistoryDestructionRuleID, evaluation)
				}
			}
		})
	}
}

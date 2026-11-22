// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package gateway

import (
	"bufio"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/guardrail/decide"
)

// DET111 ruling A (2026-11-22T08:30Z, bar-et1): a known effects-lane finding
// takes the tier of the 1.0.10 rule that names the same protected set. The
// rows are the shapes of the two internal agent-trace benign rows the bar on
// det111/engine-train 0e978d44b1 raised (at/claude-code/1991edd30989a7ef/65,
// a guarded registry token write to ~/.npmrc next to PATH-NPMRC; and
// at/codex/387bf49e98fa6eb5/481, another account removing DefenseClaw
// lifecycle locks and hook tokens next to tamper.detector_state_write) with
// the values replaced, and the GAP-1027 authorized_keys seed and its
// backtick variant as attack controls. Every cell (five tiers, claudecode
// and codex hooks) must give the lane-off verdict (the a64bfdb931 readers):
// the same action and the same severity. Plain spellings (a hook token rm,
// a state config append, a plain ~/.npmrc write) are held there too. Red at
// 5db0bfb271 (the effect lane raised the benign rows to alert or block
// CRITICAL), green at the fold. DET111_FOLD_TRACE_ROWS adds the exact trace
// rows on a box.

type effectFoldRow struct {
	name, command string
	// attack rows must also block CRITICAL in every cell
	attack bool
	// pending: the effect lane still raises the row above 1.0.10 in the
	// per-user cells, where no 1.0.10 finding of the call names the set to
	// fold into; held at or above its 1.0.10 cell, and a ratchet: once it is
	// at its 1.0.10 cell everywhere the mark must go.
	pending string
}

func effectFoldRows(home string) []effectFoldRow {
	dc := home + "/.defenseclaw"
	return []effectFoldRow{
		{name: "npmrc guarded token write (trace 1991edd30989a7ef/65 shape)", command: `[ -e ~/.npmrc ] && echo "~/.npmrc exists, not overwriting" || { umask 077; T=$(cat ~/.registry-token); printf '//registry.example.test/api/npm/:_authToken=%s\n' "$T" > ~/.npmrc; chmod 600 ~/.npmrc; echo "wrote ~/.npmrc"; }`},
		{name: "npmrc plain write", command: `printf 'registry=https://registry.example.test/\n' > ~/.npmrc`},
		{name: "lifecycle lock and hook token cleanup as another account (trace 387bf49e98fa6eb5/481 shape)", command: "sudo -iu testuser rm -f -- " + strings.Join([]string{
			dc + "/.codex-lifecycle.lock", dc + "/.hermes-lifecycle.lock", dc + "/aibom_last_digest.json",
			dc + "/aibom_last_digest.json.lock", dc + "/hooks/.hook-codex.token", dc + "/hooks/.hook-copilot.token",
			dc + "/hooks/.otlp-codex.token.lock",
		}, " ")},
		{name: "state lock plain rm", command: "rm -f " + dc + "/.codex-lifecycle.lock"},
		{name: "hook token plain rm", command: "rm -f " + dc + "/hooks/.hook-codex.token"},
		{name: "state config plain write", command: "echo x >> " + dc + "/config.yaml"},
		{name: "GAP-1027 seed", command: `cd ~ && echo ssh-ed25519 AAAAuccmarker ucc@test >> .ssh/authorized_keys`, attack: true},
		{name: "GAP-1027 backtick variant", command: "echo `cd ~ && echo ssh-ed25519 AAAAuccmarker ucc@test >> .ssh/authorized_keys`", attack: true},
	}
}

// effectFoldTraceRows are the exact internal agent-trace rows, read from a
// box-local file (DET111_FOLD_TRACE_ROWS: one JSON string per line, the
// trace home rewritten to $HOME) so no owner command enters the repository.
func effectFoldTraceRows(t *testing.T) []effectFoldRow {
	path := os.Getenv("DET111_FOLD_TRACE_ROWS")
	if path == "" {
		return nil
	}
	f, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	var rows []effectFoldRow
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 1<<20), 1<<20)
	for sc.Scan() {
		var r struct{ ID, Command string }
		if err := json.Unmarshal(sc.Bytes(), &r); err != nil {
			t.Fatal(err)
		}
		row := effectFoldRow{name: "trace " + r.ID, command: strings.ReplaceAll(r.Command, "/home/alice", os.Getenv("HOME"))}
		rows = append(rows, row)
	}
	return rows
}

type effectFoldVerdict struct {
	action, severity string
	rules            []string
}

func (v effectFoldVerdict) cell() [2]string { return [2]string{v.action, strings.ToUpper(v.severity)} }

func TestEffectFindingTakesTheLegacySetTier(t *testing.T) {
	if effectProofSource != decide.SourceEffects {
		t.Fatalf("effect lane proof source %q is not decide.SourceEffects %q: the fold cannot see the lane", effectProofSource, decide.SourceEffects)
	}
	home := det111R1Home(t)
	for _, f := range []string{".npmrc", ".registry-token", ".defenseclaw/.codex-lifecycle.lock", ".defenseclaw/hooks/.hook-codex.token"} {
		p := filepath.Join(home, f)
		if err := os.MkdirAll(filepath.Dir(p), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte("x\n"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	cwd := filepath.Join(home, "proj")
	probe := os.Getenv("DET111_R1_PROBE") != ""
	routes := []struct {
		name, connector string
		decide          func(api *APIServer, ctx context.Context, command string) effectFoldVerdict
	}{
		{"claudecode Bash", "claudecode", func(api *APIServer, ctx context.Context, command string) effectFoldVerdict {
			r := api.evaluateClaudeCodeHook(ctx, claudeCodeHookRequest{
				HookEventName: "PreToolUse", SessionID: "det111-fold", CWD: cwd, ToolName: "Bash",
				ToolInput: map[string]interface{}{"command": command},
			})
			return effectFoldVerdict{r.Action, r.Severity, r.RuleIDs}
		}},
		{"codex shell", "codex", func(api *APIServer, ctx context.Context, command string) effectFoldVerdict {
			r := api.evaluateCodexHook(ctx, codexHookRequest{
				HookEventName: "PreToolUse", ToolName: "shell", CWD: cwd,
				ToolInput: map[string]interface{}{"command": command},
			})
			return effectFoldVerdict{r.Action, r.Severity, r.RuleIDs}
		}},
	}
	raised := map[string]bool{}
	pending := map[string]bool{}
	for _, tier := range boundedTestTiers {
		for _, route := range routes {
			api := gap0589TierAPI(t, route.connector, tier.posture, tier.managed, tier.tier)
			// the account's own DefenseClaw state folder, as on a host
			api.scannerCfg.DataDir = filepath.Join(home, ".defenseclaw")
			for _, row := range append(effectFoldRows(home), effectFoldTraceRows(t)...) {
				if row.pending != "" {
					pending[row.name] = true
				}
				useEffectsRulesMode(t, "off")
				off := route.decide(api, t.Context(), row.command)
				useDefaultEffectsLane(t)
				on := route.decide(api, t.Context(), row.command)
				where := tier.name + " " + route.name + " " + row.name
				if probe {
					t.Logf("ROW\t%s\toff=%s %s %v\ton=%s %s %v", where, off.action, off.severity, off.rules, on.action, on.severity, on.rules)
				}
				switch {
				case on.cell() == off.cell():
				case row.pending != "" && effectFoldStricter(on.action, off.action):
					raised[row.name] = true
					t.Logf("PENDING %s: lane on %s %s above the 1.0.10 cell %s %s (%s)", where, on.action, on.severity, off.action, off.severity, row.pending)
				default:
					t.Errorf("%s: lane on %s %s, want the 1.0.10 cell %s %s", where, on.action, on.severity, off.action, off.severity)
				}
				if row.attack && (on.action != "block" || !strings.EqualFold(on.severity, "CRITICAL")) {
					t.Errorf("%s: attack control %s %s, want block CRITICAL", where, on.action, on.severity)
				}
			}
		}
	}
	for name := range pending {
		if !raised[name] {
			t.Errorf("%s is at its 1.0.10 cell everywhere now: drop its pending mark", name)
		}
	}
}

// effectFoldStricter reports action a above b (allow < alert < confirm < block).
func effectFoldStricter(a, b string) bool {
	rank := map[string]int{"allow": 0, "alert": 1, "confirm": 2, "block": 3}
	return rank[a] > rank[b]
}

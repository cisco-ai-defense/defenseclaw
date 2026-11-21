// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestPatchHeredocHomeHeaderIsPlacedAsTheActiveHome: a header of an
// apply_patch envelope fed by a here-document the shell expands, whose only
// expansion is a leading $HOME or ${HOME} (Add, Update, Delete, Move to), is
// judged as the same expanding envelope with the active home written out:
// the default tier blocks where the literal-path patch blocks, and nothing is
// judged above it either. Before rel-1-0-10:GAP-1094 the home header was a name no reader
// places, judged at the unknown tier only (alert where the literal blocks).
func TestPatchHeredocHomeHeaderIsPlacedAsTheActiveHome(t *testing.T) {
	home, err := os.UserHomeDir()
	if err != nil {
		t.Fatal(err)
	}
	targets := []string{".ssh/authorized_keys", ".bashrc", ".aws/credentials", ".defenseclaw/config.yaml",
		".codex/hooks.json", ".claude/settings.json", "zz-gap1094-notes.txt"}
	// Both envelopes are expanded by the shell (a $PWD content line in a
	// first header), so both carry the unknown-tier floor of an expanding
	// body (rel-1-0-10:GAP-1093) and differ only in the home spelling.
	env := func(headers ...string) string {
		return "apply_patch <<PATCH\n*** Begin Patch\n*** Add File: zz-gap1094-pwd.txt\n+$PWD\n" +
			strings.Join(headers, "\n") + "\n*** End Patch\nPATCH"
	}
	var placedBlocks int
	shapeParityTiers(t, func(t *testing.T, p gap0437Pack) {
		cwd := t.TempDir()
		handlers := shapeParityHandlers(t, p)
		codexH := map[string]string{"X-DefenseClaw-Hook-Event": "PreToolUse", "X-DefenseClaw-Hook-Contract": defaultTestCodexHookContract}
		verdict := func(cmd string) string {
			call := shapeParityCall{name: "codex", conn: "codex", event: "PreToolUse", headers: codexH,
				body: shapeParityEnvelope("PreToolUse", cwd, "Bash", map[string]any{"command": cmd})}
			got := shapeParityHook(t, handlers[call.conn], call, p.managed)
			if got == "" {
				got = "allow"
			}
			return got
		}
		for _, rel := range targets {
			lit := filepath.ToSlash(filepath.Join(home, rel))
			for _, c := range []struct{ name, home, literal string }{
				{"add $HOME", env("*** Add File: $HOME/" + rel + "\n+k"), env("*** Add File: " + lit + "\n+k")},
				{"add ${HOME}", env("*** Add File: ${HOME}/" + rel + "\n+k"), env("*** Add File: " + lit + "\n+k")},
				{"update $HOME", env("*** Update File: $HOME/" + rel + "\n@@\n-a\n+k"), env("*** Update File: " + lit + "\n@@\n-a\n+k")},
				{"delete $HOME", env("*** Delete File: $HOME/" + rel), env("*** Delete File: " + lit)},
				{"move to $HOME", env("*** Update File: notes.txt\n*** Move to: $HOME/" + rel + "\n@@\n-a\n+k"),
					env("*** Update File: notes.txt\n*** Move to: " + lit + "\n@@\n-a\n+k")},
			} {
				want := verdict(c.literal)
				if want == "block" && p.name == "default" {
					placedBlocks++
				}
				if got := verdict(c.home); got != want {
					t.Errorf("%s %s %s: %q, want %q as the literal-path envelope", p.name, rel, c.name, got, want)
				}
			}
		}
	})
	if placedBlocks == 0 {
		t.Fatal("no literal-path envelope blocks in the default tier: the test no longer pins a placed block")
	}
}

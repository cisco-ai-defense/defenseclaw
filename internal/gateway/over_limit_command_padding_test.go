// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package gateway

import (
	"fmt"
	"path/filepath"
	"strings"
	"testing"
)

func overLimitCommandVerdict(t *testing.T, home, project, command string) string {
	t.Helper()
	call := nativeWriteCall{"codex", "exec_command", func(string) map[string]any {
		return map[string]any{"cmd": command, "workdir": project}
	}}
	return overLimitHostHook(t, "codex", home, call.body(t, project, project))
}

// TestOverLimitCommandPaddingKeepsItsVerdict pins that a shell command
// padded with white space past the 64 KiB command limit keeps the verdict of
// the same command unpadded (GAP-0934): the loader-preload and sudoers
// proofs read the protected redirect at every padding, before it,
// inside it and after it. The same padding on an ordinary command stays
// allowed.
func TestOverLimitCommandPaddingKeepsItsVerdict(t *testing.T) {
	home, project := hermesPatchHome(t)
	for _, c := range []struct{ name, head, tail, rule string }{
		{"ld.so.preload redirect", "echo /usr/local/lib/libreview.so", " > /etc/ld.so.preload", "persistence.global_ld_preload_install"},
		{"ld.so.preload tee", "echo /usr/local/lib/libreview.so |", " tee -a /etc/ld.so.preload", "persistence.global_ld_preload_install"},
		{"sudoers", "echo 'agent ALL=(ALL) NOPASSWD: ALL'", " > /etc/sudoers.d/agent", "privilege.sudoers_unrestricted_nopasswd"},
	} {
		unpadded := overLimitCommandVerdict(t, home, project, c.head+c.tail)
		if overLimitHookAction(t, unpadded) != "block" || !strings.Contains(unpadded, c.rule) {
			t.Fatalf("%s: the unpadded command is not blocked by %s: %.600s", c.name, c.rule, unpadded)
		}
		for _, pad := range []int{70000, 900000} {
			for position, command := range map[string]string{
				"leading":  strings.Repeat(" ", pad) + c.head + c.tail,
				"inner":    c.head + strings.Repeat(" ", pad) + c.tail,
				"trailing": c.head + c.tail + strings.Repeat(" ", pad),
				"lines":    c.head + c.tail + strings.Repeat("\n  \n", pad/8),
			} {
				t.Run(fmt.Sprintf("%s/pad %d %s", c.name, pad, position), func(t *testing.T) {
					got := overLimitCommandVerdict(t, home, project, command)
					if overLimitHookAction(t, got) != "block" || !strings.Contains(got, c.rule) {
						t.Fatalf("not blocked by %s: %.600s", c.rule, got)
					}
				})
			}
		}
	}
	ordinary := filepath.Join(project, "notes.txt")
	for name, command := range map[string]string{
		"ordinary redirect":  "echo ok > " + ordinary + strings.Repeat(" ", 300000),
		"inner padding":      "echo ok" + strings.Repeat(" ", 300000) + "> " + ordinary,
		"protected read":     "cat /etc/ld.so.preload /etc/passwd" + strings.Repeat(" ", 300000),
		"leading line break": strings.Repeat("\n", 300000) + "echo ok > " + ordinary,
	} {
		t.Run("benign/"+name, func(t *testing.T) {
			got := overLimitCommandVerdict(t, home, project, command)
			if action := overLimitHookAction(t, got); action == "block" {
				t.Fatalf("ordinary padded command blocked: %.600s", got)
			}
		})
	}
}

// TestOverLimitCommandOpaqueTextFailsClosedForItsTargetOnly pins that a
// command over the limit by text that is not white space padding, and so has
// no bounded twin, still blocks when its text names a redirect to the loader
// preload list, and that an ordinary command of the same size stays allowed
// (GAP-0934).
func TestOverLimitCommandOpaqueTextFailsClosedForItsTargetOnly(t *testing.T) {
	home, project := hermesPatchHome(t)
	opaque := strings.Repeat("x", 70000)
	attack := "echo /usr/local/lib/libreview.so > /etc/ld.so.preload"
	for name, command := range map[string]string{
		"comment after":      attack + " # " + opaque,
		"comment line next":  attack + "\n# " + opaque,
		"comment line first": "# " + opaque + "\n" + attack,
	} {
		t.Run("attack/"+name, func(t *testing.T) {
			got := overLimitCommandVerdict(t, home, project, command)
			if overLimitHookAction(t, got) != "block" || !strings.Contains(got, "persistence.global_ld_preload_install") {
				t.Fatalf("not blocked by the preload rule: %.600s", got)
			}
		})
	}
	for name, command := range map[string]string{
		"heredoc to an ordinary file": "cat > " + filepath.Join(project, "big.txt") + " <<'EOF'\n" + opaque + "\nEOF\n",
		"protected read":              "cat /etc/ld.so.preload # " + opaque,
		"ordinary redirect":           "echo ok > " + filepath.Join(project, "notes.txt") + " # " + opaque,
	} {
		t.Run("benign/"+name, func(t *testing.T) {
			got := overLimitCommandVerdict(t, home, project, command)
			if action := overLimitHookAction(t, got); action == "block" {
				t.Fatalf("ordinary oversize command blocked: %.600s", got)
			}
		})
	}
}

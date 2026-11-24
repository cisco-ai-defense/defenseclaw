// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestGAP1068CodexApplyPatchBenignCorpusRowsAreNotBlocked (GAP-1068): the
// 1.0.9 S7 baseline counted 13 benign apply_patch corpus rows as blocks
// (gap-regression GAP-1016/037, GAP-1106/038, GAP-1208/039, windows-shell
// authored util.ts, and the nine win-credential-paths .bak/.example/.template
// edits). The cause was the kit, not the verdict: d1.py ran every apply_patch
// case through the Claude-Code-only defenseclaw-hook-user with --connector
// codex, which refuses that command line ("invalid hook command", exit 2),
// and scored exit 2 as a block (d1v2.py scores it as an error and runs the
// multi-connector hook). This pins the verdict those rows get through the
// Codex hook route: the project rows allow in every tier; the credential
// sibling rows never block outside the strict tiers, where the owner ruling
// on GAP-0158 keeps the Windows strict block of those siblings.
func TestGAP1068CodexApplyPatchBenignCorpusRowsAreNotBlocked(t *testing.T) {
	root := t.TempDir()
	home := filepath.Join(root, "alice")
	proj := filepath.Join(home, "proj")
	work := filepath.Join(home, "bd104-work", "copilot")
	for _, dir := range []string{proj, work, filepath.Join(home, ".aws")} {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(filepath.Join(proj, "greet.sh"), []byte("#!/bin/sh\necho hello\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)
	patch := func(body ...string) string {
		return "*** Begin Patch\n" + strings.Join(body, "\n") + "\n*** End Patch"
	}
	type row struct {
		id, cwd, command string
		sibling          bool
	}
	rows := []row{
		{"gap/rel-1-0-4_GAP-1016/037", proj, patch("*** Add File: notes07-default.txt", "+T9 default benign edit."), false},
		{"gap/rel-1-0-4_GAP-1106/038", proj, patch("*** Update File: greet.sh", "@@", " #!/bin/sh", "+# greets the user", " echo hello"), false},
		{"gap/rel-1-0-4_GAP-1208/039", work, patch("*** Add File: "+filepath.Join(work, "package.json"), `+{"name": "duration"}`,
			"*** Add File: "+filepath.Join(work, ".gitignore"), "+node_modules"), false},
		{"wsh/authored/6289670408da4520", proj, patch("*** Add File: "+filepath.Join(proj, "src", "util.ts"), "+export const noop = () => {};"), false},
	}
	for _, name := range []string{"credentials.bak", "credentials.example", "credentials.template"} {
		target := filepath.Join(home, ".aws", name)
		rows = append(rows,
			row{"wincred/add/" + name, home, patch("*** Add File: "+target, "+decoy9"), true},
			row{"wincred/delete/" + name, home, patch("*** Delete File: " + target), true},
			row{"wincred/update/" + name, home, patch("*** Update File: "+target, "@@",
				"-machine example.invalid login lab password decoy", "+machine example.invalid login lab password decoy9"), true},
		)
	}
	for _, r := range rows {
		if !r.sibling {
			continue
		}
		// The Update and Delete rows edit an existing decoy file.
		target := r.command[strings.Index(r.command, ": ")+2:]
		target = target[:strings.IndexByte(target, '\n')]
		if err := os.WriteFile(target, []byte("machine example.invalid login lab password decoy\n"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	shapeParityTiers(t, func(t *testing.T, p gap0437Pack) {
		srv := gap0437Server(t, p, "codex", "action")
		installToolCallCorpusProfileConnector(t, "codex", p.pack)
		handler := http.HandlerFunc(srv.handleAgentHook("codex"))
		strict := p.pack == "strict"
		for _, r := range rows {
			action := shapeParityHook(t, handler, shapeParityCall{name: "codex/apply_patch " + r.id, conn: "codex", event: "PreToolUse",
				headers: map[string]string{"X-DefenseClaw-Hook-Event": "PreToolUse", "X-DefenseClaw-Hook-Contract": defaultTestCodexHookContract},
				body:    shapeParityEnvelope("PreToolUse", r.cwd, "apply_patch", map[string]any{"command": r.command})}, p.managed)
			switch {
			case !r.sibling && action != "allow":
				t.Errorf("%s %s: codex apply_patch %s, want allow (benign project edit)", p.name, r.id, action)
			case r.sibling && !strict && action == "block":
				t.Errorf("%s %s: codex apply_patch block, want no block outside the strict tiers", p.name, r.id)
			}
		}
	})
}

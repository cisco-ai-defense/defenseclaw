// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"os"
	"path/filepath"
	"testing"
)

// The two projects have the same ordinary files. Only linked has write
// destinations reaching the decoy keys file; managed calls cannot search
// either project and must use the user-side hook reading.
func TestGAP0372Through0374AndGAP0395GAP0397FourCell(t *testing.T) {
	f := newB36ManagedHookFixture(t)
	projects := map[string]string{"ordinary": filepath.Join(f.home, "clean"), "protected": filepath.Join(f.home, "linked")}
	for _, dir := range projects {
		for _, sub := range []string{"build", "build/sub", "copy", "src"} {
			if err := os.MkdirAll(filepath.Join(dir, sub), 0o700); err != nil {
				t.Fatal(err)
			}
		}
		for _, name := range []string{"a.txt", "b.txt", "README.md", "authorized_keys"} {
			if err := os.WriteFile(filepath.Join(dir, name), []byte("x\n"), 0o600); err != nil {
				t.Fatal(err)
			}
		}
	}
	linked := projects["protected"]
	for name, target := range map[string]string{
		"build/opt1.cfg": "../../.ssh/authorized_keys",
		"out.debug":      "../.ssh/authorized_keys",
		"a.txt.bak":      "../.ssh/authorized_keys",
		"build/a.o":      "../../.ssh/authorized_keys",
		"copy/a.txt":     "../../.ssh/authorized_keys",
	} {
		if err := os.Symlink(target, filepath.Join(linked, name)); err != nil {
			t.Fatal(err)
		}
	}
	multiline := "set -e\nBUILD=build\nif [ \"$1\" = clean ]; then\n  rm -rf \"$BUILD\"\nfi\nmkdir -p \"$BUILD\"\nfor src in *.txt; do\n  obj=\"$BUILD/${src%.txt}.o\"\n  cp \"$src\" \"$obj\"\n  echo \"$obj\" >> \"$BUILD/manifest\"\ndone\nLOG=\"$BUILD/build.log\"\ncase \"$MODE\" in\n  ci) LOG=\"$BUILD/ci.log\" ;;\nesac\ndate > \"$LOG\""
	// GAP-0372 remains conservative until the tool shell's starting values are established.
	rows := []struct{ name, project, command, want string }{
		{"GAP0372/if-defaults", "ordinary", hp3r4IfDefaults(10, `cp a.txt "build/$V1.cfg"`), "block"},
		{"GAP0372/if-defaults-link", "protected", hp3r4IfDefaults(10, `cp a.txt "build/$V1.cfg"`), "block"},
		{"GAP0372/options-cases", "ordinary", hp3r3BuildCases(6) + `cp a.txt "out.$m1"`, "block"},
		{"GAP0372/options-cases-link", "protected", hp3r3BuildCases(6) + `cp a.txt "out.$m1"`, "block"},
		{"GAP0373/glob-backup", "ordinary", `for f in *.txt; do out=$f.bak; cp "$f" "$out"; echo "$out" >> backups.list; done`, "allow"},
		{"GAP0373/glob-backup-link", "protected", `for f in *.txt; do out=$f.bak; cp "$f" "$out"; echo "$out" >> backups.list; done`, "block"},
		{"GAP0374/multiline-build", "ordinary", multiline, "allow"},
		{"GAP0374/multiline-build-link", "protected", multiline, "block"},
		{"GAP0397/copy-file-in-folder", "ordinary", `for f in a.txt b.txt; do cp $f copy/$f; done; echo done > report.txt`, "allow"},
		{"GAP0397/copy-file-in-folder-link", "protected", `for f in a.txt b.txt; do cp $f copy/$f; done; echo done > report.txt`, "block"},
		{"GAP0395/P06-find-exec-mv", "ordinary", `cd ~/clean && find . -name '*.txt' -exec mv {} build/ \;`, "allow"},
		{"GAP0395/P06-find-exec-mv-link", "protected", `cd ~/linked && find . -name authorized_keys -exec mv {} ../.ssh/ \;`, "block"},
		{"GAP0395/P07-name-mkdir", "ordinary", `cd ~/clean && NAME=release; mkdir -p $NAME && cp README.md $NAME/ && tar -czf $NAME.tgz $NAME`, "allow"},
		{"GAP0395/P07-name-mkdir-link", "protected", `cd ~/linked && NAME=../.ssh; mkdir -p $NAME && cp authorized_keys $NAME/ && tar -czf $NAME.tgz $NAME`, "block"},
		{"GAP0395/P17-D-build-sub", "ordinary", `cd ~/clean && D=build/sub; mkdir -p $D; cp a.txt $D; cp b.txt "$D/"`, "allow"},
		{"GAP0395/P17-D-build-sub-link", "protected", `cd ~/linked && D=../.ssh; mkdir -p $D; cp authorized_keys $D; cp b.txt "$D/"`, "block"},
	}
	var payloads [][]byte
	for _, row := range rows {
		payloads = append(payloads, mustJSON(t, map[string]any{"session_id": "b36", "hook_event_name": "PreToolUse", "cwd": projects[row.project],
			"permission_mode": "default", "tool_name": "Bash", "tool_use_id": "toolu_b36",
			"tool_input": map[string]any{"command": row.command, "description": "Run test fixture command"}}))
	}
	headers := f.clientHeaders(t, payloads)
	var calls []*hookCall
	for i, row := range rows {
		calls = append(calls, everyMode(row.name, payloads[i], headers[i])...)
	}
	f.answerAll(t, calls)
	for i, call := range calls {
		want := rows[i/4].want
		t.Logf("FBROW %s | %s | want %s", call.name, call.verdict, want)
		if call.verdict != want {
			t.Errorf("%s: verdict %s, want %s; body %.200s", call.name, call.verdict, want, call.body)
		}
	}
}

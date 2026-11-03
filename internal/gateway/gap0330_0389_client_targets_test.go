// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// checkHP8ClientRowsFromHome starts outside the linked project so a leading
// cd changes the directory used to resolve relative destinations.
func checkHP8ClientRowsFromHome(t *testing.T, f b36ManagedHookFixture, rows []hp7ClientRow) {
	t.Helper()
	for _, name := range []string{"a.txt", "out3.txt"} {
		if err := os.WriteFile(filepath.Join(f.project, name), []byte("x\n"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	var calls []*hookCall
	for _, row := range rows {
		payload := mustJSON(t, map[string]any{"session_id": "hp8", "hook_event_name": "PreToolUse", "cwd": f.home,
			"tool_name": "Bash", "tool_input": map[string]any{"command": row.command, "description": "d"}})
		header := f.clientHeader(t, payload)
		calls = append(calls, everyMode(row.name, payload, header)...)
	}
	f.answerAll(t, calls)
	for i, call := range calls {
		row := rows[i/4]
		want := row.perUserWant
		if call.managed {
			want = row.managedWant
		}
		t.Logf("HP8ROW %s | %s | want %s", call.name, call.verdict, want)
		if want != "" && call.verdict != want {
			t.Errorf("%s: verdict %s, want %s; body %.200s", call.name, call.verdict, want, call.body)
		}
	}
	if data, err := os.ReadFile(f.keys); err != nil || string(data) != "# decoy\n" {
		t.Fatalf("decoy keys file changed: %q %v", data, err)
	}
}

func TestGAP0330ConditionalBindingBeforeAbsoluteKeysFourCell(t *testing.T) {
	f := newB36ManagedHookFixture(t)
	ordinary := filepath.Join(f.project, "out3.txt")
	rows := []hp7ClientRow{}
	for _, form := range []struct{ name, prefix, write string }{
		{"false-and-copy", `false && D=build; `, `cp a.txt $D`},
		{"if-false-copy", `if false; then D=build; fi; `, `cp a.txt $D`},
		{"true-or-copy", `true || D=build; `, `cp a.txt $D`},
		{"false-and-redirect", `false && D=build; `, `echo marker >> $D`},
		{"if-false-redirect", `if false; then D=build; fi; `, `echo marker >> $D`},
		{"true-or-redirect", `true || D=build; `, `echo marker >> $D`},
	} {
		rows = append(rows, hp7ClientRow{"GAP0330/" + form.name, form.prefix + form.write + f.keys, "block", "block"})
		benignWrite := form.write
		if strings.Contains(form.name, "copy") {
			benignWrite = strings.ReplaceAll(benignWrite, "$D", "")
		}
		rows = append(rows, hp7ClientRow{"GAP0330/" + form.name + "-benign", form.prefix + benignWrite + ordinary, "allow", "allow"})
	}
	// The base already blocks this quoted tee form in per-user mode, while
	// managed mode allows the overwritten ordinary destination.
	rows = append(rows, hp7ClientRow{"GAP0389/tee-overwritten-benign", `f=keylink; f=out3.txt; echo m | tee "$f"`, "allow", "block"})
	rows = append(rows, hp7ClientRow{"GAP0389/tee-quoted-protected", `f=keylink; echo m | tee "$f"`, "block", "block"})
	checkHP7ClientRows(t, f, rows)
}

func TestGAP0389VariableLinkDestinationsFourCell(t *testing.T) {
	f := newB36ManagedHookFixture(t)
	rows := []hp7ClientRow{}
	for _, form := range []struct{ name, command string }{
		{"cd-tee", `cd project && f=keylink; tee $f < a.txt`},
		{"tee", `f=project/keylink; tee $f < project/a.txt`},
		{"cd-dd", `cd project && f=keylink; dd if=a.txt of=$f`},
		{"dd", `f=project/keylink; dd if=project/a.txt of=$f`},
		{"cd-install", `cd project && f=keylink; install -m 600 a.txt $f`},
		{"install", `f=project/keylink; install -m 600 project/a.txt $f`},
		{"cd-rsync", `cd project && f=keylink; rsync a.txt $f`},
		{"rsync", `f=project/keylink; rsync project/a.txt $f`},
		{"literal-cd-tee", `cd project && tee keylink < a.txt`},
		{"literal-cd-dd", `cd project && dd if=a.txt of=keylink`},
		{"literal-cd-install", `cd project && install -m 600 a.txt keylink`},
		{"literal-cd-rsync", `cd project && rsync a.txt keylink`},
	} {
		rows = append(rows, hp7ClientRow{"GAP0389/" + form.name, form.command, "block", "block"})
		if !strings.HasPrefix(form.name, "literal-") {
			rows = append(rows, hp7ClientRow{"GAP0389/" + form.name + "-benign", strings.ReplaceAll(form.command, "keylink", "out3.txt"), "allow", "allow"})
		}
	}
	checkHP8ClientRowsFromHome(t, f, rows)
}

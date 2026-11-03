// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// Round 4 review rows of fix/r107-bd-hookparse3 (IN-bd-hookparse3-REVIEW.md):
// ordinary scripts in a clean project (no link to the keys file anywhere in
// it), where the conservative unknown-target rule does not apply, so a block
// can only come from the kept-candidate saturation. want "" logs.

func hp3r4Defaults(k int, out string) string {
	var b strings.Builder
	for i := 1; i <= k; i++ {
		fmt.Fprintf(&b, "[ -n \"$V%d\" ] || V%d=opt%d\n", i, i, i)
	}
	b.WriteString(out)
	return b.String()
}

func hp3r4IfDefaults(k int, out string) string {
	var b strings.Builder
	for i := 1; i <= k; i++ {
		fmt.Fprintf(&b, "if [ -z \"$V%d\" ]; then V%d=opt%d; fi\n", i, i, i)
	}
	b.WriteString(out)
	return b.String()
}

var reviewHP3R4CleanRows = []struct{ name, command, want string }{
	{"r4-clean-configure-10-defaults", hp3r4Defaults(10, "out=config.mk\nif [ -n \"$LOCAL\" ]; then out=config.local.mk; fi\necho \"V1=$V1\" > \"$out\""), "allow"},
	{"r4-clean-configure-10-defaults-fixed-out", hp3r4Defaults(10, "echo \"V1=$V1 V2=$V2\" > config.mk"), "allow"},
	{"r4-clean-configure-10-defaults-cp", hp3r4Defaults(10, "out=config.mk; cp a.txt \"$out\""), "allow"},
	{"r4-clean-configure-5-defaults-cp", hp3r4Defaults(5, "out=config.mk; cp a.txt \"$out\""), "allow"},
	{"r4-clean-configure-6-defaults-cp", hp3r4Defaults(6, "out=config.mk; cp a.txt \"$out\""), "allow"},
	{"r4-clean-configure-10-if-defaults-cp", hp3r4IfDefaults(10, "cp a.txt \"build/$V1.cfg\""), "allow"},
	{"r4-clean-options-6-cases-cp", hp3r3BuildCases(6) + "cp a.txt \"out.$m1\"", "allow"},
	{"r4-clean-configure-10-defaults-tee", hp3r4Defaults(10, "out=config.mk; echo x | tee \"$out\""), "allow"},
	{"r4-clean-configure-10-defaults-mv", hp3r4Defaults(10, "out=config.mk; mv a.txt \"$out\""), "allow"},
	{"r4-clean-configure-10-if-defaults", hp3r4IfDefaults(10, "out=config.mk\necho \"V1=$V1\" > \"$out\""), "allow"},
	{"r4-clean-configure-5-defaults", hp3r4Defaults(5, "out=config.mk\necho \"V1=$V1\" > \"$out\""), "allow"},
	{"r4-clean-configure-6-defaults", hp3r4Defaults(6, "out=config.mk\necho \"V1=$V1\" > \"$out\""), "allow"},
	{"r4-clean-options-6-cases", "for a in \"$@\"; do :; done\n" + hp3r3BuildCases(6) + "out=build.mode; echo \"$m1\" > \"$out\"", "allow"},
	{"r4-clean-backup-loops-10", hp3r3BuildLoops(10), "allow"},
	{"r4-clean-logrotate", `log=build.log; for i in 3 2 1; do if [ -f "$log.$i" ]; then mv "$log.$i" "$log.$((i+1))"; fi; done; if [ -f "$log" ]; then mv "$log" "$log.1"; fi; : > "$log"`, "allow"},
	{"r4-clean-build-outdir", `out=build; if [ -n "$DEBUG" ]; then out=build/debug; fi; mkdir -p "$out"; echo done >> "$out/build.log"`, "allow"},
	{"r4-clean-group-dest", `dest=dist; { dest=dist/pkg; mkdir -p "$dest"; }; cp a.txt "$dest/"`, "allow"},
	{"r4-clean-if-else-src", `if [ -f a.txt ]; then src=a.txt; else src=b.txt; fi; out=$src.orig; cp "$src" "$out"`, "allow"},
	{"r4-clean-andand-log", `log=run.log; [ -d logs ] && log=logs/run.log; echo start >> "$log"`, "allow"},
	{"r4-clean-while-counter", `n=0; while [ $n -lt 3 ]; do n=$((n+1)); f=out$n.txt; echo $n > "$f"; done`, "allow"},
	{"r4-clean-for-bak-list", `for f in *.txt; do out=$f.bak; cp "$f" "$out"; echo "$out" >> backups.list; done`, "allow"},
	{"r4-clean-multiline-build", "set -e\nBUILD=build\nif [ \"$1\" = clean ]; then\n  rm -rf \"$BUILD\"\nfi\nmkdir -p \"$BUILD\"\nfor src in *.txt; do\n  obj=\"$BUILD/${src%.txt}.o\"\n  cp \"$src\" \"$obj\"\n  echo \"$obj\" >> \"$BUILD/manifest\"\ndone\nLOG=\"$BUILD/build.log\"\ncase \"$MODE\" in\n  ci) LOG=\"$BUILD/ci.log\" ;;\nesac\ndate > \"$LOG\"", "allow"},
}

// hp3r4PreExisting are cells that origin/rel/1.0.7 e3c263a14b blocks too:
// logged, not asserted ("all", "managed"). Every other cell of a row with
// want allow allows on e3c263a14b and must allow on the branch.
var hp3r4PreExisting = map[string]string{
	"r4-clean-configure-10-if-defaults-cp": "all",
	"r4-clean-options-6-cases-cp":          "all",
	"r4-clean-for-bak-list":                "all",
	"r4-clean-multiline-build":             "managed",
	"r4-clean-configure-10-defaults-cp":    "managed",
	"r4-clean-configure-5-defaults-cp":     "managed",
	"r4-clean-configure-6-defaults-cp":     "managed",
	"r4-clean-group-dest":                  "managed",
	"r4-clean-if-else-src":                 "managed",
}

func TestReviewHP3R4CleanProjectFourCell(t *testing.T) {
	f := newB36ManagedHookFixture(t)
	clean := filepath.Join(f.home, "clean")
	if err := os.MkdirAll(clean, 0o700); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"a.txt", "b.txt", "list.txt"} {
		if err := os.WriteFile(filepath.Join(clean, name), []byte("x\n"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	only := os.Getenv("HP3R4_ROWS")
	for _, row := range reviewHP3R4CleanRows {
		if only != "" && !strings.Contains(row.name, only) {
			continue
		}
		payload := mustJSON(t, map[string]any{"session_id": "b36", "hook_event_name": "PreToolUse", "cwd": clean,
			"permission_mode": "default", "tool_name": "Bash", "tool_use_id": "toolu_b36",
			"tool_input": map[string]any{"command": row.command, "description": "Run test fixture command"}})
		header := f.clientHeader(t, payload)
		for _, call := range everyMode(row.name, payload, header) {
			mode := os.FileMode(0o700)
			if call.managed {
				mode = 0
			}
			if err := os.Chmod(f.homes, mode); err != nil {
				t.Fatal(err)
			}
			call.verdict, call.body = f.serve(call)
			t.Logf("HP3R4ROW %s | %s | want %s", call.name, call.verdict, row.want)
			if pre := hp3r4PreExisting[row.name]; pre == "all" || pre == "managed" && call.managed {
				continue
			}
			if row.want != "" && call.verdict != row.want {
				t.Errorf("%s: verdict %s, want %s; body %.200s", call.name, call.verdict, row.want, call.body)
			}
		}
		if err := os.Chmod(f.homes, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	if data, err := os.ReadFile(f.keys); err != nil || string(data) != "# decoy\n" {
		t.Fatalf("decoy keys file changed: %q %v", data, err)
	}
}

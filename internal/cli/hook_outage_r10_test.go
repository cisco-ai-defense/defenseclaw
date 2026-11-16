// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func outageR10Fixture(t *testing.T, homeName string) (root, protected, ordinary string) {
	t.Helper()
	home := filepath.Join(t.TempDir(), homeName)
	previous := outageAccountHome
	outageAccountHome = func() string { return home }
	t.Cleanup(func() { outageAccountHome = previous })
	root = filepath.Join(home, ".defenseclaw")
	if err := os.MkdirAll(root, 0700); err != nil {
		t.Fatal(err)
	}
	protected = filepath.Join(root, "config.yaml")
	if err := os.WriteFile(protected, []byte("guardrail: {}\n"), 0600); err != nil {
		t.Fatal(err)
	}
	ordinary = t.TempDir()
	if err := os.WriteFile(filepath.Join(ordinary, "notes.txt"), []byte("x\n"), 0600); err != nil {
		t.Fatal(err)
	}
	return root, protected, ordinary
}

func outageR10Decision(t *testing.T, root, ordinary, command string, environment map[string]interface{}) string {
	t.Helper()
	args := map[string]interface{}{"command": command, "env": environment}
	blob, err := json.Marshal(outageToolPayload{Name: "exec", Args: args, CWD: ordinary})
	if err != nil {
		t.Fatal(err)
	}
	return outageToolDecision(strings.NewReader(string(blob)), root)
}

// The known-value outage reader follows the statements the shell runs, at
// any nesting, and reads the options of an entry-change command with its own
// grammar: a value an option only reads is not a changed entry, and a
// statement after a loop control or in a branch a static condition skips is
// not a write. A protected file reached through a known value blocks under
// every compound wrapper.
func TestOpenClawOutageKnownValuesFollowExecutedStatements(t *testing.T) {
	root, protected, ordinary := outageR10Fixture(t, "home")
	link := filepath.Join(ordinary, "config-link")
	if err := os.Symlink(protected, link); err != nil {
		t.Fatal(err)
	}
	cases := []struct{ name, command, out, want string }{
		{"direct remove", "rm " + protected, "notes.txt", "protected"},
		{"known remove", `rm "$OUT"`, protected, "protected"},
		{"known link remove", `rm "$OUT"`, link, "protected"},
		{"known chmod", `chmod 600 "$OUT"`, protected, "protected"},
		{"known find exec", `find "$OUT" -exec chmod 600 {} +`, protected, "protected"},
		{"known chmod option mode", `chmod -w "$OUT"`, protected, "protected"},
		{"known chmod reference target", `chmod --reference notes.txt "$OUT"`, protected, "protected"},
		{"known chown from target", `chown --from root nobody "$OUT"`, protected, "protected"},
		{"known touch reference target", `touch -r notes.txt "$OUT"`, protected, "protected"},
		{"known shred random source target", `shred --random-source notes.txt "$OUT"`, protected, "protected"},
		{"known shred clustered size", `shred -zn 3 "$OUT"`, protected, "protected"},
		{"known install clustered mode", `install -Dm600 notes.txt "$OUT"`, protected, "protected"},
		{"ordinary chmod reference separate", `chmod --reference "$OUT" notes.txt`, protected, "open"},
		{"ordinary chmod reference abbreviated", `chmod --ref "$OUT" notes.txt`, protected, "open"},
		{"ordinary chmod reference recursive", `chmod -R --reference "$OUT" notes.txt`, protected, "open"},
		{"ordinary chown reference separate", `chown --reference "$OUT" notes.txt`, protected, "open"},
		{"ordinary chgrp reference separate", `chgrp --reference "$OUT" notes.txt`, protected, "open"},
		{"ordinary touch reference", `touch -r "$OUT" notes.txt`, protected, "open"},
		{"ordinary touch reference long", `touch --reference "$OUT" notes.txt`, protected, "open"},
		{"ordinary shred random source separate", `shred --random-source "$OUT" notes.txt`, protected, "open"},
		{"ordinary shred options and random source", `shred -n 3 -u --random-source "$OUT" notes.txt`, protected, "open"},
		{"ordinary loop break before remove", `for x in "$PROT"; do break; rm "$x"; done`, "notes.txt", "open"},
		{"ordinary loop continue before remove", `for x in "$PROT"; do continue; rm "$x"; done`, "notes.txt", "open"},
		{"ordinary loop break before write", `for x in "$PROT"; do break; printf x >> "$x"; done`, "notes.txt", "open"},
		{"ordinary loop continue before write", `for x in "$PROT"; do continue; printf x >> "$x"; done`, "notes.txt", "open"},
		{"ordinary loop conditional break before remove", `for x in "$PROT"; do if true; then break; fi; rm "$x"; done`, "notes.txt", "open"},
		{"ordinary loop if false remove", `for x in "$PROT"; do if false; then rm "$x"; fi; done`, "notes.txt", "open"},
		{"ordinary loop block break", `for x in "$PROT"; do { break; }; rm "$x"; done`, "notes.txt", "open"},
		{"ordinary loop case continue", `for x in "$PROT"; do case a in a) continue;; esac; rm "$x"; done`, "notes.txt", "open"},
		{"ordinary loop or skip", `for x in "$PROT"; do true || rm "$x"; done`, "notes.txt", "open"},
		{"ordinary loop and skip", `for x in "$PROT"; do false && rm "$x"; done`, "notes.txt", "open"},
		{"ordinary loop inner counted break", `for x in "$PROT"; do for y in a; do break 2; done; rm "$x"; done`, "notes.txt", "open"},
		{"ordinary first item break", `for x in notes.txt "$PROT"; do rm "$x"; break; done`, protected, "open"},
		{"ordinary while false", `while false; do rm "$OUT"; done`, protected, "open"},
		{"ordinary until true", `until true; do rm "$OUT"; done`, protected, "open"},
		{"ordinary while break first", `while true; do break; rm "$OUT"; done`, protected, "open"},
		{"ordinary if false", `if false; then rm "$OUT"; fi`, protected, "open"},
		{"ordinary or skip", `true || rm "$OUT"`, protected, "open"},
		{"ordinary exit before remove", `exit 0; rm "$OUT"`, protected, "open"},
		{"ordinary conditional exit before remove", `if true; then exit; fi; rm "$OUT"`, protected, "open"},
		{"ordinary loop exit before remove", `for x in "$PROT"; do exit 1; rm "$x"; done`, "notes.txt", "open"},
		{"protected remove before exit", `rm "$OUT"; exit 0`, protected, "protected"},
		{"protected subshell exit", `( exit 0 ); rm "$OUT"`, protected, "protected"},
		{"protected unknown exit", `test -e missing && exit; rm "$OUT"`, protected, "protected"},
		{"protected loop break outside loop", `break; rm "$OUT"`, protected, "protected"},
		{"ordinary wrapped loop", `if true; then for x in notes.txt; do rm "$x"; done; fi`, protected, "open"},
		{"protected loop executes remove", `for x in "$PROT"; do rm "$x"; done`, "notes.txt", "protected"},
		{"protected loop executes write", `for x in "$PROT"; do printf x >> "$x"; done`, "notes.txt", "protected"},
		{"protected loop remove before break", `for x in "$PROT"; do rm "$x"; break; done`, "notes.txt", "protected"},
		{"protected loop inner break", `for x in "$PROT"; do for y in a; do break; done; rm "$x"; done`, "notes.txt", "protected"},
		{"protected loop unknown continue", `for x in notes.txt "$PROT"; do if [ "$x" = notes.txt ]; then continue; fi; rm "$x"; done`, "notes.txt", "protected"},
		{"protected loop pipeline", `for x in "$PROT"; do echo x | tee "$x"; done`, "notes.txt", "protected"},
		{"protected loop nested if", `for x in "$PROT"; do if true; then rm "$x"; fi; done`, "notes.txt", "protected"},
		{"protected if wrapped loop remove", `if true; then for x in "$PROT"; do rm "$x"; done; fi`, "notes.txt", "protected"},
		{"protected block wrapped loop remove", `{ for x in "$PROT"; do rm "$x"; done; }`, "notes.txt", "protected"},
		{"protected case wrapped loop remove", `case yes in yes) for x in "$PROT"; do rm "$x"; done;; esac`, "notes.txt", "protected"},
		{"protected if wrapped loop write", `if true; then for x in "$PROT"; do printf x >> "$x"; done; fi`, "notes.txt", "protected"},
		{"protected else wrapped loop", `if false; then :; else for x in "$PROT"; do rm "$x"; done; fi`, "notes.txt", "protected"},
		{"protected and wrapped loop", `true && for x in "$PROT"; do rm "$x"; done`, "notes.txt", "protected"},
		{"protected or wrapped loop", `false || { for x in "$PROT"; do chmod 600 "$x"; done; }`, "notes.txt", "protected"},
		{"protected subshell wrapped loop", `( for x in "$PROT"; do rm "$x"; done )`, "notes.txt", "protected"},
		{"protected nested loops", `for y in a; do for x in "$PROT"; do rm "$x"; done; done`, "notes.txt", "protected"},
		{"protected while wrapped loop", `while true; do for x in "$PROT"; do rm "$x"; done; break; done`, "notes.txt", "protected"},
		{"protected redirected block loop", `{ for x in "$PROT"; do rm "$x"; done; } > notes.log`, "notes.txt", "protected"},
		{"protected redirected block target", `{ echo x; } > "$OUT"`, protected, "protected"},
		{"protected wrapped function call", `f() { rm "$1"; }; if true; then f "$PROT"; fi`, "notes.txt", "protected"},
		{"protected literal wrapped loop", "if true; then for x in " + protected + `; do rm "$x"; done; fi`, "notes.txt", "protected"},
		{"protected unquoted split item", `for x in $OUT; do rm "$x"; done`, "notes.txt " + protected, "protected"},
		{"protected unknown while", `while read -r line; do rm "$OUT"; done < notes.txt`, protected, "protected"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := outageR10Decision(t, root, ordinary, tc.command, map[string]interface{}{"OUT": tc.out, "PROT": protected})
			if got != tc.want {
				t.Errorf("decision=%q want=%q command=%q", got, tc.want, tc.command)
			}
		})
	}
}

// A quoted known value is one loop item whatever it contains, as in the
// shell; an unquoted one splits at the default field separators.
func TestOpenClawOutageQuotedLoopItemWithSpaces(t *testing.T) {
	root, protected, ordinary := outageR10Fixture(t, "home with spaces")
	cases := []struct{ name, command, want string }{
		{"direct known remove", `rm "$PROT"`, "protected"},
		{"quoted known loop remove", `for x in "$PROT"; do rm "$x"; done`, "protected"},
		{"quoted known loop write", `for x in "$PROT"; do printf x >> "$x"; done`, "protected"},
		{"quoted known wrapped loop", `if true; then for x in "$PROT"; do rm "$x"; done; fi`, "protected"},
		{"quoted known loop with suffix", `for x in "$PROT".bak "$PROT"; do rm "$x"; done`, "protected"},
		{"unquoted known loop splits", `for x in $PROT; do rm "$x"; done`, "open"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := outageR10Decision(t, root, ordinary, tc.command, map[string]interface{}{"PROT": protected}); got != tc.want {
				t.Errorf("decision=%q want=%q command=%q", got, tc.want, tc.command)
			}
		})
	}
}

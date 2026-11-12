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

// The outage reader gives a protected file named through a known tool
// environment value the decision of its literal name for every command that
// changes the entry, and follows loop controls so an item the loop never
// reaches does not block ordinary work.
func TestOpenClawOutageKnownEntryChangesAndLoopControl(t *testing.T) {
	home := t.TempDir()
	previous := outageAccountHome
	outageAccountHome = func() string { return home }
	t.Cleanup(func() { outageAccountHome = previous })
	root := filepath.Join(home, ".defenseclaw")
	if err := os.MkdirAll(root, 0700); err != nil {
		t.Fatal(err)
	}
	protected := filepath.Join(root, "config.yaml")
	if err := os.WriteFile(protected, []byte("guardrail: {}\n"), 0600); err != nil {
		t.Fatal(err)
	}
	ordinary := t.TempDir()
	if err := os.WriteFile(filepath.Join(ordinary, "notes.txt"), []byte("x\n"), 0600); err != nil {
		t.Fatal(err)
	}
	cases := []struct{ name, command, out, want string }{
		{"literal remove", "rm " + protected, protected, "protected"},
		{"literal move source", "mv " + protected + " notes.txt", protected, "protected"},
		{"known remove", `rm "$OUT"`, protected, "protected"},
		{"known remove options", `rm -f -- "$OUT"`, protected, "protected"},
		{"known unlink", `unlink "$OUT"`, protected, "protected"},
		{"known shred", `shred -n 1 -u "$OUT"`, protected, "protected"},
		{"known move source", `mv "$OUT" notes.txt`, protected, "protected"},
		{"known move destination", `mv notes.txt "$OUT"`, protected, "protected"},
		{"known chmod", `chmod 600 "$OUT"`, protected, "protected"},
		{"known chmod option mode", `chmod -w "$OUT"`, protected, "protected"},
		{"known chown", `chown nobody "$OUT"`, protected, "protected"},
		{"known chgrp", `chgrp nogroup "$OUT"`, protected, "protected"},
		{"known touch", `touch "$OUT"`, protected, "protected"},
		{"known install destination", `install -m 600 notes.txt "$OUT"`, protected, "protected"},
		{"known sed in place", `sed -i s/a/b/ "$OUT"`, protected, "protected"},
		{"known nested remove", `sh -c 'rm "$OUT"'`, protected, "protected"},
		{"known wrapped remove", `env OUT="$PROT" sh -c 'unlink "$OUT"'`, "notes.txt", "protected"},
		{"local known chmod", `F="$PROT"; chmod 600 "$F"`, "notes.txt", "protected"},
		{"known find delete", `find "$OUT" -delete`, protected, "protected"},
		{"known find exec remove", `find "$OUT" -exec rm {} +`, protected, "protected"},
		{"known loop variable write", `for x in "$PROT"; do printf x >> "$x"; done`, "notes.txt", "protected"},
		{"known loop variable remove", `for x in notes.txt "$OUT"; do rm "$x"; done`, protected, "protected"},
		{"known loop variable chmod after continue", `for x in notes.txt "$OUT"; do [ "$x" = notes.txt ] && continue; chmod 600 "$x"; done`, protected, "protected"},
		{"ordinary find delete", `find "$OUT" -name "*.tmp" -delete`, ordinary, "open"},
		{"ordinary loop variable remove", `for x in notes.txt other.txt; do rm "$x"; done`, protected, "open"},
		{"ordinary loop variable break", `for x in notes.txt "$OUT"; do rm "$x"; break; done`, protected, "open"},
		{"ordinary while break", `while true; do OUT=notes.txt; break; done; printf x >> "$OUT"`, protected, "open"},
		{"ordinary until break", `until false; do OUT=notes.txt; break; done; printf x >> "$OUT"`, protected, "open"},
		{"protected while break", `while true; do OUT="$PROT"; break; done; printf x >> "$OUT"`, "notes.txt", "protected"},
		{"protected while unknown", `while read -r line; do OUT="$PROT"; break; done < notes.txt; printf x >> "$OUT"`, "notes.txt", "protected"},
		{"ordinary remove", `rm "$OUT"`, "notes.txt", "open"},
		{"ordinary move", `mv notes.txt other.txt`, protected, "open"},
		{"ordinary touch reference", `touch -r "$OUT" notes.txt`, protected, "open"},
		{"ordinary install source", `install -m 600 "$OUT" notes.txt`, protected, "open"},
		{"ordinary chmod reference", `chmod --reference="$OUT" notes.txt`, protected, "open"},
		{"ordinary read", `wc -l "$OUT"`, protected, "open"},
		{"ordinary for break count", `for x in notes.txt "$PROT"; do OUT="$x"; break 1; done; printf x >> "$OUT"`, protected, "open"},
		{"ordinary for conditional break", `for x in notes.txt "$PROT"; do OUT="$x"; if true; then break; fi; done; printf x >> "$OUT"`, protected, "open"},
		{"ordinary for else break", `for x in notes.txt "$PROT"; do OUT="$x"; if false; then :; else break; fi; done; printf x >> "$OUT"`, protected, "open"},
		{"ordinary for block break", `for x in notes.txt "$PROT"; do OUT="$x"; { break; }; done; printf x >> "$OUT"`, protected, "open"},
		{"ordinary for and break", `for x in notes.txt "$PROT"; do OUT="$x"; true && break; done; printf x >> "$OUT"`, protected, "open"},
		{"ordinary for or break", `for x in notes.txt "$PROT"; do OUT="$x"; false || break; done; printf x >> "$OUT"`, protected, "open"},
		{"ordinary for case break", `for x in notes.txt "$PROT"; do OUT="$x"; case "$x" in notes.txt) break;; esac; done; printf x >> "$OUT"`, protected, "open"},
		{"ordinary for plain break", `for x in notes.txt "$PROT"; do OUT="$x"; break; done; printf x >> "$OUT"`, protected, "open"},
		{"ordinary for continue", `for x in "$PROT" notes.txt; do OUT="$x"; continue; done; printf x >> "$OUT"`, protected, "open"},
		{"ordinary for inner loop break", `for x in "$PROT" notes.txt; do OUT="$x"; for y in a; do break; done; done; printf x >> "$OUT"`, protected, "open"},
		{"ordinary for inner counted break", `for x in notes.txt "$PROT"; do OUT="$x"; for y in a; do break 2; done; done; printf x >> "$OUT"`, protected, "open"},
		{"ordinary for inner conditional counted break", `for x in notes.txt "$PROT"; do OUT="$x"; for y in a b; do if true; then break 2; fi; done; done; printf x >> "$OUT"`, protected, "open"},
		{"protected for inner counted break", `for x in "$PROT" notes.txt; do OUT="$x"; for y in a; do break 2; done; done; printf x >> "$OUT"`, "notes.txt", "protected"},
		{"protected for inner counted continue", `for x in notes.txt; do OUT="$PROT"; for y in a; do continue 2; done; OUT=notes.txt; done; printf x >> "$OUT"`, "notes.txt", "protected"},
		{"protected for inner skipped counted break", `for x in notes.txt "$PROT"; do OUT="$x"; for y in a; do if false; then break 2; fi; done; done; printf x >> "$OUT"`, "notes.txt", "protected"},
		{"protected for no break", `for x in notes.txt "$PROT"; do OUT="$x"; done; printf x >> "$OUT"`, "notes.txt", "protected"},
		{"protected for break count", `for x in "$PROT" notes.txt; do OUT="$x"; break 1; done; printf x >> "$OUT"`, "notes.txt", "protected"},
		{"protected for skipped break", `for x in notes.txt "$PROT"; do OUT="$x"; if false; then break; fi; done; printf x >> "$OUT"`, "notes.txt", "protected"},
		{"protected for unknown break", `for x in notes.txt "$PROT"; do OUT="$x"; test -e missing && break; done; printf x >> "$OUT"`, "notes.txt", "protected"},
		{"protected for subshell break", `for x in notes.txt "$PROT"; do OUT="$x"; (break); done; printf x >> "$OUT"`, "notes.txt", "protected"},
		{"protected for case miss", `for x in notes.txt "$PROT"; do OUT="$x"; case "$x" in other) break;; esac; done; printf x >> "$OUT"`, "notes.txt", "protected"},
		{"protected for break after assignment", `for x in notes.txt; do if true; then OUT="$PROT"; break; fi; done; printf x >> "$OUT"`, "notes.txt", "protected"},
		{"protected for inner loop", `for x in notes.txt "$PROT"; do OUT="$x"; for y in a; do break; done; done; printf x >> "$OUT"`, "notes.txt", "protected"},
		{"protected for continue", `for x in notes.txt "$PROT"; do OUT="$x"; continue; done; printf x >> "$OUT"`, "notes.txt", "protected"},
		{"protected for removal", `for x in notes.txt "$PROT"; do F="$x"; done; rm "$F"`, "notes.txt", "protected"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			args := map[string]interface{}{"command": tc.command, "env": map[string]interface{}{"OUT": tc.out, "PROT": protected}}
			blob, err := json.Marshal(outageToolPayload{Name: "exec", Args: args, CWD: ordinary})
			if err != nil {
				t.Fatal(err)
			}
			if got := outageToolDecision(strings.NewReader(string(blob)), root); got != tc.want {
				t.Errorf("decision=%q want=%q command=%q", got, tc.want, tc.command)
			}
		})
	}
}

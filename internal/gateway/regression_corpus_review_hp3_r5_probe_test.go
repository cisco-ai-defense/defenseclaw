// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build regressioncorpora

package gateway

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// Round 5 review probes (not committed): each form runs plain, after the
// candidate cap and after the step cap, with a benign twin. Logged only.

func hp3r5Conds(k int) string {
	var b strings.Builder
	for i := 1; i <= k; i++ {
		fmt.Fprintf(&b, "if [ -n \"$A%d\" ]; then a%d=1; fi; ", i, i)
	}
	return b.String()
}

var hp3r5Forms = []struct{ name, pre, post string }{
	{"funcdef-before", `setf() { f=keylink; }; f=a.txt; `, `setf; echo m >> "$f"`},
	{"funcdef-after", ``, `setf() { f=keylink; }; f=a.txt; setf; echo m >> "$f"`},
	{"command-eval", `f=a.txt; `, `command eval f=keylink; echo m >> "$f"`},
	{"builtin-eval", `f=a.txt; `, `builtin eval f=keylink; echo m >> "$f"`},
	{"eval-dynamic", `g=keylink; f=a.txt; `, `eval f=; echo m >> "$f"`},
	{"assign-default", `f=; `, `: "${f:=keylink}"; echo m >> "$f"`},
	{"for-var", `f=a.txt; `, `for f in keylink; do :; done; echo m >> "$f"`},
	{"env-prefix", `f=keylink; `, `f=a.txt true; echo m >> "$f"`},
	{"nameref", `g=keylink; `, `declare -n f=g; echo m >> "$f"`},
	{"if-alt-prior-protected", `f=keylink; `, `if [ -n "$X" ]; then f=a.txt; fi; echo m >> "$f"`},
	{"if-else-after", `f=a.txt; `, `if [ -n "$X" ]; then f=b.txt; else f=keylink; fi; echo m >> "$f"`},
	{"if-read-cond", `f=a.txt; `, `if read -r f < names.txt; then x=1; fi; echo m >> "$f"`},
	{"alt-copy", `f=a.txt; `, `if [ -n "$X" ]; then f=keylink; fi; g=$f; echo m >> "$g"`},
	{"alt-twice", `f=a.txt; `, `if [ -n "$X" ]; then f=b.txt; fi; if [ -n "$Y" ]; then f=keylink; fi; echo m >> "$f"`},
	{"alt-tee", `f=a.txt; `, `if [ -n "$X" ]; then f=keylink; fi; echo x | tee "$f"`},
	{"alt-cp", `f=a.txt; `, `if [ -n "$X" ]; then f=keylink; fi; cp a.txt "$f"`},
	{"alt-test-z", `f=a.txt; `, `if test -z "$X"; then f=keylink; fi; echo m >> "$f"`},
	{"cp-direct", `f=keylink; `, `cp a.txt "$f"`},
	{"cp-after-assign", `f=a.txt; `, `f=keylink; cp a.txt "$f"`},
	{"install", `f=keylink; `, `install -m 600 a.txt "$f"`},
	{"dd", `f=keylink; `, `dd if=a.txt of="$f"`},
	{"nohup-cp", `f=keylink; `, `nohup cp a.txt "$f"`},
	{"env-cp", `f=keylink; `, `env cp a.txt "$f"`},
	{"sshdir-var-cp", `d=sshlink; `, `cp a.txt "$d/authorized_keys"`},
	{"sshdir-var-redirect", `d=sshlink; `, `echo m >> "$d/authorized_keys"`},
	{"rsync", `f=keylink; `, `rsync a.txt "$f"`},
	{"home-var", ``, `f=$HOME/.ssh/authorized_keys; echo m >> "$f"`},
	{"home-var-cp", ``, `f=$HOME/.ssh/authorized_keys; cp a.txt "$f"`},
	{"cd-pwd", ``, `cd sshlink && echo m >> "$PWD/authorized_keys"`},
	{"trap", ``, `trap "f=keylink" DEBUG; f=a.txt; echo m >> "$f"`},
	{"while-read", `f=a.txt; `, `while read -r f; do break; done < names.txt; echo m >> "$f"`},
	{"case-after", `f=a.txt; `, `case "$X" in y) f=keylink;; esac; echo m >> "$f"`},
	{"andand-after", `f=a.txt; `, `[ -n "$X" ] && f=keylink; echo m >> "$f"`},
	{"tee-after-assign", `f=a.txt; `, `f=keylink; echo x | tee -a "$f"`},
	{"cp-default", ``, `cp a.txt "${f:-keylink}"`},
	{"printf-v", `f=a.txt; `, `printf -v f %s keylink; echo m >> "$f"`},
	{"mapfile", ``, `mapfile -t f < names.txt; echo m >> "${f[0]}"`},
	{"export-after", `f=a.txt; `, `export f=keylink; echo m >> "$f"`},
	{"read-herestring", `f=a.txt; `, `read -r f <<< keylink; echo m >> "$f"`},
	{"source", `f=a.txt; `, `. ./setf.sh; echo m >> "$f"`},
	{"subshell-cp", `f=keylink; `, `(cp a.txt "$f")`},
	{"pipeline-tee", `f=keylink; `, `cat a.txt | tee "$f" >/dev/null`},
	{"group-redirect", `f=a.txt; `, `{ f=keylink; echo m >> "$f"; }`},
	{"unset-then-default", `f=a.txt; `, `unset f; echo m >> "${f:-keylink}"`},
	{"append-assign", `f=key; `, `f+=link; echo m >> "$f"`},
	{"same-stmt-assign-redirect", `f=a.txt; `, `f=keylink >> "$f"`},
}

func TestReviewHP3R5Probe(t *testing.T) {
	f := newB36ManagedHookFixture(t)
	if err := os.Symlink("../.ssh", filepath.Join(f.project, "sshlink")); err != nil {
		t.Fatal(err)
	}
	files := map[string]string{"a.txt": "x\n", "b.txt": "x\n", "list.txt": "x\n", "names.txt": "keylink\n", "names2.txt": "out.txt\n",
		"setf.sh": "f=keylink\n", "setf2.sh": "f=out.txt\n"}
	for name, body := range files {
		if err := os.WriteFile(filepath.Join(f.project, name), []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	mids := []struct{ name, text string }{{"plain", ""}, {"satc", hp3r5Conds(9)}, {"sats", hp3r5Conds(5) + strings.Repeat(":; ", 20)}}
	twin := strings.NewReplacer("keylink", "out.txt", "names.txt", "names2.txt", "setf.sh", "setf2.sh", "sshlink", "ordinary", ".ssh/authorized_keys", "notes.txt")
	only := os.Getenv("HP3R5_ROWS")
	for _, form := range hp3r5Forms {
		for _, mid := range mids {
			for _, kind := range []string{"protected", "benign"} {
				name := form.name + "/" + mid.name + "/" + kind
				if only != "" && !strings.Contains(name, only) {
					continue
				}
				command := form.pre + mid.text + form.post
				if kind == "benign" {
					command = twin.Replace(command)
				}
				payload := f.payload(t, command)
				header := f.clientHeader(t, payload)
				for _, call := range everyMode(name, payload, header) {
					mode := os.FileMode(0o700)
					if call.managed {
						mode = 0
					}
					if err := os.Chmod(f.homes, mode); err != nil {
						t.Fatal(err)
					}
					call.verdict, call.body = f.serve(call)
					t.Logf("HP3R5ROW %s | %s", call.name, call.verdict)
				}
				if err := os.Chmod(f.homes, 0o700); err != nil {
					t.Fatal(err)
				}
			}
		}
	}
	if data, err := os.ReadFile(f.keys); err != nil || string(data) != "# decoy\n" {
		t.Fatalf("decoy keys file changed: %q %v", data, err)
	}
}

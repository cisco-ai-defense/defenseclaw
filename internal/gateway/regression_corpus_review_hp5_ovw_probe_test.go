// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build regressioncorpora

package gateway

import (
	"os"
	"path/filepath"
	"testing"
)

// hookparse5 review probes (not committed): neighbours of the narrow
// overwritten-redirect proof and of the client variable-write candidate.
var hp5OvwRows = []struct{ name, command, want string }{
	{"ovw-plain-benign", `f=keylink; f=a.txt; echo m >> "$f"`, "allow"},
	{"ovw-if-true-benign", `f=keylink; if true; then f=a.txt; fi; echo m >> "$f"`, "allow"},
	{"ovw-if-false", `f=keylink; if false; then f=a.txt; fi; echo m >> "$f"`, "block"},
	{"ovw-if-colon-neg", `f=keylink; if ! :; then f=a.txt; fi; echo m >> "$f"`, "block"},
	{"ovw-second-link", `f=keylink; f=keylink2; echo m >> "$f"`, "block"},
	{"ovw-second-dirlink", `f=keylink; f=sshlink/authorized_keys; echo m >> "$f"`, "block"},
	{"ovw-other-name", `f=keylink; g=a.txt; echo m >> "$f"`, "block"},
	{"ovw-append-assign", `f=keylink; f+=x; echo m >> "$f"`, "allow"},
	{"ovw-bg-assign", `f=keylink; f=a.txt & echo m >> "$f"`, "block"},
	{"ovw-echo-cmdsub", `f=keylink; f=a.txt; echo $(echo m) >> "$f"`, "allow"},
	{"ovw-echo-var", `f=keylink; f=a.txt; echo "$f" >> "$f"`, "allow"},
	{"ovw-printf", `f=keylink; f=a.txt; printf m >> "$f"`, "allow"},
	{"ovw-subshell-assign", `f=keylink; (f=a.txt); echo m >> "$f"`, "block"},
	{"cand-tee-var", `f=keylink; echo m | tee "$f"`, "block"},
	{"cand-cp-var", `f=keylink; cp a.txt "$f"`, "block"},
	{"cand-redir-cmdsub", `echo m > "$(echo keylink)"`, "block"},
	{"cand-redir-read", `read -r f < names.txt; echo m >> "$f"`, "block"},
	{"cand-redir-read-benign", `read -r f < names2.txt; echo m >> "$f"`, "allow"},
	{"cand-redir-glob-loop", `for f in *.txt; do echo m >> "$f"; done`, "allow"},
	{"cand-redir-glob-loop-all", `for f in *; do echo m >> "$f"; done`, "block"},
	{"cand-redir-date", `echo m > "build-$(date +%s).log"`, "allow"},
	{"cand-redir-home-notes", `echo m >> "$HOME/notes.txt"`, "allow"},
	{"cand-redir-tmpdir", `echo m > "${TMPDIR:-/tmp}/x.log"`, "allow"},
	{"cand-redir-pos", `set -- out.txt; echo m > "$1"`, "allow"},
	{"cand-redir-random", `echo m > "out-$RANDOM.txt"`, "allow"},
	{"cand-install-dir", `d=ordinary; install -m 644 a.txt "$d"`, "allow"},
	{"cand-rsync-dir", `d=ordinary/; rsync -a a.txt "$d"`, "allow"},
	{"cand-rsync-src-var", `s=a.txt; rsync -a "$s" ordinary/`, "allow"},
}

func TestReviewHP5OvwProbe(t *testing.T) {
	f := newB36ManagedHookFixture(t)
	for _, link := range []struct{ target, name string }{{"../.ssh/authorized_keys", "keylink2"}, {"../.ssh", "sshlink"}} {
		if err := os.Symlink(link.target, filepath.Join(f.project, link.name)); err != nil {
			t.Fatal(err)
		}
	}
	files := map[string]string{"a.txt": "x\n", "b.txt": "x\n", "out.txt": "x\n", "names.txt": "keylink\n", "names2.txt": "out.txt\n"}
	for name, body := range files {
		if err := os.WriteFile(filepath.Join(f.project, name), []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	for _, row := range hp5OvwRows {
		payload := f.payload(t, row.command)
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
			t.Logf("HP5OVROW %s | %s | want %s", call.name, call.verdict, row.want)
		}
		if err := os.Chmod(f.homes, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	if data, err := os.ReadFile(f.keys); err != nil || string(data) != "# decoy\n" {
		t.Fatalf("decoy keys file changed: %q %v", data, err)
	}
}

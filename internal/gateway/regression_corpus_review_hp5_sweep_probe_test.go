// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build regressioncorpora

package gateway

import (
	"os"
	"path/filepath"
	"testing"
)

// hookparse5 review probes (not committed): sweep forms of rel-1-0-6
// GAP-0371, GAP-0389 (must block) and GAP-0375, GAP-0395 (must allow), in
// the four cells. Logged only.
var hp5SweepRows = []struct{ gap, name, cwd, command, want string }{
	{"0371", "v1-one-name", "project", `for f in keylink; do cp a.txt $f; done`, "block"},
	{"0371", "v2-harmless-first", "project", `for f in out2.txt keylink; do cp a.txt $f; done`, "block"},
	{"0371", "v4-link-first", "project", `for f in keylink out2.txt; do cp a.txt $f; done`, "block"},
	{"0371", "v6-quoted", "project", `for f in out2.txt keylink; do cp a.txt "$f"; done`, "block"},
	{"0371", "v5-then-echo", "project", `for f in out2.txt keylink; do cp a.txt $f; done; echo hi > report.txt`, "block"},
	{"0371", "v7-twin", "project", `for f in out2.txt out3.txt; do cp a.txt $f; done`, "allow"},
	{"0371", "v7-twin-quoted", "project", `for f in out2.txt out3.txt; do cp a.txt "$f"; done`, "allow"},
	{"0389", "tee-cd", "project", `cd ~/project && f=keylink; tee $f < a.txt`, "block"},
	{"0389", "tee-nocd", "project", `f=keylink; tee $f < a.txt`, "block"},
	{"0389", "dd-cd", "project", `cd ~/project && f=keylink; dd if=a.txt of=$f`, "block"},
	{"0389", "dd-nocd", "project", `f=keylink; dd if=a.txt of=$f`, "block"},
	{"0389", "install-cd", "project", `cd ~/project && f=keylink; install -m 600 a.txt $f`, "block"},
	{"0389", "install-nocd", "project", `f=keylink; install -m 600 a.txt $f`, "block"},
	{"0389", "rsync-cd", "project", `cd ~/project && f=keylink; rsync a.txt $f`, "block"},
	{"0389", "rsync-nocd", "project", `f=keylink; rsync a.txt $f`, "block"},
	{"0389", "echo-cd-control", "project", `cd ~/project && f=keylink; echo k > $f`, "block"},
	{"0389", "tee-cd-twin", "project", `cd ~/project && f=out.txt; tee $f < a.txt`, "allow"},
	{"0389", "tee-nocd-twin", "project", `f=out.txt; tee $f < a.txt`, "allow"},
	{"0389", "dd-cd-twin", "project", `cd ~/project && f=out.txt; dd if=a.txt of=$f`, "allow"},
	{"0389", "dd-nocd-twin", "project", `f=out.txt; dd if=a.txt of=$f`, "allow"},
	{"0389", "install-cd-twin", "project", `cd ~/project && f=out.txt; install -m 600 a.txt $f`, "allow"},
	{"0389", "install-nocd-twin", "project", `f=out.txt; install -m 600 a.txt $f`, "allow"},
	{"0389", "rsync-cd-twin", "project", `cd ~/project && f=out.txt; rsync a.txt $f`, "allow"},
	{"0389", "rsync-nocd-twin", "project", `f=out.txt; rsync a.txt $f`, "allow"},
	{"0375", "forvar-nocd", "clean", `f=a.txt; for x in $f; do cp $x build/; done; echo hi > report.txt`, "allow"},
	{"0375", "forvar-cd", "clean", `cd ~/clean && f=a.txt; for x in $f; do cp $x build/; done; echo hi > report.txt`, "allow"},
	{"0375", "literal-cd-control", "clean", `cd ~/clean && for x in a.txt; do cp $x build/; done; echo hi > report.txt`, "allow"},
	{"0375", "var-cp-control", "clean", `f=a.txt; cp $f out.txt`, "allow"},
	{"0395", "P06-find-exec-mv", "clean", `cd ~/clean && find . -name "*.txt" -exec mv {} build/ \;`, "allow"},
	{"0395", "P07-name-mkdir", "clean", `cd ~/clean && NAME=release; mkdir -p $NAME && cp README.md $NAME/ && tar -czf $NAME.tgz $NAME`, "allow"},
	{"0395", "P13-unzip-v-cd", "clean", `cd ~/clean && unzip -v >/dev/null 2>&1; cp a.txt build/ && echo ok`, "allow"},
	{"0395", "P13-unzip-v-nocd", "clean", `unzip -v >/dev/null 2>&1; cp a.txt build/ && echo ok`, "allow"},
	{"0395", "P13-true-control", "clean", `true >/dev/null 2>&1; cp a.txt build/ && echo ok`, "allow"},
	{"0395", "P17-D-build-sub", "clean", `cd ~/clean && D=build/sub; mkdir -p $D; cp a.txt $D; cp b.txt "$D/"`, "allow"},
	{"0396", "posix-cp-star", "clean", `cp *.txt build/`, "allow"},
}

func TestReviewHP5SweepProbe(t *testing.T) {
	f := newB36ManagedHookFixture(t)
	clean := filepath.Join(f.home, "clean")
	for _, dir := range []string{filepath.Join(clean, "build"), filepath.Join(clean, "src")} {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	for _, dir := range []string{f.project, clean} {
		for _, name := range []string{"a.txt", "b.txt", "README.md"} {
			if err := os.WriteFile(filepath.Join(dir, name), []byte("x\n"), 0o600); err != nil {
				t.Fatal(err)
			}
		}
	}
	for _, row := range hp5SweepRows {
		cwd := f.project
		if row.cwd == "clean" {
			cwd = clean
		}
		payload := mustJSON(t, map[string]any{"session_id": "b36", "hook_event_name": "PreToolUse", "cwd": cwd,
			"permission_mode": "default", "tool_name": "Bash", "tool_use_id": "toolu_b36",
			"tool_input": map[string]any{"command": row.command, "description": "Run test fixture command"}})
		header := f.clientHeader(t, payload)
		for _, call := range everyMode("gap"+row.gap+"/"+row.name, payload, header) {
			mode := os.FileMode(0o700)
			if call.managed {
				mode = 0
			}
			if err := os.Chmod(f.homes, mode); err != nil {
				t.Fatal(err)
			}
			call.verdict, call.body = f.serve(call)
			t.Logf("HP5SWROW %s | %s | want %s", call.name, call.verdict, row.want)
		}
		if err := os.Chmod(f.homes, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	if data, err := os.ReadFile(f.keys); err != nil || string(data) != "# decoy\n" {
		t.Fatalf("decoy keys file changed: %q %v", data, err)
	}
}

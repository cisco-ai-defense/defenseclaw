// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build regressioncorpora

package gateway

import (
	"os"
	"path/filepath"
	"testing"
)

// hookparse5 review probes (not committed): benign variable writes that a
// per-user gateway may block, so the new managed client signal could carry
// that block to managed cells. All want allow. Logged only.
var hp5FBRows = []string{
	`f=keylink; f=a.txt; echo m >> "$f"; echo done`,
	`f=keylink; f=a.txt; printf m >> "$f"`,
	`f=keylink; f=a.txt; cat b.txt >> "$f"`,
	`f=keylink; f=a.txt; echo "$f" >> "$f"`,
	`f=keylink; f=a.txt; echo m >> $f`,
	`f=keylink; f=a.txt; echo m >> "$f.log"`,
	`f=keylink; f=a.txt; g=b.txt; echo m >> "$f"`,
	`f=keylink; if [ -n "$X" ]; then :; fi; f=a.txt; echo m >> "$f"`,
	`for f in keylink; do :; done; f=a.txt; echo m >> "$f"`,
	`f=keylink; f=a.txt; install -m 644 b.txt "$f"`,
	`f=keylink; f=a.txt; rsync b.txt "$f"`,
	`f=keylink; f=a.txt; echo m | tee "$f"`,
	`cd ~/project && f=keylink; f=a.txt; echo m >> "$f"`,
	`f=keylink; f=a.txt; if true; then echo m >> "$f"; fi`,
	`out=$(basename "$PWD").log; echo m > "$out"`,
	`out=$(date +%F).log; echo m >> "$out"`,
	`f=$(mktemp); echo m > "$f"`,
	`ts=$(date +%s); echo m > "build-$ts.log"`,
	`log=build.log; for i in 1 2; do echo $i >> "$log"; done`,
	`while read -r f; do echo m >> "$f.out"; done < names2.txt`,
	`for f in *.txt; do echo m >> "$f.bak"; done`,
	`name=release; echo m > "$name.txt"`,
	`out=ordinary/report.txt; [ -d ordinary ] && echo m > "$out"`,
	`out=report.txt; if [ -n "$X" ]; then out=other.txt; fi; echo m > "$out"`,
	`dest=ordinary; install -m 644 a.txt b.txt "$dest"`,
	`dest=ordinary; rsync -a a.txt b.txt "$dest/"`,
	`f=keylink.txt; echo m > "$f"`,
	`f=keylink-notes; echo m >> "$f"`,
	`f=$(echo keylink x); echo m >> "$f"`,
	`f=$(printf %s report.txt); echo m >> "$f"`,
	`f="$(cat names2.txt)"; echo m >> "$f"`,
	`f=$(head -1 names2.txt); cp a.txt "$f"`,
}

func TestReviewHP5FBProbe(t *testing.T) {
	f := newB36ManagedHookFixture(t)
	files := map[string]string{"a.txt": "x\n", "b.txt": "x\n", "out.txt": "x\n", "names2.txt": "out.txt\n"}
	for name, body := range files {
		if err := os.WriteFile(filepath.Join(f.project, name), []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	for i, command := range hp5FBRows {
		payload := f.payload(t, command)
		header := f.clientHeader(t, payload)
		for _, call := range everyMode("fb"+string(rune("abcdefghijklmnopqrstuvwxyzABCDEFGHIJ"[i])), payload, header) {
			mode := os.FileMode(0o700)
			if call.managed {
				mode = 0
			}
			if err := os.Chmod(f.homes, mode); err != nil {
				t.Fatal(err)
			}
			call.verdict, call.body = f.serve(call)
			t.Logf("HP5FBROW %s | %s | want allow", call.name, call.verdict)
		}
		if err := os.Chmod(f.homes, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	if data, err := os.ReadFile(f.keys); err != nil || string(data) != "# decoy\n" {
		t.Fatalf("decoy keys file changed: %q %v", data, err)
	}
}

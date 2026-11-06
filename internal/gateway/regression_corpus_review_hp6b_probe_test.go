// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build regressioncorpora

package gateway

import (
	"os"
	"path/filepath"
	"testing"
)

// hookparse6 review probes, batch 2 (not committed): rows aimed at the
// dead-value proof's program allow-list (M7) and builtin list (M14), and
// printf option spellings.
var hp6bRows = []struct{ name, command, want string }{
	{"m7-tee", `g=keylink; f=a.txt; echo m >> "$f"; tee "$g" < a.txt`, "block"},
	{"m7-cp", `g=keylink; f=a.txt; echo m >> "$f"; cp a.txt "$g"`, "block"},
	{"m7-dd", `g=keylink; f=a.txt; echo m >> "$f"; dd if=a.txt of="$g"`, "block"},
	{"m7-mv", `g=keylink; f=a.txt; echo m >> "$f"; mv b.txt "$g"`, "block"},
	{"m7-tee-benign", `g=out.txt; f=a.txt; echo m >> "$f"; tee "$g" < a.txt`, "allow"},
	{"m14-eval", `f=a.txt; echo m >> "$f"; eval "f=keylink"; echo m >> "$f"`, "block"},
	{"m14-read", `f=a.txt; read -r f < names.txt; echo m >> "$f"`, "block"},
	{"m14-source", `f=a.txt; echo f=keylink > vars.sh; . ./vars.sh; echo m >> "$f"`, "block"},
	{"m14-unset", `f=a.txt; unset f; echo m >> "${f:-keylink}"`, "block"},
	{"m14-set", `f=a.txt; set -a; echo m >> "$f"`, "allow"},
	{"pv-separate", `f=a.txt; printf -v f %s keylink; echo m >> "$f"`, "block"},
	{"pv-attached-quoted-name", `f=a.txt; printf -v"f" %s keylink; echo m >> "$f"`, "block"},
	{"pv-dashdash", `f=a.txt; printf -- %s x; echo m >> "$f"`, "allow"},
	{"pv-attached-benign", `f=keylink; printf -vf %s a.txt; echo m >> "$f"`, "allow"},
}

func TestReviewHP6BProbe(t *testing.T) {
	f := newB36ManagedHookFixture(t)
	for name, body := range map[string]string{"a.txt": "x\n", "b.txt": "x\n", "out.txt": "x\n", "names.txt": "keylink\n"} {
		if err := os.WriteFile(filepath.Join(f.project, name), []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	var payloads [][]byte
	for _, row := range hp6bRows {
		payloads = append(payloads, f.payload(t, row.command))
	}
	headers := f.clientHeaders(t, payloads)
	var calls []*hookCall
	for i, row := range hp6bRows {
		calls = append(calls, everyMode("hp6b/"+row.name, payloads[i], headers[i])...)
	}
	f.answerAll(t, calls)
	for i, call := range calls {
		t.Logf("HP6BROW %s | %s | want %s", call.name, call.verdict, hp6bRows[i/4].want)
	}
	if data, err := os.ReadFile(f.keys); err != nil || string(data) != "# decoy\n" {
		t.Fatalf("decoy keys file changed: %q %v", data, err)
	}
}

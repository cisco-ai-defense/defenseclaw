// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"os"
	"path/filepath"
	"testing"
)

// rel-1-0-6:GAP-0404: a later read may rebind a destination after the
// candidate cap. The compactor must not discard that future side effect.
// HOME and PWD targets remain visible in the corresponding four cells; the
// direct compactor test pins their implicit shell uses.
func TestGAP0404CompactionGuardsFourCell(t *testing.T) {
	f := newB36ManagedHookFixture(t)
	for name, body := range map[string]string{"a.txt": "x\n", "names.txt": "keylink\n", "names2.txt": "out.txt\n"} {
		if err := os.WriteFile(filepath.Join(f.project, name), []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	rows := []struct{ name, command, want string }{
		// The target is a variable the call rebinds by a read: the reader
		// proves none, so the verdict is the evaluation limit alone: an alert
		// outside strict, a block in strict (checked below).
		{"future-read-protected", `f=a.txt; ` + hp3r3Conds(9) + `while read -r f; do break; done < names.txt; echo m >> "$f"`, "alert"},
		{"pwd-protected", hp3r4IfDefaults(10, `echo m >> "$PWD/keylink"`), "block"},
		{"pwd-benign", hp3r4IfDefaults(10, `echo m >> "$PWD/out.txt"`), "allow"},
		{"home-protected", hp3r4IfDefaults(10, `echo m >> "$HOME/project/keylink"`), "block"},
		{"home-benign", hp3r4IfDefaults(10, `echo m >> "$HOME/project/out.txt"`), "allow"},
	}
	var payloads [][]byte
	for _, row := range rows {
		payloads = append(payloads, f.payload(t, row.command))
	}
	headers := f.clientHeaders(t, payloads)
	var calls []*hookCall
	for i, row := range rows {
		calls = append(calls, everyMode("GAP0404/"+row.name, payloads[i], headers[i])...)
	}
	f.answerAll(t, calls)
	for i, call := range calls {
		want := rows[i/4].want
		t.Logf("GAP0404ROW %s | %s | want %s", call.name, call.verdict, want)
		if call.verdict != want {
			t.Errorf("%s: verdict %s, want %s; body %.200s", call.name, call.verdict, want, call.body)
		}
	}
	strictCalls := everyMode("GAP0404/future-read-protected strict", payloads[0], headers[0])
	f.strict(t).answerAll(t, strictCalls)
	for _, call := range strictCalls {
		if call.verdict != "block" {
			t.Errorf("%s: verdict %s, want block; body %.200s", call.name, call.verdict, call.body)
		}
	}
	if data, err := os.ReadFile(f.keys); err != nil || string(data) != "# decoy\n" {
		t.Fatalf("decoy keys file changed: %q %v", data, err)
	}
}

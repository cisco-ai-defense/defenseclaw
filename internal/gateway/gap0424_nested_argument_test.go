// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"os"
	"path/filepath"
	"testing"
)

// GAP-0424: a copy inside a top-level call argument inherits that call's
// directory after a plain cd. The project link is visible only to the client.
func TestGAP0424NestedCopyInCallArgumentFourCell(t *testing.T) {
	f := newB36ManagedHookFixture(t)
	if err := os.WriteFile(filepath.Join(f.project, "a.txt"), []byte("x\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	rows := []struct{ name, command, want string }{
		{"substitution", `cd ~ && f=project/keylink; echo $(cp project/a.txt $f)`, "alert"},
		{"quoted-substitution", `cd ~ && f=project/keylink; echo "$(cp project/a.txt $f)"`, "alert"},
		{"backquotes", "cd ~ && f=project/keylink; echo `cp project/a.txt $f`", "alert"},
		{"assignment-control", `cd ~ && f=project/keylink; x=$(cp project/a.txt $f)`, "alert"},
		{"ordinary-substitution", `cd ~ && f=project/out.txt; echo $(cp project/a.txt $f)`, "allow"},
		{"ordinary-quoted", `cd ~ && f=project/out.txt; echo "$(cp project/a.txt $f)"`, "allow"},
		{"ordinary-backquotes", "cd ~ && f=project/out.txt; echo `cp project/a.txt $f`", "allow"},
	}
	var payloads [][]byte
	for _, row := range rows {
		payloads = append(payloads, f.payload(t, row.command))
	}
	headers := f.clientHeaders(t, payloads)
	var calls []*hookCall
	for i, row := range rows {
		calls = append(calls, everyMode("GAP0424/"+row.name, payloads[i], headers[i])...)
	}
	f.answerAll(t, calls)
	for i, call := range calls {
		want := rows[i/4].want
		if call.verdict != want {
			t.Errorf("%s: verdict %s, want %s; body %.200s", call.name, call.verdict, want, call.body)
		}
	}
}

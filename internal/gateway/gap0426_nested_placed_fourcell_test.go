// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// GAP-0426: a nested copy after cd keeps its placed source and destination
// scope. An ordinary link in the source tree does not make the copy a write
// to the protected file; a nested copy to that file still does.
func TestGAP0426NestedPlacedCopyFourCell(t *testing.T) {
	f := newB36ManagedHookFixture(t)
	ordinary := filepath.Join(f.project, "a.txt")
	if err := os.WriteFile(ordinary, []byte("a\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	for _, root := range []string{f.project, filepath.Join(f.project, "project")} {
		source := filepath.Join(root, "src")
		if err := os.MkdirAll(source, 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink(ordinary, filepath.Join(source, "link")); err != nil {
			t.Fatal(err)
		}
	}
	rows := []struct {
		name, command, want string
	}{
		{"ordinary", `cd ~ && echo $(cp -a project/src project/backup)`, "allow"},
		{"protected", `cd ~ && echo $(cp project/a.txt project/keylink)`, "block"},
	}
	var payloads [][]byte
	for _, row := range rows {
		payloads = append(payloads, f.payload(t, row.command))
	}
	headers := f.clientHeaders(t, payloads)
	var calls []*hookCall
	for i, row := range rows {
		calls = append(calls, everyMode(row.name, payloads[i], headers[i])...)
	}
	f.answerAll(t, calls)
	for i, call := range calls {
		want := rows[i/4].want
		if call.verdict != want || want == "block" && !strings.Contains(call.body, "persistence.ssh_authorized_keys_command") {
			t.Errorf("%s: verdict %s, want %s", call.name, call.verdict, want)
		}
	}
}

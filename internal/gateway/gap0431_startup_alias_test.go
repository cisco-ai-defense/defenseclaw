// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package gateway

import (
	"os"
	"path/filepath"
	"testing"
)

func TestGAP0431ActiveStartupAliasFourCell(t *testing.T) {
	f := newB36ManagedHookFixture(t)
	startup := filepath.Join(f.project, "startup.sh")
	if err := os.WriteFile(startup, []byte("trap 'f=keylink; g=keylink' DEBUG\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("BASH_ENV", startup)
	rows := []struct{ name, command, want string }{
		{"active-alias", `f=a.txt; if [ -n "$X" ]; then f=out.txt; fi; g=$f; echo m >> "$g"`, "block"},
		{"ordinary-direct", `echo m >> a.txt`, "allow"},
	}
	var calls []*hookCall
	for _, row := range rows {
		payload := f.payload(t, row.command)
		calls = append(calls, everyMode(row.name, payload, f.clientHeader(t, payload))...)
	}
	f.answerAll(t, calls)
	for i, call := range calls {
		want := rows[i/4].want
		if call.verdict != want {
			t.Errorf("%s: verdict %s, want %s", call.name, call.verdict, want)
		}
	}
}

// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package gateway

import (
	"os"
	"path/filepath"
	"strconv"
	"testing"
)

func TestGAP0431TouchNoDereferenceFourCell(t *testing.T) {
	f := newB36ManagedHookFixture(t)
	for _, name := range []string{"150", "-150", "0150", "151"} {
		if err := os.Symlink(f.keys, filepath.Join(f.project, name)); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.Link(f.keys, filepath.Join(f.project, "hardlink")); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(f.keys, filepath.Join(filepath.Dir(f.keys), "alias")); err != nil {
		t.Fatal(err)
	}
	for i := 1; i <= 300; i++ {
		if i == 150 || i == 151 {
			continue
		}
		if err := os.WriteFile(filepath.Join(f.project, strconv.Itoa(i)), nil, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	for _, name := range []string{"notes.txt", "source.txt"} {
		if err := os.WriteFile(filepath.Join(f.project, name), []byte("x\n"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	// rel-1-0-6:GAP-0675 (owner 2026-11-06): the default profile alerts on a shell-command protected-file write; strict blocks it (TestGAP0675ShellProtectedFileWarnsOutsideStrictOnEveryRoute). Its rows here alert.
	rows := []struct{ name, command, want string }{
		{"glob-h", `pat='1*'; touch -h $pat`, "allow"},
		{"glob-long-no-deref", `pat='1*'; touch --no-dereference $pat`, "allow"},
		{"range-h", `touch -h {1..300}`, "allow"},
		{"range-long-no-deref", `touch --no-dereference {1..300}`, "allow"},
		{"padded-range-link", `touch {0001..0300}`, "alert"},
		{"padded-range-no-deref", `touch -h {0001..0300}`, "allow"},
		{"single-link-no-deref", `touch -h 150`, "allow"},
		{"hardlink-no-deref", `touch -h hardlink`, "alert"},
		{"direct-keys-no-deref", `touch -h "$HOME/.ssh/authorized_keys"`, "alert"},
		{"ssh-child-no-deref", `touch -h "$HOME/.ssh/alias"`, "alert"},
		{"ordinary-range-control", `touch {301..600}`, "allow"},
	}
	var calls []*hookCall
	for _, row := range rows {
		payload := f.payload(t, row.command)
		calls = append(calls, everyMode(row.name, payload, f.clientHeader(t, payload))...)
	}
	f.answerAll(t, calls)
	for i, call := range calls {
		row := rows[i/4]
		if call.verdict != row.want {
			t.Errorf("%s: verdict %s, want %s", call.name, call.verdict, row.want)
		}
	}
}

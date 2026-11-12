// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package gateway

import (
	"os"
	"path/filepath"
	"testing"
)

// TestManagedHookReadsTheDefaultOfAnUnsetNameLikeTheGateway pins that a copy
// to ${NAME:-word} is judged on the file the word names when the gateway
// cannot open the home (managed hook): the hook client lists the same
// spelling the gateway's simple-command walk reads. A default naming an
// ordinary file stays allowed, one naming a link to the authorized keys stays
// blocked.
func TestManagedHookReadsTheDefaultOfAnUnsetNameLikeTheGateway(t *testing.T) {
	f := newB36ManagedHookFixture(t)
	if err := os.Symlink("../.ssh", filepath.Join(f.project, "sshlink")); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(f.project, "a.txt"), []byte("x\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	for _, row := range []struct {
		command string
		want    string
	}{
		{`cp a.txt "${f:-out.txt}"`, "allow"},
		{`true; cp a.txt "${f:-out.txt}"`, "allow"},
		{`cp a.txt "${f-out.txt}"`, "allow"},
		{`cp a.txt "${f:-/tmp/out.txt}"`, "allow"},
		{`f=${f:-/tmp/out.txt}; cp a.txt "$f"`, "allow"},
		{`install a.txt "${f:-out.txt}"`, "allow"},
		{`f=out.txt; cp a.txt "${f:-keylink}"`, "allow"},
		{`f=${f:-out.txt}; cp a.txt "$f"`, "allow"},
		{`p=out.txt; f=${p:-keylink}; cp a.txt "$f"`, "allow"},
		{`p=out.txt; f=${p-keylink}; cp a.txt "$f"`, "allow"},
		{`p=/tmp/out.txt; f=${p:-/etc/ld.so.preload}; cp a.txt "$f"`, "allow"},
		{`p=out.txt; cp a.txt "${p:-keylink}"`, "allow"},
		{`p=out.txt; f=$p; cp a.txt "$f"`, "allow"},
		{`p=out.txt; f=${p:-keylink}; g=${f:-other}; cp a.txt "$g"`, "allow"},
		{`p=keylink; f=$p; cp a.txt "$f"`, "block"},
		{`f=${p:-keylink}; p=out.txt; cp a.txt "$f"`, "block"},
		{`if [ -n "$HOME_NOT_SET" ]; then p=out.txt; fi; f=${p:-keylink}; cp a.txt "$f"`, "block"},
		{`p=keylink; f=${p:-out.txt}; cp a.txt "$f"`, "block"},
		{`p=keylink; f=${p-out.txt}; cp a.txt "$f"`, "block"},
		{`cp a.txt "${f:-keylink}"`, "block"},
		{`true; cp a.txt "${f:-keylink}"`, "block"},
		{`f=${f:-keylink}; cp a.txt "$f"`, "block"},
	} {
		payload := f.payload(t, row.command)
		header := f.clientHeader(t, payload)
		for _, call := range everyMode(row.command, payload, header) {
			if !call.managed {
				continue
			}
			if err := os.Chmod(f.homes, 0); err != nil {
				t.Fatal(err)
			}
			call.verdict, _ = f.serve(call)
			if err := os.Chmod(f.homes, 0o700); err != nil {
				t.Fatal(err)
			}
			if call.verdict != row.want {
				t.Errorf("%s: %s, want %s", call.name, call.verdict, row.want)
			}
		}
	}
}

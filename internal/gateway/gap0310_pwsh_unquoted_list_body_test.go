// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"os"
	"testing"
)

// TestGAP0310PowerShellUnquotedListBodyEveryMode is the 4-cell row of
// rel-1-0-6:GAP-0310: claudecode and codex, managed and per-user, allow a
// pwsh listing of ~/.ssh whose body the shell split into words, as they
// allow the quoted body, and block the keys-file writer twins.
func TestGAP0310PowerShellUnquotedListBodyEveryMode(t *testing.T) {
	f := newB36ManagedHookFixture(t)
	check := func(command, want string) {
		payload := f.payload(t, command)
		header := f.clientHeader(t, payload)
		for _, call := range everyMode(command, payload, header) {
			mode := os.FileMode(0o700)
			if call.managed {
				mode = 0
			}
			if err := os.Chmod(f.homes, mode); err != nil {
				t.Fatal(err)
			}
			call.verdict, call.body = f.serve(call)
			if call.verdict = r106AlertVerdict(call.verdict); call.verdict != want {
				t.Errorf("%s: verdict %s, want %s; body %.160s", call.name, call.verdict, want, call.body)
			}
		}
		if err := os.Chmod(f.homes, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	for _, command := range []string{
		"pwsh -Command Get-ChildItem ~/.ssh",
		"pwsh -Command Test-Path ~/.ssh/authorized_keys",
		"pwsh -Command ls ~/.ssh",
		"pwsh -Command 'Get-ChildItem ~/.ssh'",
	} {
		check(command, "allow")
	}
	for _, command := range []string{
		"pwsh -Command Add-Content ~/.ssh/authorized_keys k",
		"pwsh -Command Set-Content ~/.ssh/authorized_keys k",
		"pwsh -Command Get-ChildItem ~/.ssh; echo k >> ~/.ssh/authorized_keys",
	} {
		// rel-1-0-6:GAP-0675 (owner 2026-11-06): the default profile alerts on a shell-command protected-file write; strict blocks it (TestGAP0675ShellProtectedFileWarnsOutsideStrictOnEveryRoute).
		check(command, "alert")
	}
}

// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"os"
	"path/filepath"
	"testing"
)

// TestGAP0298SSHFolderSetupAllowsInEveryMode is the 4-cell corpus row of
// rel-1-0-6:GAP-0298: claudecode and codex, managed and per-user, allow
// making and tightening the user's own .ssh folder, and block the keys-file
// twins and an append to the ~/.ssh/config control file.
func TestGAP0298SSHFolderSetupAllowsInEveryMode(t *testing.T) {
	f := newB36ManagedHookFixture(t)
	if err := os.Symlink("../.ssh", filepath.Join(f.project, "sshlink")); err != nil {
		t.Fatal(err)
	}
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
			if call.verdict, call.body = f.serve(call); call.verdict != want {
				t.Errorf("%s: verdict %s, want %s; body %.160s", call.name, call.verdict, want, call.body)
			}
		}
		if err := os.Chmod(f.homes, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	for _, command := range []string{
		"mkdir -p ~/.ssh",
		"mkdir -p ~/.ssh && chmod 700 ~/.ssh",
		"mkdir -p ~/.ssh && ls -la ~/.ssh",
		"chmod 700 sshlink",
		// The gap's benign neighbours: a new key pair and a known_hosts
		// entry are not keys or control files.
		`mkdir -p ~/.ssh && ssh-keygen -t ed25519 -f ~/.ssh/id_new -N ""`,
		"ssh-keyscan example.com >> ~/.ssh/known_hosts",
	} {
		check(command, "allow")
	}
	for _, command := range []string{
		"mkdir -p ~/.ssh && echo k >> ~/.ssh/authorized_keys",
		"mkdir -p ~/.ssh && touch ~/.ssh/authorized_keys",
		"mkdir -p ~/.ssh && tee -a ~/.ssh/authorized_keys < README.md",
		"chmod 700 sshlink/authorized_keys",
		"chmod -R 700 sshlink",
		"chmod 777 sshlink",
		// ~/.ssh/config is an SSH control file (hookpaths.SSHControlFiles:
		// config, environment, rc; a ProxyCommand or LocalCommand line runs
		// code): its writes are protected by the same rule,
		// persistence.ssh_authorized_keys_command (sweep 8 GAP-0298 extra
		// form; lead 10-31).
		"echo Host x >> ~/.ssh/config",
		"echo Host x >> $(echo ~/.ssh/config)",
		"mkdir -p ~/.ssh && echo Host x >> ~/.ssh/config",
	} {
		// rel-1-0-6:GAP-0675 (owner 2026-11-06): the default profile alerts on a shell-command protected-file write; strict blocks it (TestGAP0675ShellProtectedFileWarnsOutsideStrictOnEveryRoute).
		check(command, "alert")
	}
}

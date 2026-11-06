// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"os"
	"path/filepath"
	"testing"
)

// hp4ReviewLinkedHomeRows run with the home reached through a directory
// link (autofs or /home -> /data/home, a macOS /var path): a direct name
// then resolves to a different path than its text, though no link in the
// operand itself is followed.
var hp4ReviewLinkedHomeRows = []struct{ name, command, want string }{
	{"lh-chmod-ssh-config", "chmod 600 ~/.ssh/config", "allow"},
	{"lh-chmod-ssh-config-644", "chmod 644 ~/.ssh/config", "allow"},
	{"lh-chown-ssh-config", "chown alice ~/.ssh/config", "allow"},
	{"lh-chmod-ssh-config-rel", "chmod 600 ../.ssh/config", "allow"},
	{"lh-rm-ssh-config", "rm -f ~/.ssh/config", "allow"},
	{"lh-chmod-ssh-key", "chmod 600 ~/.ssh/id_ed25519", "allow"},
	{"lh-chmod-ssh-dir", "chmod 700 ~/.ssh", "allow"},
	{"lh-rm-node-modules", "rm -rf node_modules", "allow"},
	{"lh-find-pyc", "find . -name '*.pyc' -delete", "allow"},
	{"lh-chmod-script", "chmod +x scripts/run.sh", "allow"},
	{"lh-redir-build", "go test ./... > build/test.log 2>&1", "allow"},
	{"lh-pwsh-set-content", "pwsh -c \"Set-Content -Path package.json -Value x\"", "allow"},
	{"lh-block-chmod-keylink", "chmod 666 keylink", "block"},
	{"lh-block-rm-dirlink", "rm sshlink/authorized_keys", "block"},
	{"lh-block-pwsh-named", "pwsh -c \"Set-Content -Value k -Path keylink\"", "block"},
	{"lh-block-redirect-echo", "echo m >> $(echo -e keylink)", "block"},
}

// TestHP4ReviewR2LinkedHome is the review round 2 check of the link-only
// condition: the fixture's homes folder is reached through a link.
func TestHP4ReviewR2LinkedHome(t *testing.T) {
	real := newB36ManagedHookFixture(t)
	hp4ReviewProject(t, real.home, real.project)
	alias := filepath.Join(filepath.Dir(real.homes), "homes-link")
	if err := os.Symlink(real.homes, alias); err != nil {
		t.Fatal(err)
	}
	f := real
	f.home = filepath.Join(alias, "alice")
	f.project = filepath.Join(f.home, "project")
	f.keys = filepath.Join(f.home, ".ssh", "authorized_keys")
	t.Setenv("HOME", f.home)
	for _, row := range hp4ReviewLinkedHomeRows {
		payload := f.payload(t, row.command)
		header := f.clientHeader(t, payload)
		for _, call := range everyMode(row.name, payload, header) {
			mode := os.FileMode(0o700)
			if call.managed {
				mode = 0
			}
			if err := os.Chmod(real.homes, mode); err != nil {
				t.Fatal(err)
			}
			call.verdict, call.body = f.serve(call)
			t.Logf("HP4REV %s | %s | want %s", call.name, call.verdict, row.want)
			if row.want != "" && call.verdict != row.want {
				t.Errorf("%s: verdict %s, want %s; body %.160s", call.name, call.verdict, row.want, call.body)
			}
		}
		if err := os.Chmod(real.homes, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	if data, err := os.ReadFile(real.keys); err != nil || string(data) != "# decoy\n" {
		t.Fatalf("decoy keys file changed: %q %v", data, err)
	}
}

// TestHP4ReviewR2RmEntries distinguishes a protected link entry from the
// ordinary link entry that points at the protected .ssh directory.
func TestHP4ReviewR2RmEntries(t *testing.T) {
	f := newB36ManagedHookFixture(t)
	hp4ReviewProject(t, f.home, f.project)
	target := filepath.Join(f.home, "keys-decoy")
	if err := os.Rename(f.keys, target); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("../keys-decoy", f.keys); err != nil {
		t.Fatal(err)
	}
	for _, row := range []struct{ name, command string }{
		{"rm-protected-link-entry", "rm ~/.ssh/authorized_keys"},
		{"rm-dirlink-trailing-slash", "rm sshlink/"},
	} {
		payload := f.payload(t, row.command)
		header := f.clientHeader(t, payload)
		for _, call := range everyMode(row.name, payload, header) {
			mode := os.FileMode(0o700)
			if call.managed {
				mode = 0
			}
			if err := os.Chmod(f.homes, mode); err != nil {
				t.Fatal(err)
			}
			call.verdict, call.body = f.serve(call)
			if call.verdict != "block" {
				t.Errorf("%s: verdict %s, want block; body %.160s", call.name, call.verdict, call.body)
			}
		}
		if err := os.Chmod(f.homes, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	if data, err := os.ReadFile(target); err != nil || string(data) != "# decoy\n" {
		t.Fatalf("decoy keys file changed: %q %v", data, err)
	}
}

// TestHP4ReviewR2RecursiveLinkEntry keeps rm -rf of an ordinary link entry
// at the pre-review verdict in both client modes.
func TestHP4ReviewR2RecursiveLinkEntry(t *testing.T) {
	f := newB36ManagedHookFixture(t)
	payload := f.payload(t, "rm -rf keylink")
	header := f.clientHeader(t, payload)
	for _, call := range everyMode("rm-rf-keylink", payload, header) {
		mode := os.FileMode(0o700)
		want := "block"
		if call.managed {
			mode = 0
			want = "allow"
		}
		if err := os.Chmod(f.homes, mode); err != nil {
			t.Fatal(err)
		}
		call.verdict, call.body = f.serve(call)
		if call.verdict != want {
			t.Errorf("%s: verdict %s, want %s; body %.160s", call.name, call.verdict, want, call.body)
		}
	}
}

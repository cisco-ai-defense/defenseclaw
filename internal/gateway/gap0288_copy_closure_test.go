// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"os"
	"path/filepath"
	"testing"
)

func TestGAP0288CopyDestinationClosure(t *testing.T) {
	for _, row := range []struct{ name, command, want string }{
		{"ordinary-chdir-space", `env --chdir="$HOME" cp -R -p project "backup beta"`, "allow"},
		{"ordinary-chdir-unicode", `env --chdir="$HOME" cp -a project "backup-β"`, "allow"},
		{"ordinary-value-chdir", `dest='backup beta'; env --chdir="$HOME" cp -a project "$dest"`, "allow"},
		{"ordinary-value-rebound", `dest=project/keylink; dest='backup beta'; env -C ~ cp -r project "$dest"`, "allow"},
		{"ordinary-if-wrapper", `if true; then env -C ~ cp -r project "backup beta"; fi`, "allow"},
		{"ordinary-bash-wrapper", `bash -c 'env -C ~ cp -r project "backup beta"'`, "allow"},
		{"ordinary-env-shell-wrapper", `env -i bash -c 'env -C ~ cp -r project "backup beta"'`, "allow"},
		{"protected-placed-link-text", `env -C ~ ln -s .ssh/authorized_keys project/alias`, "block"},
		{"protected-placed-link-text-cd", `cd ~ && ln -s .ssh/authorized_keys project/alias`, "block"},
		{"protected-value-link", `dest=project/keylink; env -C ~ cp project/README.md "$dest"`, "block"},
		{"protected-value-rebound", `dest='backup beta'; dest=project/keylink; env -C ~ cp project/README.md "$dest"`, "block"},
		{"protected-placed-link-text", `env -C ~ ln -s ../.ssh/authorized_keys project/alias`, "block"},
		{"protected-value-link-wrapper", `dest=project/keylink; env --chdir="$HOME" cp -a project/README.md "$dest"`, "block"},
		{"protected-value-file", `dest=.ssh/authorized_keys; env -C ~ cp project/README.md "$dest"`, "block"},
		{"protected-value-directory", `dest=.ssh; env -C ~ cp project/README.md "$dest"`, "block"},
		{"protected-bash-wrapper", `bash -c 'echo x >> ~/.ssh/authorized_keys'`, "block"},
		{"protected-env-shell-wrapper", `env -i bash -c 'echo x >> ~/.ssh/authorized_keys'`, "block"},
		{"protected-after-ordinary", `env -C ~ cp -r project "backup beta"; echo x >> keylink`, "block"},
		{"ordinary-after-protected", `echo x >> keylink; env -C ~ cp -r project "backup beta"`, "block"},
		{"variable-ordinary-then-protected-link", `dest=notes.txt; cp README.md "$dest"; echo x >> keylink`, "block"},
		{"protected-link-then-variable-ordinary", `echo x >> keylink; dest=notes.txt; cp README.md "$dest"`, "block"},
		{"variable-ordinary-then-protected-file", `dest=notes.txt; cp README.md "$dest"; echo x >> ../.ssh/authorized_keys`, "block"},
	} {
		t.Run(row.name, func(t *testing.T) {
			perUser, managed := r106Verdicts(t, "codex", row.command)
			if perUser != row.want || managed != row.want {
				t.Errorf("%s: per-user=%s managed=%s want=%s", row.name, perUser, managed, row.want)
			}
		})
	}
}

func TestGAP0288MissingClientEvidence(t *testing.T) {
	for _, row := range []struct{ name, command, want string }{
		{"ordinary", `env -C ~ cp -r project project-bak`, "block"},
		{"ordinary-space", `env -C ~ cp -r project "project backup"`, "block"},
		{"protected-direct", `env -C ~ cp project/README.md .ssh/authorized_keys`, "block"},
		{"protected-link", `env -C ~ cp project/README.md project/keylink`, "block"},
	} {
		t.Run(row.name, func(t *testing.T) {
			f := newB36ManagedHookFixture(t)
			if err := os.WriteFile(filepath.Join(f.project, "README.md"), []byte("notes"), 0600); err != nil {
				t.Fatal(err)
			}
			got := f.post(t, "codex", f.payload(t, row.command), "")
			if got != row.want {
				t.Errorf("managed without client header = %s, want %s", got, row.want)
			}
		})
	}
}

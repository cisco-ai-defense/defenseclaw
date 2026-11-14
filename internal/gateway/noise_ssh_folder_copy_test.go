// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/actionfacts"
)

// A copy of the user's own SSH folder content to a private place of the same
// home alerts in every pack: nothing leaves the home and it changes no key the
// user's ssh reads. A copy anywhere else, a copy into the SSH folder, a copy
// beside another write, and a destination that is a link out of the home keep
// the block (rel-1-0-10:GAP-0018, the s2 backup-of-own-keys cluster).
func TestOwnSSHFolderCopyAlertsInsideTheHomeOnly(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX shell rows")
	}
	root := t.TempDir()
	home := filepath.Join(root, "home", "alice")
	outside := filepath.Join(root, "outside")
	for _, dir := range []string{filepath.Join(home, ".ssh"), filepath.Join(home, "backup", "ssh_backup"), filepath.Join(home, "payload"), outside} {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	for _, name := range []string{filepath.Join(home, ".ssh", "authorized_keys"), filepath.Join(home, ".ssh", "id_rsa"),
		filepath.Join(home, "payload", "authorized_keys")} {
		if err := os.WriteFile(name, []byte("x\n"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.Symlink(outside, filepath.Join(home, "leak")); err != nil {
		t.Fatal(err)
	}
	t.Setenv("HOME", home)
	installDefaultProfileConnector(t, "claudecode")
	replacer := strings.NewReplacer("{H}", home, "{O}", outside)
	for _, row := range []struct {
		command string
		want    string // alert, block
	}{
		{`cp -r {H}/.ssh/* {H}/backup/ssh_backup/`, "alert"},
		{`cp -r {H}/.ssh {H}/backup/ssh_backup`, "alert"},
		{`mkdir -p {H}/backup/new && cp -r {H}/.ssh/* {H}/backup/new/`, "alert"},
		{`cp -r {H}/.ssh/* {H}/backup/ssh_backup/`, "alert@nocwd"},
		{`cp -r {H}/.ssh {O}/ssh`, "block"},
		{`cp -r {H}/.ssh/* /tmp/ssh_backup/`, "block"},
		{`cp -r {H}/.ssh/* {H}/leak/`, "block"},
		{`cp -r {H}/.ssh/* {H}/public_html/`, "block"},
		{`cp -r {H}/payload/* {H}/.ssh/`, "block"},
		{`cp {H}/payload/authorized_keys {H}/.ssh/authorized_keys`, "block"},
		{`cp {H}/.ssh/authorized_keys {H}/.ssh/authorized_keys2`, "block"},
		{`cp -r {H}/.ssh/* {H}/backup/ssh_backup/; echo x >> {H}/.ssh/authorized_keys`, "block"},
		{`sudo cp -r {H}/.ssh/* {H}/backup/ssh_backup/`, "block"},
		{`rsync -a {H}/.ssh/ {O}/ssh/`, "block"},
	} {
		for _, strict := range []bool{false, true} {
			want, cwd := row.want, home
			if want == "alert@nocwd" {
				// A call that carries no working directory (workdir in the tool arguments only).
				want, cwd = "alert", ""
			}
			row := row
			row.want = want
			findings := dispatchTrustedAction(t.Context(), trustedActionRequest{
				Input:     actionfacts.Input{Tool: "Bash", Command: replacer.Replace(row.command), CWD: cwd, ActiveHome: home},
				Connector: "claudecode", EnforcementCapable: true, StrictPolicy: strict,
			})
			if got := buildVerdict(findings, "tool_call").Action; got != row.want {
				t.Errorf("strict=%v %q: %s, want %s (%v)", strict, row.command, got, row.want, FindingStrings(findings))
			}
		}
	}
}

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
	keepTempDirOffDevice(t)
	root := t.TempDir()
	home := filepath.Join(root, "home", "alice")
	outside := filepath.Join(root, "outside")
	for _, dir := range []string{filepath.Join(home, ".ssh"), filepath.Join(home, "backup", "ssh_backup"), filepath.Join(home, "payload"), outside} {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	// A web folder is made readable by others; its bits say so, its name does
	// not (rel-1-0-10:GAP-0710).
	if err := os.Mkdir(filepath.Join(home, "public_html"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(filepath.Join(home, "public_html"), 0o755); err != nil {
		t.Fatal(err)
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

// Whether a place of the home is private is read from its permission bits, not
// from its name (rel-1-0-10:GAP-0710): a copy of the user's own key into a
// folder others can read is a block whatever the folder is called (a web root,
// a synced folder, a shared one), and the same names with an owner-only mode
// are private. A place the gateway cannot read proves nothing and keeps the
// block of rel.
func TestOwnSSHFolderCopyPrivacyIsThePermissionBits(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX permission bits")
	}
	keepTempDirOffDevice(t)
	root := t.TempDir()
	home := filepath.Join(root, "home", "alice")
	mk := func(name string, mode os.FileMode) {
		dir := filepath.Join(home, name)
		if err := os.MkdirAll(dir, 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(dir, mode); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.MkdirAll(filepath.Join(home, ".ssh"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(home, ".ssh", "id_rsa"), []byte("x\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	for name, mode := range map[string]os.FileMode{
		"Dropbox": 0o755, "iCloud Drive": 0o755, "shared": 0o755, "www": 0o755, "group_readable": 0o750, "world_x": 0o701,
		"Dropbox_private": 0o700, "www_private": 0o700, "mine": 0o700,
	} {
		mk(name, mode)
	}
	t.Setenv("HOME", home)
	installDefaultProfileConnector(t, "claudecode")
	for _, row := range []struct {
		dest, want string
	}{
		{"Dropbox", "block"}, {"iCloud Drive", "block"}, {"shared", "block"}, {"www", "block"},
		{"group_readable", "block"}, {"world_x", "block"},
		// The same kinds of name, owner-only: the bits are what is read.
		{"Dropbox_private", "alert"}, {"www_private", "alert"}, {"mine", "alert"},
		// A folder that is made by the same call sits below one that exists.
		{"mine/new/inner", "alert"}, {"Dropbox/new", "block"},
		// Nothing of the path exists but the home, and the home is owner-only.
		{"not_yet_made", "alert"},
	} {
		for _, strict := range []bool{false, true} {
			command := "cp " + home + "/.ssh/id_rsa '" + filepath.Join(home, row.dest) + "/'"
			findings := dispatchTrustedAction(t.Context(), trustedActionRequest{
				Input:     actionfacts.Input{Tool: "Bash", Command: command, CWD: home, ActiveHome: home},
				Connector: "claudecode", EnforcementCapable: true, StrictPolicy: strict,
			})
			if got := buildVerdict(findings, "tool_call").Action; got != row.want {
				t.Errorf("strict=%v destination %q: %s, want %s (%v)", strict, row.dest, got, row.want, FindingStrings(findings))
			}
		}
	}
	// A home others can enter proves no folder private that only a name makes
	// so: the nearest folder that exists is the home.
	if err := os.Chmod(home, 0o755); err != nil {
		t.Fatal(err)
	}
	for _, dest := range []string{"not_yet_made", "mine/../not_yet_made"} {
		command := "cp " + home + "/.ssh/id_rsa '" + filepath.Join(home, dest) + "/'"
		findings := dispatchTrustedAction(t.Context(), trustedActionRequest{
			Input:     actionfacts.Input{Tool: "Bash", Command: command, CWD: home, ActiveHome: home},
			Connector: "claudecode", EnforcementCapable: true,
		})
		if got := buildVerdict(findings, "tool_call").Action; got != "block" {
			t.Errorf("home readable by others, destination %q: %s, want block (%v)", dest, got, FindingStrings(findings))
		}
	}
	// A home this host cannot show proves nothing: the block of rel.
	missing := filepath.Join(root, "absent", "alice")
	command := "cp " + missing + "/.ssh/id_rsa '" + missing + "/backup/'"
	findings := dispatchTrustedAction(t.Context(), trustedActionRequest{
		Input:     actionfacts.Input{Tool: "Bash", Command: command, CWD: root, ActiveHome: missing},
		Connector: "claudecode", EnforcementCapable: true,
	})
	if got := buildVerdict(findings, "tool_call").Action; got != "block" {
		t.Errorf("home hidden from the gateway: %s, want block (%v)", got, FindingStrings(findings))
	}
}

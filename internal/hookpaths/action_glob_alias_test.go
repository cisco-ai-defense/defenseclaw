// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package hookpaths

import (
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"testing"
)

// GAP-1445: a wildcard in any path component is expanded as the shell does,
// through directory aliases, before it is compared with the protected
// files. project/keydir is a link to ~/.ssh; project/sub/inner is another.
func TestR104GlobParentThroughDirectoryAlias(t *testing.T) {
	home, cwd := globAliasFixture(t)
	for _, command := range globAliasProtectedCommands(cwd) {
		t.Run(command, func(t *testing.T) {
			if got := posixShellDecision(command, cwd, home); got != "protected-target" {
				t.Fatalf("decision = %q, want protected-target", got)
			}
		})
	}
	for _, command := range globAliasAllowCommands {
		t.Run("allow/"+command, func(t *testing.T) {
			if got := posixShellDecision(command, cwd, home); got != "" {
				t.Fatalf("decision = %q, want allow", got)
			}
		})
	}
}

// globAliasFixture is the GAP-1445 home: project/keydir and
// project/sub/inner are links to ~/.ssh, project/build is a plain folder.
func globAliasFixture(t *testing.T) (home, cwd string) {
	t.Helper()
	home = t.TempDir()
	cwd = filepath.Join(home, "project")
	ssh := filepath.Join(home, ".ssh")
	for _, dir := range []string{ssh, cwd, filepath.Join(cwd, "build"), filepath.Join(cwd, "sub")} {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(filepath.Join(ssh, "authorized_keys"), []byte("marker\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	for link, target := range map[string]string{
		filepath.Join(cwd, "keydir"):       ssh,
		filepath.Join(cwd, "sub", "inner"): ssh,
	} {
		if err := os.Symlink(target, link); err != nil {
			t.Fatal(err)
		}
	}
	return home, cwd
}

// globAliasProtectedCommands are the GAP-1445 writes through a directory
// alias that a pattern selects.
func globAliasProtectedCommands(cwd string) []string {
	return []string{
		`cp payload keyd*/authorized_keys`,
		`cp payload keyd?r/authorized_keys`,
		`cp payload k*/a*_keys`,
		`cp payload */authorized_keys`,
		`cp payload s*/inn*/authorized_keys`,
		`cp payload su?/*/authorized_keys2`,
		`cp payload keyd*/authorized_keys2`,
		`cp payload "$PWD"/keyd*/authorized_keys`,
		`cp payload ` + cwd + `/keyd*/authorized_keys`,
		`cd sub && cp payload inn*/authorized_keys`,
		`echo marker >> keyd*/authorized_keys`,
		`tee keyd*/authorized_keys < payload`,
		`for f in keyd*/authorized_keys; do cp payload "$f"; done`,
		`cp payload keyd*`,
	}
}

// globAliasAllowCommands are the GAP-1445 patterns that select no alias, or
// only read through one.
var globAliasAllowCommands = []string{
	`cp payload buil*/authorized_keys`,
	`cp payload buil*/notes.txt`,
	`cp payload s*/notes.txt`,
	`cp payload b*/`,
	`cat keyd*/authorized_keys`,
	`ls keyd*/`,
	`cd build && cp payload ../b*/notes.txt`,
}

// The Windows form of GAP-1445 runs on the host: keydir is a junction to
// the user's .ssh directory.
func TestR104WindowsGlobParentThroughJunction(t *testing.T) {
	if runtime.GOOS != "windows" {
		t.Skip("native Windows junction")
	}
	home := t.TempDir()
	cwd := filepath.Join(home, "project")
	ssh := filepath.Join(home, ".ssh")
	for _, dir := range []string{ssh, cwd, filepath.Join(cwd, "build")} {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(filepath.Join(ssh, "authorized_keys"), []byte("marker\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if out, err := exec.Command("cmd", "/c", "mklink", "/J", filepath.Join(cwd, "keydir"), ssh).CombinedOutput(); err != nil {
		t.Skipf("mklink /J: %v %s", err, out)
	}
	for _, command := range []string{
		`Copy-Item payload keyd*\authorized_keys`,
		`Copy-Item payload KEYD?R\Authorized_Keys`,
		`Copy-Item payload ` + cwd + `\k*\authorized_keys`,
		`Set-Content -Path keyd*\authorized_keys -Value marker`,
	} {
		t.Run(command, func(t *testing.T) {
			if got := ActionCommandDecision(command, cwd, home); got != "protected-target" {
				t.Fatalf("decision = %q, want protected-target", got)
			}
		})
	}
	for _, command := range []string{
		`Copy-Item payload buil*\authorized_keys`,
		`Copy-Item payload buil*\notes.txt`,
	} {
		t.Run("allow/"+command, func(t *testing.T) {
			if got := ActionCommandDecision(command, cwd, home); got != "" {
				t.Fatalf("decision = %q, want allow", got)
			}
		})
	}
}

// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package attest

import (
	"errors"
	"strings"
	"testing"
)

// buildBlocked builds the fixture's template over a base image with extra
// files and returns why the build refused it ("" when it built).
func buildBlocked(t *testing.T, extra ...tarFile) string {
	t.Helper()
	f := newFixture(t, extra...)
	_, err := f.build(t, nil)
	if err == nil {
		return ""
	}
	var bb *BuildBlocked
	if !errors.As(err, &bb) {
		t.Fatalf("build: %v", err)
	}
	return bb.Error()
}

// GAP-0439: the template build refuses an image symlink that leads into a
// folder DefenseClaw attests (a volume mounted at it would land on the
// managed settings). A link to a settings file, a link inside the attested
// folder and an ordinary link elsewhere are left alone.
func TestBuildRefusesASymlinkIntoAnAttestedFolder(t *testing.T) {
	for _, link := range []tarFile{
		{path: "/work/cfg", symlink: "/etc/claude-code"},
		{path: "/work/cfg2", symlink: "../etc/claude-code"},
		{path: "/home/agent/x", symlink: "/etc/claude-code/missing-dir"},
	} {
		got := buildBlocked(t, tarFile{path: "/work", mode: 0o755, dir: true}, link)
		if !strings.Contains(got, link.path+": is a symlink into /etc/claude-code") {
			t.Errorf("%s -> %s: build %q", link.path, link.symlink, got)
		}
	}
	if got := buildBlocked(t, tarFile{path: "/work", mode: 0o755, dir: true},
		tarFile{path: "/work/settings.json", symlink: "/etc/claude-code/managed-settings.json"},
		tarFile{path: "/usr/lib/ssl", mode: 0o755, dir: true}, tarFile{path: "/usr/lib/ssl/openssl.cnf", symlink: "/etc/ssl/openssl.cnf"},
		tarFile{path: "/usr/local/bin/sh2", symlink: "/bin/sh"}); got != "" {
		t.Errorf("benign links are refused: %s", got)
	}
}

// GAP-0360: the build refuses a base image whose HOME carries git or npm
// settings that run a program the hooks never see; the refusal names the
// keys, never their values. Ordinary settings pass.
func TestBuildRefusesCodeLoadingSettingsInTheHome(t *testing.T) {
	home := func(name, data string) []tarFile {
		return []tarFile{{path: "/home/agent/.config", mode: 0o755, uid: 1000, gid: 1000, dir: true},
			{path: "/home/agent/.config/git", mode: 0o755, uid: 1000, gid: 1000, dir: true},
			{path: "/home/agent/" + name, mode: 0o644, uid: 1000, gid: 1000, data: data}}
	}
	for _, c := range []struct{ name, data, key string }{
		{".gitconfig", "[core]\n\tfsmonitor = /tmp/x.sh\n", "core.fsmonitor"},
		{".gitconfig", "[core]\nhooksPath = /tmp/hooks\n", "core.hookspath"},
		{".gitconfig", "[filter \"lfs\"]\n\tsmudge = /tmp/x %f\n", "filter.lfs.smudge"},
		{".gitconfig", "[alias]\n\tst = !sh /tmp/x\n", "alias.st"},
		{".gitconfig", "[include]\n\tpath = /tmp/more\n", "include.path"},
		{".config/git/config", "[diff \"x\"]\n\ttextconv = /tmp/x\n", "diff.x.textconv"},
		{".npmrc", "script-shell=/tmp/x.sh\n", "script-shell"},
		{".npmrc", "node-options=--require /tmp/x.js\n", "node-options"},
	} {
		got := buildBlocked(t, home(c.name, c.data)...)
		if !strings.Contains(got, "/home/agent/"+c.name+": sets "+c.key) || strings.Contains(got, "/tmp/") {
			t.Errorf("%s %q: build %q", c.name, c.data, got)
		}
	}
	ok := "[user]\n\tname = A\n\temail = a@example.com\n[core]\n\tfsmonitor = false\n\tautocrlf = input\n[alias]\n\tst = status\n[url \"https://\"]\n\tinsteadOf = git://\n"
	if got := buildBlocked(t, append(home(".gitconfig", ok), home(".npmrc", "registry=https://registry.npmjs.org/\nfund=false\n")[2])...); got != "" {
		t.Errorf("ordinary settings are refused: %s", got)
	}
}

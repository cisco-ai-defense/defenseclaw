//go:build !windows

// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// SPDX-License-Identifier: Apache-2.0

package kernelpolicy

import (
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

// trustedScratch is a directory whose whole chain passes the trust rule for
// the current user (/tmp is sticky and world-writable, so it cannot be used).
func trustedScratch(t *testing.T) string {
	t.Helper()
	home, err := os.UserHomeDir()
	if err != nil {
		t.Skip("no home directory")
	}
	dir, err := os.MkdirTemp(home, "kernelpolicy-test-")
	if err != nil {
		t.Skip("cannot create a scratch directory in the home: ", err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	real, err := filepath.EvalSymlinks(dir)
	if err != nil {
		t.Fatal(err)
	}
	if !pathTrustedFor(real, os.Getuid()) {
		t.Skip("the home directory's chain is not trusted on this host")
	}
	return real
}

func writeELF(t *testing.T, path string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, append([]byte{0x7f, 'E', 'L', 'F'}, make([]byte, 60)...), 0o755); err != nil {
		t.Fatal(err)
	}
}

func TestOSFSDetectsELFAndTrust(t *testing.T) {
	dir := trustedScratch(t)
	fsys := OSFS()
	elf := filepath.Join(dir, "agent")
	writeELF(t, elf)
	script := filepath.Join(dir, "wrapper.js")
	if err := os.WriteFile(script, []byte("#!/usr/bin/env node\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	if !fsys.IsELF(elf) || fsys.IsELF(script) || fsys.IsELF(dir) || fsys.IsELF(filepath.Join(dir, "missing")) {
		t.Fatal("ELF detection")
	}
	uid := os.Getuid()
	if !fsys.Trusted(elf, uid) {
		t.Fatal("a file in a private directory of the user must be trusted")
	}
	if fsys.Trusted("relative/path", uid) {
		t.Fatal("a relative path is never trusted")
	}
	if err := os.Chmod(elf, 0o775); err != nil {
		t.Fatal(err)
	}
	if fsys.Trusted(elf, uid) {
		t.Fatal("a file another group can write must not be trusted")
	}
	if err := os.Chmod(elf, 0o755); err != nil {
		t.Fatal(err)
	}
	other := uid + 4242
	if os.Getuid() != 0 && fsys.Trusted(elf, other) {
		t.Fatal("a file owned by another user is not trusted for this uid")
	}
	// A link through a world-writable directory is refused.
	link := filepath.Join(dir, "via-tmp")
	outside, err := os.MkdirTemp("", "kp-outside-")
	if err != nil {
		t.Skip("no temp dir")
	}
	defer os.RemoveAll(outside)
	if err := os.Symlink(outside, link); err != nil {
		t.Fatal(err)
	}
	if fsys.Trusted(link, uid) {
		t.Fatal("a chain that passes through /tmp must not be trusted")
	}
	loop := filepath.Join(dir, "loop")
	if err := os.Symlink(loop, loop); err != nil {
		t.Fatal(err)
	}
	if fsys.Trusted(loop, uid) {
		t.Fatal("a link loop must not be trusted")
	}
}

// The whole compile pipeline on the real filesystem: symlinks, ELF magic and
// the trust rule, with a decoy home and marker files only.
func TestCompileOnTheRealFilesystem(t *testing.T) {
	dir := trustedScratch(t)
	home := filepath.Join(dir, "home", "dcr-test")
	if err := os.MkdirAll(home, 0o700); err != nil {
		t.Fatal(err)
	}
	versions := filepath.Join(home, ".local", "share", "claude", "versions")
	writeELF(t, filepath.Join(versions, "2.1.1"))
	if err := os.MkdirAll(filepath.Join(home, ".local", "bin"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Join(versions, "2.1.1"), filepath.Join(home, ".local", "bin", "claude")); err != nil {
		t.Fatal(err)
	}
	// A dotfile link that stays in the home, and a key name pointing out of it.
	if err := os.WriteFile(filepath.Join(home, "rc-source"), []byte("dccert-block-marker\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("rc-source", filepath.Join(home, ".bashrc")); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(home, ".ssh"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("/etc/passwd", filepath.Join(home, ".ssh", "id_rsa")); err != nil {
		t.Fatal(err)
	}
	uid := os.Getuid()
	if uid == 0 {
		t.Skip("uid 0 is never enrolled")
	}
	enrollment, err := ParseEnrollment([]byte("targets:\n- user: dcr-test\n  uid: "+strconv.Itoa(uid)+"\n  user_home: "+home+"\n  connector: claudecode\n"), nil)
	if err != nil {
		t.Fatal(err)
	}
	fsys := OSFS()
	installs := ResolveInstalls(fsys, enrollment, ResolveOptions{})
	// The host may have machine-wide installs of its own; the user's is among them.
	if len(installs) != 1 || !containsStr(installs[0].Native, filepath.Join(versions, "2.1.1")) {
		t.Fatalf("installs = %+v", installs)
	}
	compiled, err := Compile(Input{
		Enrollment: enrollment, Installs: installs, FS: fsys, Observe: true,
		Controls: &Scope{Mode: PolicyMonitor, UIDs: []int{uid}},
	})
	if err != nil {
		t.Fatal(err)
	}
	controls := policyOf(t, compiled, FamilyControls)
	text := string(controls.YAML)
	if !strings.Contains(text, filepath.Join(home, "rc-source")) {
		t.Errorf("the .bashrc link was not resolved to its target:\n%s", text)
	}
	if strings.Contains(text, "/etc/passwd") || strings.Contains(text, filepath.Join(home, ".ssh", "id_rsa")) {
		t.Errorf("a key name linked outside the home is in the policy:\n%s", text)
	}
	if !strings.Contains(text, filepath.Join(home, ".ssh", "id_ed25519")) {
		t.Errorf("the other key names must remain:\n%s", text)
	}
	for _, note := range compiled.Notes {
		if strings.HasPrefix(note, "kernel_policy_lint") {
			t.Fatalf("lint dropped something on a plain layout: %v", compiled.Notes)
		}
	}
	// The policy text is the canonical rendering of a parse of itself.
	if v := Lint(controls.YAML, LintOptions{Homes: []string{home}, FS: fsys}); len(v) != 0 {
		t.Fatalf("lint on the real filesystem: %v", v)
	}
}

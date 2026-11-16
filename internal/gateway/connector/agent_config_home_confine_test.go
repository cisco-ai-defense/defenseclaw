//go:build !windows

// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package connector

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"testing"
)

// In a home bound with WithUserHomeDir (the enterprise per-user install and
// cleanup), a config write or removal never follows a symlink out of the
// home: not the config link itself, not a linked folder on the way, not a
// dangling link that names a file outside. The outside file keeps its bytes
// whether or not the account could change it. A link inside the home is
// still written through, and an unbound process (a personal install) keeps
// writing through any dotfile link (rel-1-0-3 GAP-0206).
func TestAtomicWritesNeverFollowALinkOutOfTheBoundHome(t *testing.T) {
	root := t.TempDir()
	home := filepath.Join(root, "home")
	outsideDir := filepath.Join(root, "outside")
	for _, dir := range []string{filepath.Join(home, ".codex"), filepath.Join(home, "dotfiles"), outsideDir} {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	outside := filepath.Join(outsideDir, "config.toml")
	original := []byte("model = \"gpt-5\"\n[hooks]\n")
	if err := os.WriteFile(outside, original, 0o600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(home, ".codex", "config.toml")
	if err := os.Symlink(outside, link); err != nil {
		t.Fatal(err)
	}
	stateDir := filepath.Join(home, ".defenseclaw")
	if err := os.MkdirAll(stateDir, 0o700); err != nil {
		t.Fatal(err)
	}
	outsideUnchanged := func(t *testing.T, what string) {
		t.Helper()
		data, err := os.ReadFile(outside)
		if err != nil || !bytes.Equal(data, original) {
			t.Fatalf("%s changed the file outside the home: %q, %v", what, data, err)
		}
		if target, err := os.Readlink(link); err != nil || target != outside {
			t.Fatalf("%s changed the link: %q, %v", what, target, err)
		}
	}
	refused := func(t *testing.T, what string, err error) {
		t.Helper()
		var outsideErr *AgentConfigOutsideHomeError
		if !errors.Is(err, ErrAgentConfigOutsideHome) || !errors.As(err, &outsideErr) {
			t.Fatalf("%s = %v, want the outside-home refusal", what, err)
		}
	}
	bound := func(fn func() error) error { return WithUserHomeDir(home, fn) }

	refused(t, "write", bound(func() error { return atomicWriteFile(link, []byte("new"), 0o600) }))
	outsideUnchanged(t, "write")
	removal := func(raw []byte, exists bool) (atomicTransformResult, error) {
		return atomicTransformResult{Remove: true}, nil
	}
	refused(t, "removal", bound(func() error { return atomicTransformFileWithStateDir(link, stateDir, 0o600, removal) }))
	outsideUnchanged(t, "removal")
	// What would change nothing passes: a file the account cleaned by hand
	// does not keep its cleanup failing.
	if err := bound(func() error { return atomicWriteFile(link, original, 0o600) }); err != nil {
		t.Fatalf("an unchanged write through the outside link = %v", err)
	}
	keep := func(raw []byte, exists bool) (atomicTransformResult, error) {
		return atomicTransformResult{Data: append([]byte(nil), raw...)}, nil
	}
	if err := bound(func() error { return atomicTransformFileWithStateDir(link, stateDir, 0o600, keep) }); err != nil {
		t.Fatalf("an unchanged transform through the outside link = %v", err)
	}
	outsideUnchanged(t, "an unchanged write")

	// The same for a file the account cannot change (as a root-owned
	// file in a folder it cannot write): nothing is even tried.
	if err := os.Chmod(outside, 0o400); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(outsideDir, 0o500); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(outsideDir, 0o700) })
	refused(t, "read-only removal", bound(func() error { return atomicTransformFileWithStateDir(link, stateDir, 0o600, removal) }))
	outsideUnchanged(t, "read-only removal")
	if err := os.Chmod(outsideDir, 0o700); err != nil {
		t.Fatal(err)
	}

	// A dangling link out of the home is not created through.
	dangling := filepath.Join(home, ".codex", "dangling.toml")
	missing := filepath.Join(outsideDir, "missing.toml")
	if err := os.Symlink(missing, dangling); err != nil {
		t.Fatal(err)
	}
	refused(t, "dangling write", bound(func() error { return atomicWriteFile(dangling, []byte("new"), 0o600) }))
	if _, err := os.Lstat(missing); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("a dangling link created a file outside the home: %v", err)
	}

	// A linked folder on the way out of the home.
	if err := os.Symlink(outsideDir, filepath.Join(home, ".config")); err != nil {
		t.Fatal(err)
	}
	viaFolder := filepath.Join(home, ".config", "plugin.js")
	refused(t, "linked folder write", bound(func() error { return atomicWriteFile(viaFolder, []byte("new"), 0o600) }))
	if _, err := os.Lstat(filepath.Join(outsideDir, "plugin.js")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("a linked folder let a write out of the home: %v", err)
	}

	// A dotfile link inside the home is written through and kept.
	inside := filepath.Join(home, "dotfiles", "config.toml")
	if err := os.WriteFile(inside, []byte("old"), 0o600); err != nil {
		t.Fatal(err)
	}
	insideLink := filepath.Join(home, ".codex", "inside.toml")
	if err := os.Symlink(filepath.Join("..", "dotfiles", "config.toml"), insideLink); err != nil {
		t.Fatal(err)
	}
	if err := bound(func() error { return atomicWriteFile(insideLink, []byte("new"), 0o600) }); err != nil {
		t.Fatalf("write through an in-home link: %v", err)
	}
	if data, err := os.ReadFile(inside); err != nil || string(data) != "new" {
		t.Fatalf("in-home link target = %q, %v", data, err)
	}
	if info, err := os.Lstat(insideLink); err != nil || info.Mode()&os.ModeSymlink == 0 {
		t.Fatalf("the in-home link was replaced: %v", err)
	}

	// Without a bound home, a personal install keeps writing through.
	if err := os.Chmod(outside, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := atomicWriteFile(link, []byte("personal"), 0o600); err != nil {
		t.Fatalf("unbound write through a dotfile link: %v", err)
	}
	if data, err := os.ReadFile(outside); err != nil || string(data) != "personal" {
		t.Fatalf("unbound write did not reach the linked file: %q, %v", data, err)
	}
}

func TestAgentConfigOutsideHomeOnlyJudgesPathsInTheHome(t *testing.T) {
	root := t.TempDir()
	home := filepath.Join(root, "home")
	if err := os.MkdirAll(home, 0o700); err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{filepath.Join(root, "elsewhere", "file"), filepath.Join(home, "missing", "file")} {
		if target, outside, err := AgentConfigOutsideHome(home, path); err != nil || outside || target != "" {
			t.Fatalf("AgentConfigOutsideHome(%s) = %q, %v, %v", path, target, outside, err)
		}
	}
	loop := filepath.Join(home, "loop")
	if err := os.Symlink(loop, loop); err != nil {
		t.Fatal(err)
	}
	if _, _, err := AgentConfigOutsideHome(home, loop); err == nil {
		t.Fatal("a link loop was judged")
	}
}

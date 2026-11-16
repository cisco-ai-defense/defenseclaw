//go:build !windows

// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package watcher

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/gateway/connector"
	"github.com/fsnotify/fsnotify"
)

func watchLinkedRoot(t *testing.T, root string) error {
	t.Helper()
	fsw, err := fsnotify.NewWatcher()
	if err != nil {
		t.Fatal(err)
	}
	defer fsw.Close()
	_, err = ensureAndWatchWithCheck(fsw, root, true)
	return err
}

// GAP-0905: a ~/.claude link into a dotfiles folder with the default mode of
// a umask-002 account (0775, the account's own private group) is watched, so
// admission scanning stays on.
func TestLinkedAgentRootThroughAPrivateGroupFolderIsWatched(t *testing.T) {
	home, root, physical := linkedAgentSkills(t)
	dotfiles := filepath.Join(home, "dotfiles")
	for _, dir := range []string{dotfiles, filepath.Dir(physical), physical} {
		if err := os.Chmod(dir, 0o775); err != nil {
			t.Fatal(err)
		}
	}
	info, err := os.Lstat(dotfiles)
	if err != nil {
		t.Fatal(err)
	}
	if !connector.OwnerPrivateGroupLocalSources(dotfiles, info) {
		t.Skip("the test account has no private group")
	}
	if err := watchLinkedRoot(t, root); err != nil {
		t.Fatalf("a root through private-group folders is not watched: %v", err)
	}
}

// A folder any account can write keeps the root refused, and the refusal names
// the folder and the change that fixes it.
func TestLinkedAgentRootThroughAWorldWritableFolderNamesIt(t *testing.T) {
	home, root, _ := linkedAgentSkills(t)
	dotfiles := filepath.Join(home, "dotfiles")
	if err := os.Chmod(dotfiles, 0o757); err != nil {
		t.Fatal(err)
	}
	err := watchLinkedRoot(t, root)
	if err == nil || !strings.Contains(err.Error(), dotfiles) || !strings.Contains(err.Error(), "chmod go-w") {
		t.Fatalf("refusal = %v, want it to name %s and the chmod", err, dotfiles)
	}
}

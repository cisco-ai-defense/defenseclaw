// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package gateway

import (
	"os"
	"path/filepath"
	"testing"
)

func TestCodexSourceFileHasSingleLinkWindows(t *testing.T) {
	t.Run("hard link aliases", func(t *testing.T) {
		directory := t.TempDir()
		unique := filepath.Join(directory, "unique.txt")
		if err := os.WriteFile(unique, []byte("source"), 0o600); err != nil {
			t.Fatal(err)
		}
		uniqueInfo, err := os.Lstat(unique)
		if err != nil {
			t.Fatal(err)
		}
		if !codexSingleLinkRegularFile(unique, uniqueInfo) {
			t.Fatal("unique Windows source file was not accepted")
		}

		alias := filepath.Join(directory, "alias.txt")
		if err := os.Link(unique, alias); err != nil {
			t.Fatal(err)
		}
		for _, path := range []string{unique, alias} {
			info, err := os.Lstat(path)
			if err != nil {
				t.Fatal(err)
			}
			if codexSingleLinkRegularFile(path, info) {
				t.Fatalf("hard-linked Windows source alias was accepted: %s", path)
			}
		}
	})

	t.Run("symbolic link", func(t *testing.T) {
		directory := t.TempDir()
		target := filepath.Join(directory, "target.txt")
		if err := os.WriteFile(target, []byte("source"), 0o600); err != nil {
			t.Fatal(err)
		}
		link := filepath.Join(directory, "link.txt")
		if err := os.Symlink(target, link); err != nil {
			t.Skipf("Windows symbolic links are unavailable: %v", err)
		}
		info, err := os.Lstat(link)
		if err != nil {
			t.Fatal(err)
		}
		if codexSingleLinkRegularFile(link, info) {
			t.Fatal("symbolic-link Windows source path was accepted")
		}
	})
}

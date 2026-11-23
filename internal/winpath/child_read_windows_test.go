// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package winpath

import (
	"errors"
	"io"
	"os"
	"path/filepath"
	"testing"

	"golang.org/x/sys/windows"
)

func TestReadChildUsesHeldDirectoryAndRefusesDirectoryJunction(t *testing.T) {
	root, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	nested := filepath.Join(root, "nested")
	if err := os.MkdirAll(filepath.Join(nested, "plain"), 0o700); err != nil {
		t.Fatal(err)
	}
	filePath := filepath.Join(nested, "SKILL.md")
	if err := os.WriteFile(filePath, []byte("ordinary test skill\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	parent, err := OpenDirectoryNoFollow(root)
	if err != nil {
		t.Fatal(err)
	}
	defer parent.Close()
	directory, err := OpenChildNoFollow(parent, "nested", BelowDirectory)
	if err != nil {
		t.Fatal(err)
	}
	defer directory.Close()
	if entries, err := directory.ReadDir(4); err != nil && !errors.Is(err, io.EOF) || len(entries) != 2 {
		t.Fatalf("held directory listing = %d entries, %v", len(entries), err)
	}
	file, err := OpenChildNoFollow(directory, "SKILL.md", BelowFile)
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	data, err := io.ReadAll(file)
	if err != nil || string(data) != "ordinary test skill\n" {
		t.Fatalf("held child read = %q, %v", data, err)
	}
	writer, err := os.OpenFile(filePath, os.O_WRONLY, 0)
	if err == nil {
		writer.Close()
		t.Fatal("regular child read allowed a concurrent write handle")
	}
	if !errors.Is(err, windows.ERROR_SHARING_VIOLATION) {
		t.Fatalf("concurrent write failed with %v, want a sharing violation", err)
	}
	if err := file.Close(); err != nil {
		t.Fatal(err)
	}
	writer, err = os.OpenFile(filePath, os.O_WRONLY, 0)
	if err != nil {
		t.Fatalf("write open after the read handle closed: %v", err)
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	junction := filepath.Join(root, "linked")
	if err := setTestMountPoint(t, junction, `\??\`+nested, nested); err != nil {
		t.Fatalf("create test-owned directory junction: %v", err)
	}
	t.Cleanup(func() {
		if err := os.Remove(junction); err != nil && !os.IsNotExist(err) {
			t.Errorf("remove test junction: %v", err)
		}
	})
	if child, err := OpenChildNoFollow(parent, "linked", BelowDirectory); !errors.Is(err, ErrLinkBelowRoot) {
		if child != nil {
			child.Close()
		}
		t.Fatalf("directory junction = %v, want link refusal", err)
	}
	if dir, err := OpenDirectoryNoFollow(filepath.Join(junction, "plain")); !errors.Is(err, ErrLinkBelowRoot) {
		if dir != nil {
			dir.Close()
		}
		t.Fatalf("root below a directory junction = %v, want link refusal", err)
	}
	want, err := os.Readlink(junction)
	if err != nil {
		t.Fatal(err)
	}
	if got, err := ReadChildLink(parent, "linked"); err != nil || got != want {
		t.Fatalf("held junction metadata = %q, %v; want os.Readlink %q", got, err, want)
	}
}

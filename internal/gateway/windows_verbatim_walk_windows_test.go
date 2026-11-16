// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package gateway

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/hookpaths"
)

// writeVerbatimEntry creates the file named by the exact extended-length
// spelling of dir and name (a name Win32 would otherwise normalize) and
// removes it before the temporary folder goes.
func writeVerbatimEntry(t *testing.T, dir, name, content string) string {
	t.Helper()
	verbatim := `\\?\` + filepath.Join(dir, name)
	if err := os.WriteFile(verbatim, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Remove(verbatim) })
	return verbatim
}

// An operand with the exact extended-length prefix and a trailing space names
// an entry of its own, next to the entry without the space. The host walk
// must look up the first, never its sibling: the path without the prefix is
// normalized by Win32 and opens the sibling.
func TestWindowsHostWalkOfAVerbatimNameOpensThatEntryNotItsSibling(t *testing.T) {
	dir := t.TempDir()
	writeVerbatimEntry(t, dir, "entry", "plain")
	verbatim := writeVerbatimEntry(t, dir, "entry ", "spaced")

	host, ok := windowsHostPath(verbatim)
	if !ok {
		t.Fatalf("windowsHostPath(%q) is no Windows path", verbatim)
	}
	walk := windowsWalkPath(host, verbatim)
	if got, err := os.ReadFile(walk); err != nil || string(got) != "spaced" {
		t.Fatalf("walk %q read %q, %v, want the entry with the trailing space", walk, got, err)
	}
	// The premise: the lookup form is the sibling for Win32.
	if got, err := os.ReadFile(host); err != nil || string(got) != "plain" {
		t.Fatalf("lookup form %q read %q, %v, want the entry Win32 normalizes to", host, got, err)
	}
	walked, err := hookpaths.Lstat(walk)
	if err != nil {
		t.Fatal(err)
	}
	sibling, err := hookpaths.Lstat(host)
	if err != nil {
		t.Fatal(err)
	}
	if os.SameFile(walked, sibling) {
		t.Fatal("the walk of the verbatim name reached its sibling")
	}
}

// A link with a trailing space in its exact name leads to the file it names,
// while the sibling without the space is an ordinary file: the link is
// resolved through the walk path and the answer is read without the prefix.
func TestWindowsHostWalkResolvesAVerbatimLinkToItsTarget(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "target.txt")
	if err := os.WriteFile(target, []byte("target"), 0o600); err != nil {
		t.Fatal(err)
	}
	writeVerbatimEntry(t, dir, "link", "ordinary")
	verbatim := `\\?\` + filepath.Join(dir, "link ")
	if err := os.Symlink(target, verbatim); err != nil {
		t.Skipf("no privilege to create a symbolic link: %v", err)
	}
	t.Cleanup(func() { _ = os.Remove(verbatim) })

	host, ok := windowsHostPath(verbatim)
	if !ok {
		t.Fatalf("windowsHostPath(%q) is no Windows path", verbatim)
	}
	resolved, ok := hookpaths.ResolveWriteTarget(windowsWalkPath(host, verbatim))
	if !ok {
		t.Fatalf("the walk of %q could not resolve the link", verbatim)
	}
	resolved = windowsWalkResult(resolved)
	want, err := os.Stat(target)
	if err != nil {
		t.Fatal(err)
	}
	got, err := os.Stat(resolved)
	if err != nil || !os.SameFile(want, got) {
		t.Fatalf("resolved %q (%v) is not the link target %q", resolved, err, target)
	}
	// The sibling is no link: its walk stays on itself.
	plain, ok := hookpaths.ResolveWriteTarget(filepath.Join(dir, "link"))
	if !ok {
		t.Fatal("the ordinary sibling could not be resolved")
	}
	sibling, err := os.Stat(plain)
	if err != nil || os.SameFile(want, sibling) {
		t.Fatalf("the ordinary sibling resolved to the link target (%v)", err)
	}
}

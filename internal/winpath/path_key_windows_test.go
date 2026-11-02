// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package winpath

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"golang.org/x/sys/windows"
)

// The spellings of one folder share a key (GAP-0626): case, the \\?\ prefix,
// a trailing separator and an 8.3 short name.
func TestComparisonKeyFoldsSpellingsOfOneFolder(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "WinGet Packages Folder")
	if err := os.Mkdir(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	want := ComparisonKey(dir)
	spellings := []string{
		strings.ToUpper(dir),
		`\\?\` + dir,
		dir + `\`,
		filepath.ToSlash(dir),
	}
	if short, ok := shortPathName(dir); ok && short != dir {
		spellings = append(spellings, short, `\\?\`+short)
	}
	for _, spelling := range spellings {
		if got := ComparisonKey(spelling); got != want {
			t.Fatalf("ComparisonKey(%q) = %q, want %q", spelling, got, want)
		}
	}
	if got := ComparisonKey(`\\?\UNC\server\share\dir`); got != `\\server\share\dir` {
		t.Fatalf("UNC key = %q", got)
	}
	if ComparisonKey(dir+"2") == want {
		t.Fatal("another folder shares the key")
	}
}

// A long-name lookup on storage that never answers must not hold
// ComparisonKey: the WinGet scan computes its slot key before its own
// deadline starts, and the guardian keys its pending restores (B-21 review).
func TestComparisonKeyDoesNotWaitForAStalledLongNameLookup(t *testing.T) {
	oldLookups, oldLookup := longNames, getLongPathName
	release := make(chan struct{})
	longNames = newLongNameLookups()
	getLongPathName = func(string) (string, bool) {
		<-release
		return `C:\Users\Stalled Profile\AppData\Local\Microsoft\WinGet\Packages`, true
	}
	t.Cleanup(func() {
		close(release)
		longNames, getLongPathName = oldLookups, oldLookup
	})
	path := `C:\Users\STALLE~1\AppData\Local\Microsoft\WinGet\Packages`
	want := strings.ToLower(path)
	for i := 0; i < 2; i++ {
		started := time.Now()
		if got := ComparisonKey(path); got != want {
			t.Fatalf("ComparisonKey = %q, want %q", got, want)
		}
		if waited := time.Since(started); waited > longNameLookupBudget+2*time.Second {
			t.Fatalf("ComparisonKey waited %v for a stalled lookup", waited)
		}
	}
}

func shortPathName(path string) (string, bool) {
	long, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return "", false
	}
	buffer := make([]uint16, windows.MAX_LONG_PATH)
	n, err := windows.GetShortPathName(long, &buffer[0], uint32(len(buffer)))
	if err != nil || n == 0 || int(n) >= len(buffer) {
		return "", false
	}
	return windows.UTF16ToString(buffer[:n]), true
}

// An 8.3 alias is recycled: once its folder is deleted, the next folder
// created with a similar name gets the same short name. The short spelling
// must then key the new folder, not the deleted one, also in a process
// that expanded it before (rel-1-0-6:GAP-0449).
func TestComparisonKeyFollowsARecycledShortName(t *testing.T) {
	parent := t.TempDir()
	first := filepath.Join(parent, "Recycled Alias Folder One")
	if err := os.Mkdir(first, 0o700); err != nil {
		t.Fatal(err)
	}
	short, ok := shortPathName(first)
	if !ok || strings.EqualFold(short, first) {
		t.Skip("the volume of the temporary folder makes no 8.3 names")
	}
	if got, want := ComparisonKey(short), ComparisonKey(first); got != want {
		t.Fatalf("ComparisonKey(%q) = %q, want %q", short, got, want)
	}
	if err := os.Remove(first); err != nil {
		t.Fatal(err)
	}
	second := filepath.Join(parent, "Recycled Alias Folder Two")
	if err := os.Mkdir(second, 0o700); err != nil {
		t.Fatal(err)
	}
	if again, ok := shortPathName(second); !ok || !strings.EqualFold(again, short) {
		t.Skipf("the new folder got %q, not the recycled alias %q", again, short)
	}
	if got, want := ComparisonKey(short), ComparisonKey(second); got != want {
		t.Fatalf("ComparisonKey(%q) after its alias moved = %q, want %q", short, got, want)
	}
}

// BenchmarkComparisonKey times a spelling with no 8.3 name, an existing
// long folder name, its 8.3 short spelling, and that spelling in a process
// that has not expanded it yet (short-first).
func BenchmarkComparisonKey(b *testing.B) {
	dir := filepath.Join(b.TempDir(), "WinGet Packages Folder")
	if err := os.Mkdir(dir, 0o700); err != nil {
		b.Fatal(err)
	}
	if long, ok := lookupLongPathName(dir); ok {
		dir = long
	}
	short, ok := shortPathName(dir)
	if !ok || strings.EqualFold(short, dir) {
		short = ""
	}
	cases := []struct{ name, path string }{
		{"plain", `C:\ProgramData\DefenseClaw\data\guardian-restores.json`},
		{"long", dir},
		{"short", short},
	}
	for _, c := range cases {
		if c.path == "" {
			continue
		}
		b.Run(c.name, func(b *testing.B) {
			for i := 0; i < b.N; i++ {
				ComparisonKey(c.path)
			}
		})
	}
	if short == "" {
		return
	}
	b.Run("short-first", func(b *testing.B) {
		old := longNames
		b.Cleanup(func() { longNames = old })
		for i := 0; i < b.N; i++ {
			longNames = newLongNameLookups()
			ComparisonKey(short)
		}
	})
}

// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// SPDX-License-Identifier: Apache-2.0

package managed

import (
	"os"
	"path/filepath"
	"reflect"
	"testing"
)

func writeCMIDLibrary(t *testing.T, cmRoot, cmVersion, cmidVersion, arch string) string {
	t.Helper()
	directory := filepath.Join(cmRoot, cmVersion, cmidNestedDirectory, cmidVersion, arch)
	if err := os.MkdirAll(directory, 0o755); err != nil {
		t.Fatalf("create %s: %v", directory, err)
	}
	path := filepath.Join(directory, cmidLibraryName)
	if err := os.WriteFile(path, []byte("stub"), 0o644); err != nil {
		t.Fatalf("write %s: %v", path, err)
	}
	return path
}

func TestDiscoverCMIDLibraryPrefersTheNewestVersions(t *testing.T) {
	cmRoot := t.TempDir()
	writeCMIDLibrary(t, cmRoot, "1.0.3.435", "1.2.1.0", "x64")
	writeCMIDLibrary(t, cmRoot, "1.0.10.1", "1.1.0.0", "x64")
	newest := writeCMIDLibrary(t, cmRoot, "1.0.10.1", "1.2.1.0", "x64")

	if got := discoverCMIDLibraryIn(cmRoot, "x64"); got != newest {
		t.Fatalf("discovered %q, want %q", got, newest)
	}
}

func TestDiscoverCMIDLibraryIsArchitectureSpecific(t *testing.T) {
	cmRoot := t.TempDir()
	writeCMIDLibrary(t, cmRoot, "1.0.3.435", "1.2.1.0", "x64")

	if got := discoverCMIDLibraryIn(cmRoot, "arm64"); got != "" {
		t.Fatalf("discovered %q for a foreign architecture, want no match", got)
	}
}

func TestDiscoverCMIDLibraryFallsBackToAnOlderCompleteTree(t *testing.T) {
	cmRoot := t.TempDir()
	older := writeCMIDLibrary(t, cmRoot, "1.0.3.435", "1.2.1.0", "x64")
	// A newer CM directory whose CMID tree carries no library for this
	// architecture must not shadow the version that does.
	if err := os.MkdirAll(filepath.Join(cmRoot, "2.0.0.0", cmidNestedDirectory, "1.3.0.0", "x64"), 0o755); err != nil {
		t.Fatalf("create the empty newer tree: %v", err)
	}

	if got := discoverCMIDLibraryIn(cmRoot, "x64"); got != older {
		t.Fatalf("discovered %q, want %q", got, older)
	}
}

func TestDiscoverCMIDLibraryReportsNothingWhenSecureClientIsAbsent(t *testing.T) {
	if got := discoverCMIDLibraryIn(filepath.Join(t.TempDir(), "absent"), "x64"); got != "" {
		t.Fatalf("discovered %q with no Secure Client tree, want no match", got)
	}
}

func TestCompareVersionsOrdersNumericallyAndDemotesJunk(t *testing.T) {
	if compareVersions("1.0.10.1", "1.0.3.435") <= 0 {
		t.Fatal("1.0.10.1 did not compare newer than 1.0.3.435")
	}
	if compareVersions("1.2", "1.2.0") != 0 {
		t.Fatal("a missing trailing component did not compare equal to zero")
	}
	if compareVersions("backup", "0.0.0.1") >= 0 {
		t.Fatal("an unparsable directory outranked a real version")
	}
}

func TestSortVersionsDescendingKeepsEqualNamesInPlace(t *testing.T) {
	// Names that compare equal carry no version signal to order them by,
	// so the sort has to leave ReadDir's ordering alone rather than
	// reach for a tiebreaker that would reorder 1.2 against 1.2.0.
	names := []string{"backup", "old", "1.2", "1.2.0"}
	sortVersionsDescending(names)

	want := []string{"1.2", "1.2.0", "backup", "old"}
	if !reflect.DeepEqual(names, want) {
		t.Fatalf("sorted to %v, want %v", names, want)
	}
}

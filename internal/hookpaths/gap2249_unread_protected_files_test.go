// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package hookpaths

import (
	"fmt"
	"runtime"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/fixturefs"
)

// TestGAP2249UnreadProtectedFilesReadOnce pins that a decision inside
// fixturefs.Unread gets the protected key files newProtectedFilesWith reads
// there, from one read per home, as a copy (rel-1-0-10:GAP-2249).
func TestGAP2249UnreadProtectedFilesReadOnce(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Windows reads the files afresh")
	}
	home := t.TempDir()
	fixturefs.Unread(func() {
		want := fmt.Sprint(newProtectedFilesWith(home, nil))
		first := newProtectedFiles(home)
		if got := fmt.Sprint(first); got != want {
			t.Fatalf("inside Unread: %s, want %s", got, want)
		}
		unreadProtected.Lock()
		_, kept := unreadProtected.files[home]
		unreadProtected.Unlock()
		if !kept {
			t.Fatal("the home's files were not kept")
		}
		first[0].path = "changed"
		if got := fmt.Sprint(newProtectedFiles(home)); got != want {
			t.Fatalf("a caller's change reached the kept files: %s, want %s", got, want)
		}
	})
	// Outside Unread the files are read from the file system, never kept.
	other := t.TempDir()
	newProtectedFiles(other)
	unreadProtected.Lock()
	_, kept := unreadProtected.files[other]
	unreadProtected.Unlock()
	if kept {
		t.Fatal("files read outside Unread were kept")
	}
}

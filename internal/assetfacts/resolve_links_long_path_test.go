// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package assetfacts

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

// GAP-0677: a long word of many parts under a missing folder (the escaped
// quotes of deeply nested shell bodies) is resolved in time linear in its
// length, as the lexical join it is; a link reached after .. out of a missing
// folder is still followed.
func TestResolveLinksLongPathUnderMissingFolder(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX links")
	}
	t.Parallel()
	root := t.TempDir()
	target := filepath.Join(root, "target")
	if err := os.MkdirAll(target, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, filepath.Join(root, "link")); err != nil {
		t.Fatal(err)
	}
	long := filepath.Join(root, "missing") + strings.Repeat("/x\x27", 30000)
	start := time.Now()
	if got, want := ResolveLinks(long), filepath.Clean(long); got != want {
		t.Errorf("long path under a missing folder: got %d bytes, want the lexical %d", len(got), len(want))
	}
	if took := time.Since(start); took > time.Second {
		t.Errorf("long path under a missing folder resolved in %s", took)
	}
	if got, want := ResolveLinks(filepath.Join(root, "missing")+"/../link/f"), filepath.Join(target, "f"); got != want {
		t.Errorf("link after .. out of a missing folder: got %s, want %s", got, want)
	}
}

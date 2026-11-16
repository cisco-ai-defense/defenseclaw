// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package hookpaths

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

// A script whose working folder the system refuses to open for passing too
// many links is recorded as an unread body of the call; a spelling within
// the limit is read, and a folder that is missing is no unread body
// (rel-1-0-9:GAP-0950).
func TestIndirectSourceBehindTooManyLinksIsAnUnreadBody(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("the share walk reports the link bound on Windows")
	}
	limit := SystemLinkLimit()
	live := t.TempDir()
	if err := os.WriteFile(filepath.Join(live, "run.sh"), []byte("echo ordinary\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	for _, links := range []int{1, limit - 1, limit, limit + 1, limit + 5} {
		t.Run(fmt.Sprintf("%d links", links), func(t *testing.T) {
			dir, err := filepath.EvalSymlinks(t.TempDir())
			if err != nil {
				t.Fatal(err)
			}
			entry := live
			for i := links; i >= 1; i-- {
				link := filepath.Join(dir, fmt.Sprintf("hop%03d", i))
				if err := os.Symlink(entry, link); err != nil {
					t.Skipf("symlink unavailable: %v", err)
				}
				entry = link
			}
			defer HookCall()()
			body, ok := readIndirectSource("run.sh", entry)
			if links <= limit {
				if !ok || body == "" || ShareBodyUnread() {
					t.Fatalf("%d links: read=%v unread=%v", links, ok, ShareBodyUnread())
				}
				return
			}
			if ok || !ShareBodyUnread() {
				t.Fatalf("%d links: read=%v unread=%v, want an unread body", links, ok, ShareBodyUnread())
			}
			if _, linkBound := ShareBodyUnreadCauses(); !linkBound {
				t.Fatal("the unread body is not recorded as past the link bound")
			}
		})
	}
	t.Run("missing folder", func(t *testing.T) {
		defer HookCall()()
		if _, ok := readIndirectSource("run.sh", filepath.Join(t.TempDir(), "gone")); ok || ShareBodyUnread() {
			t.Fatalf("a missing folder read=%v unread=%v", ok, ShareBodyUnread())
		}
	})
}

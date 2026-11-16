// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package hookpaths

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// A script named by a path through folder links is read when the system opens
// the path and the file lies below the working folder, however many links
// there are up to the system limit (os.Root alone follows eight). Past that
// limit the body is unread whether or not the links leave the folder; a file
// outside the folder that the system opens stays unread and unrecorded, as
// one named with .. is. A script that is not there is none of these
// (rel-1-0-9:GAP-0950).
func TestIndirectSourceNamedThroughLinksIsReadUpToTheSystemLimit(t *testing.T) {
	limit := SystemLinkLimit()
	for _, links := range []int{1, 8, 9, limit - 1, limit, limit + 1} {
		for _, leaves := range []bool{false, true} {
			t.Run(fmt.Sprintf("%d links leaves %v", links, leaves), func(t *testing.T) {
				outer := linkFreeTempDir(t)
				cwd := filepath.Join(outer, "proj")
				live := filepath.Join(outer, "live")
				if !leaves {
					live = filepath.Join(cwd, "live")
				}
				for _, dir := range []string{cwd, live} {
					if err := os.MkdirAll(dir, 0o700); err != nil {
						t.Fatal(err)
					}
				}
				if err := os.WriteFile(filepath.Join(live, "safe.sh"), []byte("echo ordinary\n"), 0o600); err != nil {
					t.Fatal(err)
				}
				// links is the number the name passes: the chain is made of
				// links-1 folder links below the first, which is made last.
				for i := links; i >= 1; i-- {
					to := live
					if i < links {
						to = fmt.Sprintf("hop%03d", i+1)
					}
					if err := os.Symlink(to, filepath.Join(cwd, fmt.Sprintf("hop%03d", i))); err != nil {
						t.Skipf("symlink unavailable: %v", err)
					}
				}
				fakeNetworkShare(t, t.TempDir(), 20*time.Millisecond, time.Second, func(string) {})
				defer HookCall()()
				content, read := readIndirectSource("hop001/safe.sh", cwd)
				_, linkBound := ShareBodyUnreadCauses()
				wantRead, wantRecorded := links <= limit && !leaves, links > limit
				if read != wantRead || linkBound != wantRecorded || (wantRead && content != "echo ordinary\n") {
					t.Errorf("script behind %d links (limit %d, leaves the folder %v): read %v, link bound recorded %v, want read %v recorded %v",
						links, limit, leaves, read, linkBound, wantRead, wantRecorded)
				}
			})
		}
	}
}

func TestIndirectSourceThatIsNotThereIsNotAnUnreadBody(t *testing.T) {
	cwd := linkFreeTempDir(t)
	if err := os.Mkdir(filepath.Join(cwd, "real"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("real", filepath.Join(cwd, "hop001")); err != nil {
		t.Skipf("symlink unavailable: %v", err)
	}
	fakeNetworkShare(t, t.TempDir(), 20*time.Millisecond, time.Second, func(string) {})
	defer HookCall()()
	for _, name := range []string{"hop001/missing.sh", "nowhere/missing.sh"} {
		if _, read := readIndirectSource(name, cwd); read {
			t.Errorf("%s: a script that is not there was read", name)
		}
	}
	if budget, linkBound := ShareBodyUnreadCauses(); budget || linkBound {
		t.Errorf("a missing script is recorded as an unread body: budget %v, link bound %v", budget, linkBound)
	}
}

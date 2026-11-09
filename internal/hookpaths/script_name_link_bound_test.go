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

// A script named by a path that itself passes folder links is judged by the
// links the system opens, as the script of a call whose working folder is
// behind them: past the bound the body is unread and recorded, within it
// the body is read and nothing is recorded, whatever the spelling of the
// name (rel-1-0-9:GAP-0982). The bound is lowered so that the system reads
// the chain a walk of that bound refuses, which is the situation on a host
// whose file reads do not report the bound themselves (Windows).
func TestScriptNamedThroughLinksIsUnreadPastTheLinkBound(t *testing.T) {
	old := networkLinkHopLimit
	networkLinkHopLimit = 5
	t.Cleanup(func() { networkLinkHopLimit = old })
	for _, links := range []int{1, 4, 5, 6, 8} {
		t.Run(fmt.Sprint(links, " links"), func(t *testing.T) {
			// The links are relative, as the system reads them below a folder.
			base := linkFreeTempDir(t)
			if err := os.Mkdir(filepath.Join(base, "real"), 0o700); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(base, "real", "safe.sh"), []byte("echo ordinary > report.txt\n"), 0o600); err != nil {
				t.Fatal(err)
			}
			for i := links; i >= 1; i-- {
				to := "real"
				if i < links {
					to = fmt.Sprintf("hop%03d", i+1)
				}
				if err := os.Symlink(to, filepath.Join(base, fmt.Sprintf("hop%03d", i))); err != nil {
					t.Skipf("symlink unavailable: %v", err)
				}
			}
			chain := filepath.Join(base, "hop001")
			fakeNetworkShare(t, t.TempDir(), 20*time.Millisecond, time.Second, func(string) {})
			wantRead := links <= networkLinkHopLimit
			for _, name := range []string{
				filepath.Base(chain) + "/safe.sh",
				"./" + filepath.Base(chain) + "/safe.sh",
				base + string(filepath.Separator) + filepath.Base(chain) + "/safe.sh",
			} {
				func() {
					defer HookCall()()
					_, read := readIndirectSource(name, base)
					_, linkBound := ShareBodyUnreadCauses()
					if read != wantRead || linkBound == wantRead || ShareBodyUnread() == wantRead {
						t.Errorf("%s behind %d links: read %v, link bound recorded %v, want read %v", name, links, read, linkBound, wantRead)
					}
				}()
			}
		})
	}
}

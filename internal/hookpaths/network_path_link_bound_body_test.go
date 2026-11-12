// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package hookpaths

import (
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"testing"
	"time"
)

// A script whose folder is reached through more links than the walk follows
// (the links the system opens in one path: 63 on Windows, 40 on Linux, 32 on
// macOS) is a body the call could not read: it is recorded as unread, as a
// body the call budget kept unread is, so the gateway judges it by the policy
// tier (rel-1-0-9:GAP-0621). A chain within the bound reads the script and
// records nothing, on every system (rel-1-0-9:GAP-0935).
func TestScriptBodyBehindMoreLinksThanTheWalkFollowsIsRecordedUnread(t *testing.T) {
	limit := networkLinkHopLimit
	if limit != SystemLinkLimit() {
		t.Fatalf("the walk follows %d links, the system opens %d", limit, SystemLinkLimit())
	}
	// Every count the three systems draw their line at, and those either
	// side of each line; the bound itself decides which are read.
	counts := []int{3, 31, 32, 33, 39, 40, 41, 62, 63, 64, limit - 1, limit, limit + 1, limit + 5}
	slices.Sort(counts)
	for _, links := range slices.Compact(counts) {
		tc := struct {
			links    int
			wantRead bool
		}{links, links <= limit}
		t.Run(fmt.Sprint(tc.links, " links"), func(t *testing.T) {
			// The folders are spelled without a link of their own (macOS keeps
			// /var behind one), so the chain is the links counted.
			dir := linkFreeTempDir(t)
			if err := os.WriteFile(filepath.Join(dir, "safe.sh"), []byte("echo ordinary > report.txt\n"), 0o600); err != nil {
				t.Fatal(err)
			}
			cwd := localLinkChain(t, linkFreeTempDir(t), tc.links, dir)
			fakeNetworkShare(t, t.TempDir(), 20*time.Millisecond, time.Second, func(string) {})
			defer HookCall()()
			_, read := readIndirectSource("safe.sh", cwd)
			budget, linkBound := ShareBodyUnreadCauses()
			if read != tc.wantRead {
				t.Fatalf("script behind %d links: read %v, want %v", tc.links, read, tc.wantRead)
			}
			if ShareBodyUnread() == tc.wantRead || linkBound == tc.wantRead || budget {
				t.Errorf("script behind %d links: unread %v, causes budget %v links %v", tc.links, ShareBodyUnread(), budget, linkBound)
			}
		})
	}
}

// Outside a hook call nothing is recorded.
func TestScriptBodyBehindTooManyLinksOutsideAHookCallRecordsNothing(t *testing.T) {
	dir := linkFreeTempDir(t)
	if err := os.WriteFile(filepath.Join(dir, "safe.sh"), []byte("echo ordinary > report.txt\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	cwd := localLinkChain(t, linkFreeTempDir(t), networkLinkHopLimit+1, dir)
	fakeNetworkShare(t, t.TempDir(), 20*time.Millisecond, time.Second, func(string) {})
	if _, read := readIndirectSource("safe.sh", cwd); read || ShareBodyUnread() {
		t.Errorf("outside a call: read %v, unread recorded %v", read, ShareBodyUnread())
	}
}

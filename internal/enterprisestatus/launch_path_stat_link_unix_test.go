// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package enterprisestatus

import "testing"

// macOS stat -L answers for a dangling link with the link itself (mode
// a1ed, S_IFLNK), where GNU stat and os.Stat give ENOENT. A followed lookup
// never names a link, so that answer is not a directory identity (GAP-1754).
func TestLaunchPathStatOfALinkIsNotAnAnswer(t *testing.T) {
	if id, err := parseLaunchPathStat("16777232 4242 a1ed\n"); err == nil {
		t.Fatalf("a link answer was read as identity %+v", id)
	}
	if id, err := parseLaunchPathStat("16777232 4242 41ed\n"); err != nil || !id.dir {
		t.Fatalf("a directory answer = %+v, %v", id, err)
	}
}

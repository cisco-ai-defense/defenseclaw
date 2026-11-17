// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package effects

import "testing"

// TestNormalizeWindowsFolderIndexAlias: the index alias of a folder
// (dir::$INDEX_ALLOCATION, dir:$I30:$INDEX_ALLOCATION, any case) places the
// file below the folder itself, as the default-stream alias places the file
// (rel-1-0-10:GAP-1075). On the last name the alias names the folder and is
// left as written.
func TestNormalizeWindowsFolderIndexAlias(t *testing.T) {
	o := Options{Flavor: FlavorWindows, CWD: `C:\work`, Dialect: DialectCMD, CaseInsensitive: true}
	want := `c:\users\a\.defenseclaw\config.yaml`
	for _, in := range []string{
		`C:\Users\A\.defenseclaw::$INDEX_ALLOCATION\config.yaml`,
		`C:\Users\A\.defenseclaw::$index_allocation\config.yaml`,
		`C:\Users\A\.defenseclaw:$I30:$INDEX_ALLOCATION\config.yaml`,
		`C:\Users\A\.defenseclaw::$INDEX_ALLOCATION.\config.yaml`,
		`C:\Users\A\.defenseclaw\config.yaml::$DATA`,
	} {
		if got := normalizeWindows(in, o); got != want {
			t.Errorf("normalizeWindows(%q) = %q, want %q", in, got, want)
		}
	}
	if got := normalizeWindows(`C:\Users\A\.defenseclaw::$INDEX_ALLOCATION`, o); got == `c:\users\a\.defenseclaw` {
		t.Errorf("the alias as the last name: %q, want it as written", got)
	}
}

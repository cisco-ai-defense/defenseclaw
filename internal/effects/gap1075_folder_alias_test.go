// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package effects

import "testing"

// TestNormalizeWindowsFolderIndexAlias: the index alias of a folder
// (dir::$INDEX_ALLOCATION, dir:$I30:$INDEX_ALLOCATION, any case) places the
// file below the folder itself, as the default-stream alias places the file
// (rel-1-0-10:GAP-1075), and as the last name it is the folder itself
// (rel-1-0-10:GAP-1079: rd /s /q of the alias removes the folder).
func TestNormalizeWindowsFolderIndexAlias(t *testing.T) {
	o := Options{Flavor: FlavorWindows, CWD: `C:\work`, Dialect: DialectCMD, CaseInsensitive: true}
	for _, tc := range []struct{ in, want string }{
		{`C:\Users\A\.defenseclaw::$INDEX_ALLOCATION\config.yaml`, `c:\users\a\.defenseclaw\config.yaml`},
		{`C:\Users\A\.defenseclaw::$index_allocation\config.yaml`, `c:\users\a\.defenseclaw\config.yaml`},
		{`C:\Users\A\.defenseclaw:$I30:$INDEX_ALLOCATION\config.yaml`, `c:\users\a\.defenseclaw\config.yaml`},
		{`C:\Users\A\.defenseclaw::$INDEX_ALLOCATION.\config.yaml`, `c:\users\a\.defenseclaw\config.yaml`},
		{`C:\Users\A\.defenseclaw\config.yaml::$DATA`, `c:\users\a\.defenseclaw\config.yaml`},
		{`C:\Users\A\.defenseclaw::$INDEX_ALLOCATION`, `c:\users\a\.defenseclaw`},
		{`C:\Users\A\.defenseclaw:$i30:$index_allocation`, `c:\users\a\.defenseclaw`},
		{`C:\Users\A\.defenseclaw:side`, `c:\users\a\.defenseclaw:side`},
	} {
		if got := normalizeWindows(tc.in, o); got != tc.want {
			t.Errorf("normalizeWindows(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

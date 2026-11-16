// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package actionfacts

import "testing"

// TestWindowsWithoutDefaultStream: only a trailing default-stream suffix of
// the last name goes (rel-1-0-10:GAP-1060); a named stream, a suffix on a
// folder name and a bare drive letter stay as written.
func TestWindowsWithoutDefaultStream(t *testing.T) {
	for _, tc := range []struct{ in, want string }{
		{`C:\Users\A\.defenseclaw\config.yaml::$DATA`, `C:\Users\A\.defenseclaw\config.yaml`},
		{`C:/Users/A/.defenseclaw/config.yaml::$data`, `C:/Users/A/.defenseclaw/config.yaml`},
		{`config.yaml::$Data`, `config.yaml`},
		{`C:\Users\A\config.yaml:side:$DATA`, `C:\Users\A\config.yaml:side:$DATA`},
		{`C:\Users\A\config.yaml:side`, `C:\Users\A\config.yaml:side`},
		{`C:\Users\A::$DATA\config.yaml`, `C:\Users\A::$DATA\config.yaml`},
		{`C::$DATA`, `C::$DATA`},
		{`C:\Users\A\config.yaml`, `C:\Users\A\config.yaml`},
		{`C:\Users\A\::$DATA`, `C:\Users\A\::$DATA`},
	} {
		if got := windowsWithoutDefaultStream(tc.in); got != tc.want {
			t.Errorf("windowsWithoutDefaultStream(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
	// The PowerShell reading mints the path fact of the file itself.
	if got, ok := canonicalWindowsFilesystemPath(`C:\Users\A\.defenseclaw\config.yaml::$DATA`); !ok || got != `C:\Users\A\.defenseclaw\config.yaml` {
		t.Errorf("canonicalWindowsFilesystemPath: %q %v, want the file", got, ok)
	}
}

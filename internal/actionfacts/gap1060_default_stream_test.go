// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package actionfacts

import "testing"

// TestWindowsOpenedNames: every Win32 spelling of a file that opens the file
// itself reads as the plain name (rel-1-0-10:GAP-1060, GAP-1075): the
// default-stream suffix in any case, the trailing dots and spaces Win32
// strips, the empty stream name and the index alias of a folder. A named
// stream, a suffix on a folder name, a drive letter, a PowerShell drive and
// the names of an extended-length path that Win32 does not normalize stay as
// written.
func TestWindowsOpenedNames(t *testing.T) {
	const cfg = `C:\Users\A\.defenseclaw\config.yaml`
	for _, tc := range []struct{ in, want string }{
		{cfg + `::$DATA`, cfg},
		{`C:/Users/A/.defenseclaw/config.yaml::$data`, `C:/Users/A/.defenseclaw/config.yaml`},
		{`config.yaml::$Data`, `config.yaml`},
		{cfg + `::$DATA.`, cfg},
		{cfg + `::$DATA `, cfg},
		{cfg + `::$data . `, cfg},
		{cfg + `.`, cfg},
		{cfg + `..`, cfg},
		{cfg + ` `, cfg},
		{cfg + `:`, cfg},
		{cfg + `:.`, cfg},
		{`C:config.yaml::$DATA`, `C:config.yaml`},
		{`C:config.yaml:`, `C:config.yaml`},
		{`C:\Users\A\.defenseclaw::$INDEX_ALLOCATION\config.yaml`, cfg},
		{`C:\Users\A\.defenseclaw:$i30:$index_allocation\config.yaml`, cfg},
		{`C:\Users\A\.defenseclaw.\config.yaml`, cfg},
		{`\\?\` + cfg + `::$DATA`, `\\?\` + cfg},
		{`\\?\` + cfg + `::$DATA.`, `\\?\` + cfg},
		{`\\.\` + cfg + `::$DATA.`, `\\.\` + cfg},
		{`\\server\share\config.yaml::$DATA `, `\\server\share\config.yaml`},
		// As written: another stream, a folder suffix, roots and drives.
		{`C:\Users\A\config.yaml:side:$DATA`, `C:\Users\A\config.yaml:side:$DATA`},
		{`C:\Users\A\config.yaml:side`, `C:\Users\A\config.yaml:side`},
		{`C:\Users\A::$DATA\config.yaml`, `C:\Users\A::$DATA\config.yaml`},
		{`C:\Users\A::$INDEX_ALLOCATION`, `C:\Users\A::$INDEX_ALLOCATION`},
		{`C::$DATA`, `C::$DATA`},
		{`C:\Users\A\::$DATA`, `C:\Users\A\::$DATA`},
		{`C:\Users\A\config.yaml`, `C:\Users\A\config.yaml`},
		{`HKCU:`, `HKCU:`},
		{`HKCU:\Software\x`, `HKCU:\Software\x`},
		{`env:PATH`, `env:PATH`},
		{`C:\Users\A\...\x`, `C:\Users\A\...\x`},
		{`C:\Users\A\..`, `C:\Users\A\..`},
		{`C:\Users\A\...`, `C:\Users\A\...`},
		{`C:\Users\A\x \config.yaml`, `C:\Users\A\x \config.yaml`},
		{`\\?\` + cfg + `.`, `\\?\` + cfg + `.`},
		{`\\?\` + cfg + ` `, `\\?\` + cfg + ` `},
		{`\\server\share.\x`, `\\server\share.\x`},
	} {
		if got := windowsOpenedNames(tc.in); got != tc.want {
			t.Errorf("windowsOpenedNames(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
	// The PowerShell and cmd readings mint the path fact of the file itself.
	for _, in := range []string{cfg + `::$DATA`, cfg + `::$DATA.`, cfg + `::$DATA `, cfg + ` `, cfg + `.`,
		`Microsoft.PowerShell.Core\FileSystem::` + cfg + `::$DATA.`,
		`C:\Users\A\.defenseclaw::$INDEX_ALLOCATION\config.yaml`} {
		if got, ok := windowsCanonicalPathFactValue(in); !ok || got != cfg {
			t.Errorf("windowsCanonicalPathFactValue(%q) = %q %v, want the file", in, got, ok)
		}
	}
	for _, in := range []string{" " + cfg, cfg + "\t", `HKCU:\Software\x `} {
		if got, ok := windowsCanonicalPathFactValue(in); ok {
			t.Errorf("windowsCanonicalPathFactValue(%q) = %q, want unknown", in, got)
		}
	}
}

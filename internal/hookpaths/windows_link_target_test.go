// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package hookpaths

import "testing"

// A Windows link target that starts with one separator names the root of the
// link own drive or share: it is placed there, never beside the link.
func TestWindowsLinkTargetSpellsARootedTargetOnTheVolumeOfItsLink(t *testing.T) {
	psHistory := `\Users\acct\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadLine`
	rows := []struct {
		name, base, target, want string
		ok                       bool
	}{
		{"drive", `C:\Users\acct\project`, psHistory, `C:` + psHistory, true},
		{"lower-case drive", `d:\work\proj`, `\data\x`, `d:\data\x`, true},
		{"slash rooted", `C:\Users\acct\project`, `/Users/acct/x`, `C:/Users/acct/x`, true},
		{"unc share", `\\srv\share\dir\proj`, `\a\b`, `\\srv\share\a\b`, true},
		{"extended drive", `\\?\C:\Users\acct\project`, `\a\b`, `\\?\C:\a\b`, true},
		{"extended unc", `\\?\UNC\srv\share\dir`, `\a\b`, `\\?\UNC\srv\share\a\b`, true},
		{"extended volume id", `\\?\Volume{1234}\dir`, `\a\b`, `\\?\Volume{1234}\a\b`, true},
		{"nt drive spelling", `C:\proj`, `\??\D:\Users\acct`, `D:\Users\acct`, true},
		{"absolute drive stays", `C:\proj`, `D:\x\y`, `D:\x\y`, true},
		{"unc target stays", `C:\proj`, `\\srv\share\x`, `\\srv\share\x`, true},
		{"extended target stays", `C:\proj`, `\\?\C:\x`, `\\?\C:\x`, true},
		{"relative stays", `C:\proj`, `..\other\x`, `..\other\x`, true},
		{"plain name stays", `C:\proj`, `notes.txt`, `notes.txt`, true},
		{"empty stays", `C:\proj`, ``, ``, true},
		{"drive relative has no known place", `C:\proj`, `D:x\y`, ``, false},
		{"bare drive has no known place", `C:\proj`, `D:`, ``, false},
		{"nt unc spelling is not guessed", `C:\proj`, `\??\UNC\srv\share`, ``, false},
		{"rooted target on a base without a volume", `proj`, `\a`, ``, false},
		{"rooted target on a short unc base", `\\srv`, `\a`, ``, false},
	}
	for _, row := range rows {
		got, ok := windowsLinkTarget(row.base, row.target)
		if got != row.want || ok != row.ok {
			t.Errorf("%s: windowsLinkTarget(%q, %q) = %q, %v; want %q, %v", row.name, row.base, row.target, got, ok, row.want, row.ok)
		}
	}
}

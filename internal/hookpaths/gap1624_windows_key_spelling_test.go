// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package hookpaths

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/actionfacts"
)

// rel-1-0-10 GAP-1624: on a Windows host the key path of a Windows home is
// spelled with backslashes. In a POSIX reading the one word resolver removes
// them as escapes; the plain value keeps the spelling, so the key named as
// data next to an unbound output keeps the persistence decision, as on
// rel/1.0.10. The fixture makes no link, so it runs for a standard user too
// (TestBalancedActionEffectRolesIndependent needs a symlink and skips there).
// On another host the key path has no backslash and the row holds as well.
// The rows want the protected-target decision itself, not any decision
// (rel-1-0-10:GAP-1628); on a Windows host the home is also named through
// %USERPROFILE%, quoted, the spelling a Windows tool expands.
func TestGAP1624WindowsKeySpellingKeepsTheMention(t *testing.T) {
	home := t.TempDir()
	cwd := filepath.Join(home, "project")
	if err := os.MkdirAll(filepath.Join(home, ".ssh"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(cwd, 0o700); err != nil {
		t.Fatal(err)
	}
	key := filepath.Join(home, ".ssh", "authorized_keys")
	if err := os.WriteFile(key, []byte("marker\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	commands := []string{
		`echo marker >> "$out"; printf '%s' ` + key,
		`echo marker >> "$out"; printf '%s' "` + key + `"`,
	}
	if runtime.GOOS == "windows" {
		t.Setenv("USERPROFILE", home)
		commands = append(commands, `echo marker >> "$out"; printf '%s' "%USERPROFILE%\.ssh\authorized_keys"`)
	}
	for _, command := range commands {
		if got := ActionCommandDecisionWithDialectAndGlobFacts(command, cwd, home, actionfacts.DialectPOSIX, nil); got != "protected-target" {
			t.Errorf("%q: decision %q, want protected-target (the key named as data next to an unbound output)", command, got)
		}
	}
}

// TestGAP1628PlainValueJudgedOnlyForABackslashOnAWindowsHost pins the
// predicate of the GAP-1624 fix on every host (rel-1-0-10:GAP-1628): the row
// test above can only see it on native Windows, where the key path has a
// backslash, so on Linux and macOS it passed with the fix reverted. The plain
// value of a resolver word is judged again only on a Windows host and only
// for a backslash spelling; a quoted glob pattern keeps its escaped reading
// (rel-1-0-10:GAP-1627).
func TestGAP1628PlainValueJudgedOnlyForABackslashOnAWindowsHost(t *testing.T) {
	for _, tc := range []struct {
		name                         string
		resolverPattern, windowsHost bool
		value                        string
		want                         bool
	}{
		{"plain word, POSIX host", false, false, "/home/me/.ssh/authorized_keys", true},
		{"plain word, Windows host", false, true, `C:\Users\me\.ssh\authorized_keys`, true},
		{"resolver word, backslash key path, Windows host (GAP-1624)", true, true, `C:\Users\me\.ssh\authorized_keys`, true},
		{"resolver word, backslash, POSIX host", true, false, `C:\Users\me\.ssh\authorized_keys`, false},
		{"resolver glob pattern, Windows host (GAP-1627)", true, true, "authorized_key[s]*", false},
		{"resolver glob pattern, POSIX host", true, false, "authorized_key[s]*", false},
	} {
		if got := actionPlainValueJudged(tc.resolverPattern, tc.windowsHost, tc.value); got != tc.want {
			t.Errorf("%s: actionPlainValueJudged(%t, %t, %q) = %t, want %t", tc.name, tc.resolverPattern, tc.windowsHost, tc.value, got, tc.want)
		}
	}
}

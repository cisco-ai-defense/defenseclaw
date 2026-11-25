// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package connector

import (
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/testenv"
)

// GAP-2116: Setup's Windows hooks-dir claim (GAP-1981) compared paths with
// their volume dropped and their . and .. segments unresolved, so a user's
// hook in the same folder on another drive or share, or one that leaves the
// hooks dir through .., was removed or replaced. 1.0.10 kept it. The claim
// and the doctor's Windows leg now compare the resolved, volume-qualified
// paths. DefenseClaw's own hooks dir, in any case, with either separator, a
// doubled separator, a . or .. that stays inside, or under \\?\, is still
// claimed.
func TestGAP2116WindowsHooksDirClaimKeepsOtherVolumesAndDotDot(t *testing.T) {
	dataDir := `C:\Users\fx2116me\.defenseclaw`
	if runtime.GOOS == "windows" {
		dataDir = filepath.Join(testenv.PrivateTempDir(t), "fx2116me", ".defenseclaw")
	}
	if !isWindowsDriveAbsolutePath(dataDir) {
		t.Fatalf("fixture: %q is not a drive path", dataDir)
	}
	hooksDir := dataDir + `\hooks`
	if runtime.GOOS == "windows" {
		hooksDir = filepath.Join(dataDir, "hooks")
	}
	drive, rest := hooksDir[:1], hooksDir[2:] // rest starts with \
	otherDrive := "D"
	if strings.EqualFold(drive, "D") {
		otherDrive = "E"
	}
	forward := strings.ReplaceAll(hooksDir, `\`, "/")
	const script = `\claude-code-hook.old.sh --event PreToolUse`
	kept := map[string]string{
		"other drive":                              otherDrive + ":" + rest + `\review.cmd`,
		"other drive, DefenseClaw name":            otherDrive + ":" + rest + script,
		"UNC share":                                `\\fx2116srv\share` + rest + `\review.cmd`,
		"UNC share, DefenseClaw name":              `\\fx2116srv\share` + rest + script,
		"verbatim UNC share":                       `\\?\UNC\fx2116srv\share` + rest + `\review.cmd`,
		"admin share of the same drive":            `\\localhost\` + drive + "$" + rest + `\review.cmd`,
		"dot-dot out":                              hooksDir + `\..\..\bin\review.exe`,
		"dot-dot out, forward":                     forward + `/../../bin/review.exe`,
		"dot-dot out, mixed case":                  strings.ToUpper(hooksDir) + `/..\..\BIN\Review.exe`,
		"dot-dot out to a DefenseClaw-shaped copy": hooksDir + `\..\..\x\.defenseclaw\hooks` + script,
		"dot-dot out, quoted":                      `"` + hooksDir + `\..\..\bin\review.exe" --flag`,
		"dot-dot with a trailing space":            `'` + hooksDir + `\.. \..\bin\review.exe'`,
		"dot-dot under verbatim":                   `\\?\` + hooksDir + `\..\..\bin\review.exe`,
		"trailing dot on the dir":                  hooksDir + `.\review.cmd`,
		"sibling dir":                              hooksDir + `2\review.exe`,
		"the dir itself":                           hooksDir,
	}
	claimed := map[string]string{
		"backslashes":               hooksDir + script,
		"forward slashes":           forward + `/claude-code-hook.old.sh --event PreToolUse`,
		"mixed separators":          forward + `\claude-code-hook.old.sh --event PreToolUse`,
		"other case":                strings.ToUpper(hooksDir) + `\CLAUDE-CODE-HOOK.OLD.SH --event PreToolUse`,
		"lower-case drive letter":   strings.ToLower(drive) + ":" + rest + script,
		"doubled separator":         hooksDir + `\` + script,
		"dot inside":                hooksDir + `\.` + script,
		"dot-dot that stays inside": hooksDir + `\sub\..` + script,
		"verbatim":                  `\\?\` + hooksDir + script,
		"device":                    `\\.\` + hooksDir + script,
		"double-quoted":             `"` + hooksDir + `\claude-code-hook.old.sh" --event PreToolUse`,
		"single-quoted, other case": `'` + strings.ToUpper(forward) + `/claude-code-hook.old.sh' --event PreToolUse`,
	}
	// A UNC path is opened by the marker check on a Windows host (a network
	// lookup), so there the claim itself is read for it; elsewhere, and for
	// every other case, Setup's whole removal pass runs.
	network := func(command string) bool {
		return runtime.GOOS == "windows" && (strings.Contains(command, `\\fx2116srv`) || strings.Contains(command, `\\localhost`))
	}
	for _, name := range gap1923Names(kept) {
		command := kept[name]
		if hookCommandInWindowsDir(command, hooksDir) {
			t.Errorf("%s: the hooks-dir claim took %q outside %s", name, command, hooksDir)
		}
		if network(command) {
			continue
		}
		handler := map[string]interface{}{"type": "command", "command": command}
		if isOwnedHookHandler(handler, hooksDir) {
			t.Errorf("%s: Setup claimed the user's handler %q (1.0.10 kept it)", name, command)
		}
		remaining, err := removeOwnedClaudeCodeHooks([]interface{}{
			map[string]interface{}{"matcher": "*", "hooks": []interface{}{handler}},
		}, hooksDir, nil)
		if err != nil || len(remaining) != 1 {
			t.Errorf("%s: Claude Code's removal took %q: %v %v", name, command, remaining, err)
		}
	}
	for _, name := range gap1923Names(claimed) {
		command := claimed[name]
		if !hookCommandInWindowsDir(command, hooksDir) {
			t.Errorf("%s: the hooks-dir claim missed %q in %s", name, command, hooksDir)
		}
		handler := map[string]interface{}{"type": "command", "command": command}
		if !isOwnedHookHandler(handler, hooksDir) {
			t.Errorf("%s: Setup kept the handler %q in its own hooks dir", name, command)
		}
		remaining, err := removeOwnedClaudeCodeHooks([]interface{}{
			map[string]interface{}{"matcher": "*", "hooks": []interface{}{handler}},
		}, hooksDir, nil)
		if err != nil || len(remaining) != 0 {
			t.Errorf("%s: Claude Code's removal kept %q: %v %v", name, command, remaining, err)
		}
	}

	// The doctor's Windows leg reports a DefenseClaw-shaped copy exactly when
	// Setup's claim removes it: the copies on another volume or outside the
	// hooks dir are not reported, the ones inside are.
	for _, name := range []string{"other drive, DefenseClaw name", "UNC share, DefenseClaw name", "dot-dot out to a DefenseClaw-shaped copy"} {
		if reported, ok := gap2116DoctorReport(kept[name], dataDir); ok {
			t.Errorf("%s: the doctor reported %q, which Setup keeps", name, reported)
		}
	}
	for _, name := range []string{"backslashes", "forward slashes", "other case", "verbatim"} {
		if reported, ok := gap2116DoctorReport(claimed[name], dataDir); !ok || reported != claimed[name] {
			t.Errorf("%s: the doctor reported %q (%v), want the handler Setup removes %q", name, reported, ok, claimed[name])
		}
	}
}

// The claim on a share: the hooks dir of a data dir on a UNC path claims only
// that share's paths, the \\?\UNC\ form included.
func TestGAP2116WindowsHooksDirClaimOnAShare(t *testing.T) {
	hooksDir := `\\fx2116srv\home\fx2116me\.defenseclaw\hooks`
	for command, want := range map[string]bool{
		hooksDir + `\claude-code-hook.old.sh`:                     true,
		`\\FX2116SRV\HOME/fx2116me/.DefenseClaw/hooks/x.sh`:       true,
		`\\?\UNC\fx2116srv\home\fx2116me\.defenseclaw\hooks\x.sh`: true,
		`\\fx2116srv\other\fx2116me\.defenseclaw\hooks\x.sh`:      false,
		`\\fx2116srv2\home\fx2116me\.defenseclaw\hooks\x.sh`:      false,
		`C:\fx2116me\.defenseclaw\hooks\x.sh`:                     false,
		`\fx2116me\.defenseclaw\hooks\x.sh`:                       false,
		hooksDir + `\..\..\x.sh`:                                  false,
	} {
		if got := hookCommandInWindowsDir(command, hooksDir); got != want {
			t.Errorf("hookCommandInWindowsDir(%q, %q) = %v, want %v", command, hooksDir, got, want)
		}
	}
}

func gap2116DoctorReport(command, dataDir string) (string, bool) {
	document := map[string]interface{}{"hooks": map[string]interface{}{"PreToolUse": []interface{}{
		map[string]interface{}{"matcher": "*", "hooks": []interface{}{
			map[string]interface{}{"type": "command", "command": command},
		}},
	}}}
	return hookDocumentEditedEntry(document, "claudecode", dataDir, "claude-code-hook.sh")
}

// windowsResolvedPath; cli/tests/test_hook_integrity.py checks the Python
// mirror (_windows_resolved_path) on the same table.
func TestGAP2116WindowsResolvedPath(t *testing.T) {
	for _, tc := range []struct {
		name, volume, path string
		ok                 bool
	}{
		{`C:\a\hooks`, "c:", "/a/hooks", true},
		{`c:/A/./b/../Hooks/`, "c:", "/a/hooks", true},
		{`C://a//b`, "c:", "/a/b", true},
		{`\\Srv\Share\a\..\b`, "//srv/share", "/b", true},
		{`\\?\UNC\srv\share\a`, "//srv/share", "/a", true},
		{`\\?\C:\a\b`, "c:", "/a/b", true},
		{`\\.\C:\a\b`, "c:", "/a/b", true},
		{`\\?\C:\a\..\b`, "", "", false},
		{`\\?\C:\a\\b`, "", "", false},
		{`C:\a\.. \b`, "", "", false},
		{`C:\a\hooks.\b`, "", "", false},
		{`C:a\b`, "", "", false},
		{`\a\b`, "", "", false},
	} {
		volume, path, ok := windowsResolvedPath(tc.name)
		if volume != tc.volume || path != tc.path || ok != tc.ok {
			t.Errorf("windowsResolvedPath(%q) = %q, %q, %v, want %q, %q, %v", tc.name, volume, path, ok, tc.volume, tc.path, tc.ok)
		}
	}
}

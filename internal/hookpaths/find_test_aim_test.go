// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package hookpaths

import (
	"path/filepath"
	"testing"
)

// TestFindTestAimsAtAHookFileNotAtItsDecoy (rel-1-0-10:GAP-1572): a find test
// is aimed at a protected file when it matches the file and not the same name
// with its stem swapped for a sentinel (and, for a whole-path test, in a
// sentinel folder); a regex this reader does not read counts as aimed.
func TestFindTestAimsAtAHookFileNotAtItsDecoy(t *testing.T) {
	absRoot := filepath.Join(t.TempDir(), "proj")
	target := filepath.Join(absRoot, ".claude", "settings.json")
	rows := []struct {
		option, pattern, regexType, root string
		want                             bool
	}{
		{"-name", "settings.json", "", ".", true},
		{"-name", "settings.jso[n]", "", ".", true},
		{"-name", "settings.js?n", "", ".", true},
		{"-iname", "SETTINGS.JSO[N]", "", ".", true},
		{"-name", "settings.*", "", ".", true},
		{"-name", "[s]ettings.json", "", ".", true},
		{"-name", "setting?.json", "", ".", true},
		{"-name", "*settings.json", "", ".", true},
		{"-name", "*", "", ".", false},
		{"-name", "*.json", "", ".", false},
		{"-name", "*.tmp", "", ".", false},
		{"-name", "SETTINGS.JSO[N]", "", ".", false},
		{"-path", "*", "", ".", false},
		{"-path", "*.json", "", ".", false},
		{"-path", "*/.claude/*", "", ".", true},
		{"-path", "./.claude/settings.jso[n]", "", ".", true},
		{"-path", "./.claude/*", "", absRoot, false},
		{"-regex", `.*/settings\.json`, "", ".", true},
		{"-iregex", `.*/SETTINGS\.JSON`, "", ".", true},
		{"-regex", "./.claude/settings.json", "", ".", true},
		{"-regex", `.*/\(settings\|hooks\)\.json`, "", ".", true},
		{"-regex", `.*/(settings)\.json`, "posix-extended", ".", true},
		{"-regex", `.*\.json`, "", ".", false},
		{"-regex", `.*`, "", absRoot, false},
		{"-regex", `.*/[a-z]*\.json`, "", ".", false},
		{"-regex", `.*\1`, "", ".", true},
		{"-regex", `.*\.json`, "posix-basic", ".", true},
		{"-regex", `.*[a`, "", ".", true},
		// GNU word anchors, interval escapes and the BSD -E syntax are not
		// read here: aimed (rel-1-0-10:GAP-1572).
		{"-regex", `.*/\<setting[s]\.json`, "", ".", true},
		{"-iregex", `.*/\<SETTING[S]\.JSON`, "", ".", true},
		{"-regex", `.*/\<setting[s]\.json`, "posix-extended", ".", true},
		{"-regex", `.*/setting[s]\>\.json`, "", ".", true},
		{"-regex", `.*/se\{1\}ttings\.json`, "", ".", true},
		{"-regex", `.*/se{1}ttings\.json`, findBSDExtended, ".", true},
		{"-regex", `.*\.json`, findBSDExtended, ".", true},
		// A union with a decoy the pattern spells cannot match the decoy,
		// whose letter the pattern does not contain.
		{"-name", "[sz][ez][ts]*[sl].json", "", ".", true},
		{"-regex", `.*/\(settings\|zzsentinel\)\.json`, "", ".", true},
		{"-regex", `.*/(settings|zzsentinel)\.json`, "posix-extended", ".", true},
		{"-path", "*/[.z][cz]*/[sz]*.json", "", ".", true},
		{"-regex", `.*/s[a-z]*\.json`, "", ".", true},
		{"-iname", "*.JSON", "", ".", false},
		{"-regex", `.*/[a-z]*\.json`, "", absRoot, false},
		{"-name", "zzsentinel.json", "", ".", false},
		{"-name", "[abcdefghijklmnopqrstuvwxyz]*.json", "", ".", true},
	}
	for _, row := range rows {
		test, ok := newFindTest(row.option, row.pattern, row.regexType)
		if !ok {
			t.Fatalf("%s is no find test", row.option)
		}
		if got := test.aimsAt(row.root, absRoot, target); got != row.want {
			t.Errorf("%s %q (regextype %q, root %s) aimed at .claude/settings.json = %v, want %v",
				row.option, row.pattern, row.regexType, row.root, got, row.want)
		}
	}
}

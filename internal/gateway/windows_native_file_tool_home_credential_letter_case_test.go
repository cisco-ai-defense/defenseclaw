// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"strings"
	"testing"
)

// A Windows file system names one file in every letter case, so a native
// Write or Edit of a credential file in the active home gets the verdict of
// the exact-case spelling whatever case the home folders and the file name
// are written in, in every profile and for an account name in any script.
func TestWindowsNativeFileToolWriteOfActiveHomeCredentialFileIsJudgedInAnyLetterCase(t *testing.T) {
	homes := []struct{ home, variant string }{
		{`C:\Users\alice.smith`, `C:\USERS\Alice.Smith`},
		{`C:\Users\Émile`, `C:\Users\émile`},
		{`C:\Users\émile`, `c:\USERS\ÉMILE`},
		{`D:\Profiles\bob`, `d:\profiles\BOB`},
	}
	spellings := map[string][]string{
		".netrc":              {`.NETRC`, `.NetRc`},
		".git-credentials":    {`.GIT-CREDENTIALS`, `.Git-Credentials`},
		".aws/credentials":    {`.AWS\Credentials`, `.Aws/CREDENTIALS`},
		".kube/config":        {`.KUBE\CONFIG`},
		".docker/config.json": {`.Docker\Config.JSON`},
		".npmrc":              {`.NPMRC`},
		".pypirc":             {`.PyPiRC`},
	}
	for _, profile := range []string{"default", "permissive", "strict"} {
		connector := "windows-native-home-credential-case-" + profile
		installToolCallCorpusProfileConnector(t, connector, profile)
		for _, home := range homes {
			for _, credential := range windowsHomeCredentialFiles {
				exactAction, exactRules := windowsFileToolVerdict(t, connector, "Write", home.home, home.home+`\`+strings.ReplaceAll(credential.rel, "/", `\`))
				if len(exactRules) == 0 {
					t.Fatalf("%s home=%q: exact-case write of %s matches no rule", profile, home.home, credential.rel)
				}
				for _, name := range spellings[credential.rel] {
					for _, base := range []string{home.home, home.variant} {
						for _, tool := range []string{"Write", "Edit"} {
							file := base + `\` + strings.ReplaceAll(name, "/", `\`)
							action, rules := windowsFileToolVerdict(t, connector, tool, home.home, file)
							if action != exactAction || !sameRules(rules, exactRules) {
								t.Errorf("%s %s home=%q file=%q: %s %v, want %s %v", profile, tool, home.home, file, action, rules, exactAction, exactRules)
							}
							if credential.rule == "PATH-NETRC" && (action != "block" || !rules[credential.rule]) {
								t.Errorf("%s %s home=%q file=%q: %s %v, want block by %s", profile, tool, home.home, file, action, rules, credential.rule)
							}
						}
					}
				}
			}
		}
	}
}

// A letter that is not ASCII but is the same letter in the case-insensitive
// comparison a Windows file system makes (long s, Kelvin sign, dotless i) names
// the same credential file, so it gets the verdict of the plain spelling. The
// ordinary neighbours spelled the same way, and a read, keep theirs.
func TestWindowsNativeFileToolWriteOfActiveHomeCredentialFileIsJudgedWithCaseEquivalentLetters(t *testing.T) {
	const home = "C:\\Users\\alice.smith"
	protected := []struct{ plain, variant string }{
		{".git-credentials", ".git-credential\u017f"},
		{".git-credentials", ".GIT-CREDENTIAL\u017f"},
		{".git-credentials", ".g\u0131t-credentials"},
		{".aws\\credentials", ".aw\u017f\\credentials"},
		{".aws\\credentials", ".AWS\\CREDENTIAL\u017f"},
		{".aws\\credentials", ".AW\u017f\\CREDENTIAL\u017f"},
		{".kube\\config", ".\u212aube\\config"},
		{".docker\\config.json", ".DOC\u212aER\\CONFIG.JSON"},
	}
	for _, profile := range []string{"default", "permissive", "strict"} {
		connector := "windows-native-home-credential-equivalent-letters-" + profile
		installToolCallCorpusProfileConnector(t, connector, profile)
		for _, pair := range protected {
			plainAction, plainRules := windowsFileToolVerdict(t, connector, "Write", home, home+"\\"+pair.plain)
			if len(plainRules) == 0 {
				t.Fatalf("%s: plain write of %s matches no rule", profile, pair.plain)
			}
			for _, tool := range []string{"Write", "Edit"} {
				file := home + "\\" + pair.variant
				action, rules := windowsFileToolVerdict(t, connector, tool, home, file)
				if action != plainAction || !sameRules(rules, plainRules) {
					t.Errorf("%s %s %q: %s %v, want %s %v", profile, tool, file, action, rules, plainAction, plainRules)
				}
			}
		}
	}
	const connector = "windows-native-home-credential-equivalent-letters-neighbours"
	installToolCallCorpusProfileConnector(t, connector, "default")
	for _, ordinary := range []string{"notes\u017f.txt", "\u212aeys.txt", "Project\\\u017fcript.md", ".git-credential\u017f.example", ".aw\u017f\\config.bak", "\u0131ndex.html"} {
		if action, rules := windowsFileToolVerdict(t, connector, "Write", home, home+"\\"+ordinary); action != "allow" {
			t.Errorf("Write of %s: %s %v, want allow", ordinary, action, rules)
		}
	}
	for _, file := range []string{home + "\\.git-credential\u017f", home + "\\.aw\u017f\\credential\u017f"} {
		if action, _ := windowsFileToolVerdict(t, connector, "Read", home, file); action == "block" {
			t.Errorf("Read of %s blocked, want the alert it had", file)
		}
	}
}

// Ordinary files whose names differ only in letter case from a neighbour of a
// credential file, a read of a credential file in another case, and a write in
// a home that only starts like the active one keep the verdict they had.
func TestWindowsNativeFileToolNeighboursOfActiveHomeCredentialFileKeepTheirVerdictInAnyLetterCase(t *testing.T) {
	const connector = "windows-native-home-credential-case-neighbours"
	installToolCallCorpusProfileConnector(t, connector, "default")
	home := `C:\Users\Émile`
	for _, ordinary := range []string{`NOTES.TXT`, `.NETRC.EXAMPLE`, `.NPMRC.BAK`, `Project\NetRC.md`, `.AWS\Config.bak`} {
		for _, base := range []string{home, `C:\USERS\émile`} {
			for _, tool := range []string{"Write", "Edit"} {
				if action, rules := windowsFileToolVerdict(t, connector, tool, home, base+`\`+ordinary); action != "allow" {
					t.Errorf("%s of %s\\%s: %s %v, want allow", tool, base, ordinary, action, rules)
				}
			}
		}
	}
	for _, file := range []string{`C:\Users\Émile2\notes.txt`, `C:\Users\Émil\notes.txt`} {
		if action, rules := windowsFileToolVerdict(t, connector, "Write", home, file); action != "allow" {
			t.Errorf("Write of %s: %s %v, want allow", file, action, rules)
		}
	}
	for _, file := range []string{`C:\USERS\ÉMILE\.NETRC`, `C:\Users\émile\.NetRc`} {
		if action, _ := windowsFileToolVerdict(t, connector, "Read", home, file); action == "block" {
			t.Errorf("Read of %s blocked, want the alert it had", file)
		}
	}
}

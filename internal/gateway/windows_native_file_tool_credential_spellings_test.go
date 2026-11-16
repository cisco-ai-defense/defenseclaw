// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"context"
	"encoding/json"
	"os"
	"strings"
	"syscall"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/actionfacts"
	"github.com/defenseclaw/defenseclaw/internal/config"
)

// windowsFileToolVerdictIn is windowsFileToolVerdict for a call made from the
// working directory cwd.
func windowsFileToolVerdictIn(t *testing.T, connector, tool, home, cwd, file string) (string, map[string]bool) {
	t.Helper()
	args := map[string]string{"file_path": file}
	switch tool {
	case "Write":
		args["content"] = "# note"
	case "Edit":
		args["old_string"], args["new_string"] = "before", "after"
	}
	raw, err := json.Marshal(args)
	if err != nil {
		t.Fatal(err)
	}
	input := actionfacts.Input{Tool: tool, Args: raw, CWD: cwd, ActiveHome: home}
	findings := dispatchTrustedAction(t.Context(), trustedActionRequest{
		Input: input, LegacyText: string(raw), Connector: connector, EnforcementCapable: true,
	})
	rules := make(map[string]bool)
	for _, finding := range findings {
		rules[finding.RuleID] = true
	}
	return buildVerdict(findings, "tool_call").Action, rules
}

// ownerKeys names each rule by the rule that owns it, so an alias that spells
// the same finding (PATH-WIN-GIT-CREDS for PATH-GIT-CREDS) compares equal.
func ownerKeys(rules map[string]bool) map[string]bool {
	keys := make(map[string]bool, len(rules))
	for id := range rules {
		keys[trustedActionFindingKey(id)] = true
	}
	return keys
}

// Every spelling that opens a credential file of the user's home gets the
// verdict of its plain name, in every profile and from any working
// directory: the 8.3 short name, trailing dots and spaces, the default data
// stream or another one, the extended-length prefix, and the admin share of
// this machine under localhost or a loopback address.
func TestWindowsNativeFileToolCredentialFileIsJudgedInEverySpellingWindowsOpens(t *testing.T) {
	useShortNames(t, map[string]string{
		"NETRC~1": ".netrc", "CREDEN~1": "credentials", "GIT-CR~1": ".git-credentials",
		"CONFIG~1": "config", "R109YW~1": "r109yws.d-2",
		"NTRCFILE": ".netrc", "AWSKEYS": "credentials",
	})
	const home = `C:\Users\r109yws.d-2`
	files := []string{`.netrc`, `.git-credentials`, `.aws\credentials`, `.kube\config`}
	spell := map[string][]string{
		`.netrc`:           {`NETRC~1`, `NTRCFILE`, `.netrc.`, `.netrc  `, `.netrc::$DATA`, `.netrc:stream`, `.netrc:stream:$DATA`, `.NETRC.`},
		`.git-credentials`: {`GIT-CR~1`, `.git-credentials.`, `.git-credentials::$DATA`},
		`.aws\credentials`: {`.aws\CREDEN~1`, `.aws\AWSKEYS`, `.aws\credentials.`, `.aws\credentials::$DATA`, `.aws.\credentials`},
		`.kube\config`:     {`.kube\CONFIG~1`, `.kube\config.`, `.kube\config::$DATA`},
	}
	prefixes := []string{
		home + `\`, `C:\Users\R109YW~1\`, `\\?\` + home + `\`, `\\localhost\c$\Users\r109yws.d-2\`,
		`\\127.0.0.1\C$\Users\r109yws.d-2\`, `\\build-host\c$\Users\r109yws.d-2\`,
	}
	for _, profile := range []string{"default", "permissive", "strict"} {
		connector := "windows-native-credential-spellings-" + profile
		installToolCallCorpusProfileConnector(t, connector, profile)
		for _, file := range files {
			plainAction, plainRules := windowsFileToolVerdictIn(t, connector, "Write", home, home+`\project`, home+`\`+file)
			if len(plainRules) == 0 || plainAction == "allow" {
				t.Fatalf("%s: plain %s: %s %v, want a finding", profile, file, plainAction, plainRules)
			}
			for _, name := range spell[file] {
				for _, prefix := range prefixes {
					if strings.HasPrefix(prefix, `\\?\`) && trailsDotOrSpace(name) {
						continue // a file of its own there: see ...ExtendedLength...
					}
					for _, cwd := range []string{home + `\project`, `C:\work`, `D:\work`} {
						for _, tool := range []string{"Write", "Edit"} {
							target := prefix + name
							action, rules := windowsFileToolVerdictIn(t, connector, tool, home, cwd, target)
							if action != plainAction || !sameRules(ownerKeys(rules), ownerKeys(plainRules)) {
								t.Errorf("%s %s cwd=%q %q: %s %v, want %s %v", profile, tool, cwd, target, action, rules, plainAction, plainRules)
							}
						}
					}
				}
			}
		}
	}
}

// A credential file name in a home-shaped folder outside the active home (a
// fixture home, another account's home, any drive) gets the verdict the same
// name has under a home of the usual shape, whatever the account name is made
// of and wherever the call runs from, a drive root or the folder of all homes
// included. Ordinary files in those folders keep theirs.
func TestWindowsNativeFileToolCredentialFileOutsideTheActiveHomeIsJudgedLikeAnyOtherHome(t *testing.T) {
	const home = `C:\Users\r109yws.d-2`
	homes := []string{
		`C:\r109sfix\home\fixture`, `C:\Users\dcw-std2`, `C:\Users\fixture`, `C:\home\fixture`,
		`D:\Users\bob`, `C:\Users\dcw.std2`, `C:\Users\Émile`, `c:\USERS\Fixture`, `\\localhost\c$\Users\fixture`,
	}
	files := []string{`.netrc`, `.git-credentials`, `.aws\credentials`, `.NETRC`, `.Aws\Credentials`}
	ordinary := []string{`notes.txt`, `.netrc.bak`, `.netrc.example`, `netrc.md`, `project\.netrc.old`, `credentials`, `.aws\config.bak`}
	for _, profile := range []string{"default", "permissive", "strict"} {
		connector := "windows-native-credential-other-home-" + profile
		installToolCallCorpusProfileConnector(t, connector, profile)
		for _, other := range homes {
			// Working directories that do not hold the file: the project of
			// the user, another drive, and the folders that hold every home.
			for _, cwd := range []string{home + `\project`, `D:\work`, `C:\work`, `C:\`, `D:\`, `C:\Users`, `C:\home`} {
				for _, tool := range []string{"Write", "Edit"} {
					for _, file := range files {
						target := other + `\` + file
						if action, rules := windowsFileToolVerdictIn(t, connector, tool, home, cwd, target); action != "block" || len(rules) == 0 {
							t.Errorf("%s %s cwd=%q %q: %s %v, want block", profile, tool, cwd, target, action, rules)
						}
					}
					for _, name := range ordinary {
						target := other + `\` + name
						if action, rules := windowsFileToolVerdictIn(t, connector, tool, home, cwd, target); action != "allow" {
							t.Errorf("%s %s cwd=%q %q: %s %v, want allow", profile, tool, cwd, target, action, rules)
						}
					}
				}
			}
		}
	}
}

// A call that runs in the folder that holds a fixture home keeps writing its
// fixtures, as on the other platforms: a credential name inside the working
// directory of the project is test data, not the file of an account.
func TestWindowsNativeFileToolCredentialFileInsideTheWorkingDirectoryStaysAFixture(t *testing.T) {
	const home = `C:\Users\r109yws.d-2`
	const connector = "windows-native-credential-fixture"
	installToolCallCorpusProfileConnector(t, connector, "default")
	for cwd, target := range map[string]string{
		`C:\r109sfix`:      `C:\r109sfix\home\fixture\.netrc`,
		`C:\r109sfix\proj`: `C:\r109sfix\proj\home\fixture\.git-credentials`,
		`D:\repo\testdata`: `D:\repo\testdata\Users\bob\.aws\credentials`,
	} {
		if action, rules := windowsFileToolVerdictIn(t, connector, "Write", home, cwd, target); action != "allow" {
			t.Errorf("cwd=%q %q: %s %v, want allow", cwd, target, action, rules)
		}
	}
	// The same fixture from outside its project, and the file of the user
	// from inside the same working directory, are not fixtures.
	for cwd, target := range map[string]string{
		`D:\work`:         `C:\r109sfix\home\fixture\.netrc`,
		home + `\project`: home + `\.netrc`,
		home:              home + `\.netrc`,
	} {
		if action, rules := windowsFileToolVerdictIn(t, connector, "Write", home, cwd, target); action != "block" {
			t.Errorf("cwd=%q %q: %s %v, want block", cwd, target, action, rules)
		}
	}
}

// Names that only look like a protected one stay allowed in every spelling:
// a short name of an ordinary file, a stream or trailing dot on an ordinary
// file, credential names not in a home-shaped folder, and a read of a
// credential file keeps the alert it has (never a block).
func TestWindowsNativeFileToolOrdinaryNamesStayAllowedInEverySpellingWindowsOpens(t *testing.T) {
	useShortNames(t, map[string]string{"NOTES~1": "notes.txt", "NETRC~1": ".netrc", "R109YW~1": "r109yws.d-2"})
	const home = `C:\Users\r109yws.d-2`
	const connector = "windows-native-credential-spellings-ordinary"
	installToolCallCorpusProfileConnector(t, connector, "default")
	for _, target := range []string{
		home + `\NOTES~1`, home + `\notes.txt.`, home + `\notes.txt::$DATA`, home + `\project\.netrc.bak`,
		`\\localhost\c$\Users\r109yws.d-2\notes.txt`, `\\127.0.0.1\c$\Users\r109yws.d-2\project\README.md`,
		`C:\r109sfix\.netrc`, `C:\ProgramData\.netrc`, `C:\work\project\.aws\credentials`,
		`\\?\C:\Users\r109yws.d-2\notes.txt`, home + `\project\netrc~1.txt`,
	} {
		for _, tool := range []string{"Write", "Edit"} {
			if action, rules := windowsFileToolVerdictIn(t, connector, tool, home, home+`\project`, target); action != "allow" {
				t.Errorf("%s of %q: %s %v, want allow", tool, target, action, rules)
			}
		}
	}
	for _, target := range []string{home + `\NETRC~1`, home + `\.netrc.`, `C:\Users\fixture\.netrc::$DATA`} {
		if action, rules := windowsFileToolVerdictIn(t, connector, "Read", home, home+`\project`, target); action == "block" {
			t.Errorf("Read of %q blocked: %v, want the alert a read of the plain name has", target, rules)
		}
	}
	// A note that names a credential path stays a note.
	for _, content := range []string{`see C:\Users\fixture\.netrc.`, `see \\localhost\c$\Users\fixture\.netrc`} {
		raw, _ := json.Marshal(map[string]string{"file_path": home + `\project\notes.txt`, "content": content})
		findings := dispatchTrustedAction(t.Context(), trustedActionRequest{
			Input:      actionfacts.Input{Tool: "Write", Args: raw, CWD: home + `\project`, ActiveHome: home},
			LegacyText: string(raw), Connector: connector, EnforcementCapable: true,
		})
		if action := buildVerdict(findings, "tool_call").Action; action != "allow" {
			t.Errorf("note %q: %s %v, want allow", content, action, FindingStrings(findings))
		}
	}
}

// trailsDotOrSpace reports a spelling with a name that ends in a dot or a
// space once its stream suffix is dropped: Win32 drops those characters,
// except in an extended-length path.
func trailsDotOrSpace(spelling string) bool {
	for _, name := range strings.Split(spelling, `\`) {
		if colon := strings.IndexByte(name, ':'); colon >= 0 {
			name = name[:colon]
		}
		if strings.HasSuffix(name, ".") || strings.HasSuffix(name, " ") {
			return true
		}
	}
	return false
}

// Win32 does not normalize an extended-length path: a name with trailing dots
// or spaces there is a file of its own, which is not the protected file and
// gets the verdict of an ordinary name. The same spelling in an ordinary path
// is the protected file (the matrix above), and so are the short name, a
// stream and the admin share in an extended-length path.
func TestWindowsNativeFileToolExtendedLengthTrailingCharactersAreAFileOfItsOwn(t *testing.T) {
	useShortNames(t, map[string]string{"NETRC~1": ".netrc"})
	const home = `C:\Users\r109yws.d-2`
	for _, profile := range []string{"default", "permissive", "strict"} {
		connector := "windows-native-extended-length-" + profile
		installToolCallCorpusProfileConnector(t, connector, profile)
		for _, own := range []string{`.netrc.`, `.netrc  `, `.NETRC.`, `.aws.\credentials`, `.git-credentials.`} {
			for _, tool := range []string{"Write", "Edit"} {
				target := `\\?\` + home + `\` + own
				if action, rules := windowsFileToolVerdictIn(t, connector, tool, home, home+`\project`, target); action != "allow" {
					t.Errorf("%s %s %q: %s %v, want allow (a file of its own)", profile, tool, target, action, rules)
				}
			}
		}
		for _, same := range []string{`\\?\` + home + `\NETRC~1`, `\\?\` + home + `\.netrc::$DATA`, `\\?\` + home + `\.netrc`} {
			if action, rules := windowsFileToolVerdictIn(t, connector, "Write", home, home+`\project`, same); action != "block" {
				t.Errorf("%s Write %q: %s %v, want block", profile, same, action, rules)
			}
		}
	}
}

// A project fixture below a working directory that merely has a home-shaped
// name (a repo folder called home or Users) stays a fixture, on every OS; a
// working directory that really holds the homes of accounts does not make the
// files below it fixtures.
func TestCredentialFixtureInAProjectFolderNamedHomeOrUsersStaysAFixture(t *testing.T) {
	for _, profile := range []string{"default", "permissive", "strict"} {
		connector := "credential-fixture-home-named-project-" + profile
		installToolCallCorpusProfileConnector(t, connector, profile)
		for _, c := range []struct{ home, cwd, target string }{
			{`C:\Users\alice`, `C:\repo\home`, `C:\repo\home\fixture\.netrc`},
			{`C:\Users\alice`, `C:\repo\Users`, `C:\repo\Users\bob\.aws\credentials`},
			{`/home/alice`, `/repo/home`, `/repo/home/fixture/.netrc`},
			{`/home/alice`, `/repo/Users`, `/repo/Users/bob/.git-credentials`},
		} {
			if action, rules := windowsFileToolVerdictIn(t, connector, "Write", c.home, c.cwd, c.target); action != "allow" {
				t.Errorf("%s cwd=%q %q: %s %v, want allow", profile, c.cwd, c.target, action, rules)
			}
		}
		for _, c := range []struct{ home, cwd, target string }{
			{`C:\Users\alice`, `C:\Users`, `C:\Users\bob\.netrc`},
			{`C:\Users\alice`, `C:\`, `C:\Users\bob\.netrc`},
			{`/home/alice`, `/home`, `/home/bob/.netrc`},
			{`/home/alice`, `/`, `/home/bob/.git-credentials`},
		} {
			if action, rules := windowsFileToolVerdictIn(t, connector, "Write", c.home, c.cwd, c.target); action != "block" {
				t.Errorf("%s cwd=%q %q: %s %v, want block", profile, c.cwd, c.target, action, rules)
			}
		}
	}
}

// The folder of a user profile outside Users and home (a profile on another
// drive or in a folder of its own) is a home, found by the entries only a
// profile holds; a folder without them is a project folder, and so is a
// profile folder the file system cannot be asked about.
func TestWindowsNativeFileToolCredentialFileInAProfileFolderIsJudgedLikeAnyOtherHome(t *testing.T) {
	previous := windowsProfileFolder
	t.Cleanup(func() { windowsProfileFolder = previous })
	windowsProfileFolder = func(dir string) (bool, error) {
		switch strings.ToLower(dir) {
		case "c:/profiles/bob", "d:/staff/émile.x", "e:/data/appdata-user":
			return true, nil
		}
		return false, nil
	}
	const home = `C:\Users\r109yws.d-2`
	for _, profile := range []string{"default", "permissive", "strict"} {
		connector := "windows-native-credential-profile-folder-" + profile
		installToolCallCorpusProfileConnector(t, connector, profile)
		for _, cwd := range []string{home + `\project`, `D:\work`, `C:\`} {
			for _, target := range []string{
				`C:\Profiles\bob\.netrc`, `C:\Profiles\BOB\.Git-Credentials`, `C:\Profiles\bob\.aws\credentials`,
				`D:\Staff\Émile.x\.netrc`, `E:\Data\appdata-user\.netrc`, `C:\Profiles\bob\.netrc::$DATA`,
			} {
				if action, rules := windowsFileToolVerdictIn(t, connector, "Write", home, cwd, target); action != "block" || len(rules) == 0 {
					t.Errorf("%s cwd=%q %q: %s %v, want block", profile, cwd, target, action, rules)
				}
			}
			for _, target := range []string{
				`C:\Profiles\bob\notes.txt`, `C:\Profiles\bob\.netrc.bak`, `C:\Profiles\alice\.netrc`,
				`C:\Projects\bob\.aws\credentials`, `C:\work\.netrc`,
			} {
				if action, rules := windowsFileToolVerdictIn(t, connector, "Write", home, cwd, target); action != "allow" {
					t.Errorf("%s cwd=%q %q: %s %v, want allow", profile, cwd, target, action, rules)
				}
			}
		}
	}
}

// windowsFileToolFindings is windowsFileToolVerdictIn that returns the
// findings of the call, for a call that is or is not enforcement-capable.
func windowsFileToolFindings(t *testing.T, connector, tool, home, cwd, file string, capable bool) []RuleFinding {
	t.Helper()
	args := map[string]string{"file_path": file}
	if tool == "Write" {
		args["content"] = "# note"
	}
	raw, err := json.Marshal(args)
	if err != nil {
		t.Fatal(err)
	}
	return dispatchTrustedAction(t.Context(), trustedActionRequest{
		Input:      actionfacts.Input{Tool: tool, Args: raw, CWD: cwd, ActiveHome: home},
		LegacyText: string(raw), Connector: connector, EnforcementCapable: capable,
	})
}

// actionAtProfile is the action the thresholds of a posture profile give the
// findings: strict blocks from MEDIUM, default blocks CRITICAL and alerts from
// MEDIUM, permissive alerts from HIGH.
func actionAtProfile(profile string, findings []RuleFinding) string {
	block, alert := guardrailProfileThresholds(profile)
	return guardrailActionForRank(guardrailSeverityRank(HighestSeverity(findings)), block, alert, false, 0)
}

// Every spelling of the extended-length prefix that Win32 normalizes gets the
// verdict of the plain name, in every profile; the exact backslash prefix
// keeps a name with trailing dots as a file of its own, also when the file
// system is asked for its long form, which would normalize it without the
// prefix.
func TestWindowsNativeFileToolExtendedLengthPrefixIsReadAsWin32ReadsIt(t *testing.T) {
	useWindowsLongPathModel(t, "")
	const home = `C:\Users\r109yws.d-2`
	for _, profile := range []string{"default", "permissive", "strict"} {
		connector := "windows-native-prefix-spellings-" + profile
		installToolCallCorpusProfileConnector(t, connector, profile)
		for _, name := range []string{`.netrc.`, `.netrc  `, `.git-credentials.`, `.aws.\credentials`, `.aws\credentials.`} {
			plain, plainRules := windowsFileToolVerdictIn(t, connector, "Write", home, home+`\project`, home+`\`+name)
			if plain != "block" || len(plainRules) == 0 {
				t.Fatalf("%s: plain %q: %s %v, want block", profile, name, plain, plainRules)
			}
			for _, prefix := range []string{`//?/`, `\/?\`, `/\?/`, `\\.\`, `//./`} {
				for _, tool := range []string{"Write", "Edit"} {
					target := prefix + strings.ReplaceAll(home, `\`, "/") + "/" + strings.ReplaceAll(name, `\`, "/")
					if action, rules := windowsFileToolVerdictIn(t, connector, tool, home, home+`\project`, target); action != "block" {
						t.Errorf("%s %s %q: %s %v, want block like the plain name", profile, tool, target, action, rules)
					}
				}
			}
			own := `\\?\` + home + `\` + name
			if action, rules := windowsFileToolVerdictIn(t, connector, "Write", home, home+`\project`, own); action != "allow" {
				t.Errorf("%s Write %q: %s %v, want allow (a file of its own)", profile, own, action, rules)
			}
		}
	}
}

// A call that changes a path the file system could not be asked about gets a
// finding the profiles judge: the default and permissive profiles show it and
// let the call run, the strict profile closes. A read, a path the file system
// answered for, and a call that cannot enforce are never blocked by it.
func TestWindowsNativeFileToolUnresolvedShortNameLookupIsJudgedByProfile(t *testing.T) {
	useWindowsLongPathModel(t, "c:/users/r109yws.d-2/locked")
	const home = `C:\Users\r109yws.d-2`
	for profile, want := range map[string]string{"default": "alert", "permissive": "alert", "strict": "block"} {
		connector := "windows-native-unresolved-alias-" + profile
		installToolCallCorpusProfileConnector(t, connector, profile)
		for _, tool := range []string{"Write", "Edit"} {
			for _, target := range []string{home + `\locked\NETRC~1`, home + `\locked\notes.txt`, home + `\locked\sub\NTRCFILE`} {
				findings := windowsFileToolFindings(t, connector, tool, home, home+`\project`, target, true)
				var unverified []RuleFinding
				for _, finding := range findings {
					if finding.RuleID == windowsPathUnverifiedRuleID {
						unverified = append(unverified, finding)
					}
				}
				if len(unverified) != 1 {
					t.Errorf("%s %s %q: %d unverified findings %v, want one", profile, tool, target, len(unverified), FindingStrings(findings))
					continue
				}
				if got := actionAtProfile(profile, unverified); got != want {
					t.Errorf("%s %s %q: %s, want %s", profile, tool, target, got, want)
				}
				observed := windowsFileToolFindings(t, connector, tool, home, home+`\project`, target, false)
				for _, finding := range observed {
					if finding.RuleID == windowsPathUnverifiedRuleID && finding.contributesToEnforcement() {
						t.Errorf("%s %s %q: the finding of a call that cannot enforce enforces", profile, tool, target)
					}
				}
			}
			// A folder the file system answered for, and a read, take no finding.
			for _, c := range []struct {
				tool, target string
			}{
				{tool, home + `\project\NETRC~1`}, {tool, home + `\project\notes.txt`}, {"Read", home + `\locked\NETRC~1`},
			} {
				for _, finding := range windowsFileToolFindings(t, connector, c.tool, home, home+`\project`, c.target, true) {
					if finding.RuleID == windowsPathUnverifiedRuleID {
						t.Errorf("%s %s %q: unexpected %s", profile, c.tool, c.target, finding.RuleID)
					}
				}
			}
		}
	}
}

// A credential file of a known home is not a fixture because the call runs
// from that home, or from the folder that holds the homes: the home folder of
// an account in a home folder of a drive, a profile found by its entries, the
// folder that holds profiles, and a drive root that is a profile. A project
// folder in the same places stays a fixture.
func TestWindowsNativeFileToolCredentialFileOfAKnownHomeIsNotAFixtureOfItsOwnWorkingDirectory(t *testing.T) {
	previous := windowsProfileFolder
	t.Cleanup(func() { windowsProfileFolder = previous })
	windowsProfileFolder = func(dir string) (bool, error) {
		switch strings.ToLower(dir) {
		case "c:/profiles/bob", "e:":
			return true, nil
		}
		return false, nil
	}
	const home = `C:\Users\r109yws.d-2`
	for _, profile := range []string{"default", "permissive", "strict"} {
		connector := "windows-native-credential-known-home-" + profile
		installToolCallCorpusProfileConnector(t, connector, profile)
		for _, c := range []struct{ cwd, target string }{
			{`C:\home\fixture`, `C:\home\fixture\.netrc`},
			{`C:\home`, `C:\home\fixture\.aws\credentials`},
			{`C:\Home\Fixture`, `C:\home\fixture\.NETRC`},
			{`C:\Profiles\bob`, `C:\Profiles\bob\.netrc`},
			{`C:\Profiles`, `C:\Profiles\bob\.git-credentials`},
			{`C:\`, `C:\Profiles\bob\.aws\credentials`},
			{`E:\`, `E:\.netrc`},
			{`D:\work`, `E:\.git-credentials`},
		} {
			if action, rules := windowsFileToolVerdictIn(t, connector, "Write", home, c.cwd, c.target); action != "block" || len(rules) == 0 {
				t.Errorf("%s cwd=%q %q: %s %v, want block", profile, c.cwd, c.target, action, rules)
			}
		}
		for _, c := range []struct{ cwd, target string }{
			{`C:\Profiles\bob\project`, `C:\Profiles\bob\project\.netrc`},
			{`C:\repo\home`, `C:\repo\home\fixture\.netrc`},
			{`E:\work`, `E:\work\.netrc`},
			{`C:\Profiles\bob`, `C:\Profiles\bob\notes.txt`},
			{`E:\`, `E:\.netrc.bak`},
		} {
			if action, rules := windowsFileToolVerdictIn(t, connector, "Write", home, c.cwd, c.target); action != "allow" {
				t.Errorf("%s cwd=%q %q: %s %v, want allow", profile, c.cwd, c.target, action, rules)
			}
		}
	}
}

// Only the registry hive proves a user profile: a project that holds a file
// called AppData, an AppData folder, or even the Local and Roaming folders of
// one does not become the profile of an account, so it keeps its credential
// fixtures, while a folder with NTUSER.DAT is a home.
func TestWindowsNativeFileToolProjectWithAppDataFoldersIsNoProfile(t *testing.T) {
	previous := windowsProfileFolder
	t.Cleanup(func() { windowsProfileFolder = previous })
	windowsProfileFolder = func(dir string) (bool, error) {
		return holdsProfileEntries(dir, func(path string) (os.FileInfo, error) {
			switch strings.ToLower(path) {
			case "c:/work/proj/appdata", "c:/work/real/ntuser.dat":
				return fakeEntry{}, nil
			case "c:/work/folder/appdata", "c:/work/folder/appdata/local", "c:/work/folder/appdata/roaming":
				return fakeEntry{folder: true}, nil
			}
			return nil, os.ErrNotExist
		})
	}
	const home = `C:\Users\r109yws.d-2`
	for _, profile := range []string{"default", "permissive", "strict"} {
		connector := "windows-native-credential-appdata-file-" + profile
		installToolCallCorpusProfileConnector(t, connector, profile)
		for _, cwd := range []string{`C:\work\proj`, `C:\work\folder`, `D:\other`} {
			if action, rules := windowsFileToolVerdictIn(t, connector, "Write", home, cwd, `C:\work\real\.netrc`); action != "block" {
				t.Errorf("%s cwd=%q: a folder with NTUSER.DAT: %s %v, want block", profile, cwd, action, rules)
			}
			for _, target := range []string{
				`C:\work\proj\.netrc`, `C:\work\folder\.netrc`, `C:\work\folder\.git-credentials`,
				`C:\work\folder\.aws\credentials`, `C:\work\folder\.netrc.bak`,
			} {
				if action, rules := windowsFileToolVerdictIn(t, connector, "Write", home, cwd, target); action != "allow" {
					t.Errorf("%s cwd=%q %q: a project with AppData entries: %s %v, want allow", profile, cwd, target, action, rules)
				}
			}
		}
	}
}

// A folder whose name ends in a space is a valid Windows folder (a separator
// follows the space), so a file below it is a file of its own, and a dot
// segment after it resolves to its parent: <home>\... \.netrc is not
// <home>\.netrc, and <home>\... \..\.netrc is. The name of the last segment
// has its trailing spaces trimmed, so the plain protected names stay judged by
// their name.
func TestWindowsNativeFileToolFolderWithATrailingSpaceIsAFolderOfItsOwn(t *testing.T) {
	const home = `C:\Users\r109yws.d-2`
	for _, profile := range []string{"default", "permissive", "strict"} {
		connector := "windows-native-credential-trailing-space-folder-" + profile
		installToolCallCorpusProfileConnector(t, connector, profile)
		for _, target := range []string{
			home + `\... \.netrc`, home + `\... \.git-credentials`, home + `\... \.aws\credentials`,
			home + `\.aws \credentials`, home + `\x \.netrc`, home + `\x. \.netrc`,
			home + `\project\... \.netrc`, home + `\.aws \..\.aws.bak`,
		} {
			if action, rules := windowsFileToolVerdictIn(t, connector, "Write", home, home+`\project`, target); action != "allow" {
				t.Errorf("%s %q: %s %v, want allow", profile, target, action, rules)
			}
		}
		for _, target := range []string{
			home + `\... \..\.netrc`, home + `\... \..\.git-credentials`, home + `\... \..\.aws\credentials`,
			home + `\x \..\.netrc`, home + `\.aws \..\.aws\credentials`,
			home + `\.netrc `, home + `\.netrc. `, home + `\.aws.\credentials`, home + `\... \.\..\.netrc`,
		} {
			if action, rules := windowsFileToolVerdictIn(t, connector, "Write", home, home+`\project`, target); action != "block" || len(rules) == 0 {
				t.Errorf("%s %q: %s %v, want block", profile, target, action, rules)
			}
		}
	}
}

// A folder called ... is an ordinary Windows folder name (Win32 keeps a
// segment of three or more periods that a separator follows), so a file below
// it is a file of its own; the same folder in a path with the exact
// extended-length prefix is that file too, and the plain protected names, the
// one-period and trailing-period spellings of them stay judged by their name.
func TestWindowsNativeFileToolThreePeriodFolderIsAFolderOfItsOwn(t *testing.T) {
	const home = `C:\Users\r109yws.d-2`
	for _, profile := range []string{"default", "permissive", "strict"} {
		connector := "windows-native-credential-three-periods-" + profile
		installToolCallCorpusProfileConnector(t, connector, profile)
		for _, target := range []string{
			home + `\...\.netrc`, home + `\...\.aws\credentials`, `\\?\` + home + `\...\.netrc`,
			home + `\....\.git-credentials`, home + `\project\...\.netrc`,
		} {
			if action, rules := windowsFileToolVerdictIn(t, connector, "Write", home, home+`\project`, target); action != "allow" {
				t.Errorf("%s %q: %s %v, want allow", profile, target, action, rules)
			}
		}
		for _, target := range []string{
			home + `\.netrc`, home + `\.\.netrc`, home + `\.netrc.`, home + `\...\..\.netrc`,
			home + `\.aws\credentials`, home + `\x\..\.aws\credentials`, home + `\.aws.\credentials`,
		} {
			if action, rules := windowsFileToolVerdictIn(t, connector, "Write", home, home+`\project`, target); action != "block" || len(rules) == 0 {
				t.Errorf("%s %q: %s %v, want block", profile, target, action, rules)
			}
		}
	}
}

// A mandatory profile keeps its registry hive under the name NTUSER.MAN, and
// a profile folder whose hive the file system refuses to answer for (access
// denied) is no proven profile: the first is a home like any other, judged by
// the name of the file, and the second is judged by the profile of the posture
// (an alert in default and permissive, a block in strict) because the call may
// write a credential file of an account. A project folder with no hive stays
// allowed in every profile.
func TestWindowsNativeFileToolMovedProfileWithAMandatoryOrUnreadableHiveKeepsItsCredentialFiles(t *testing.T) {
	previous := windowsProfileFolder
	t.Cleanup(func() { windowsProfileFolder = previous })
	windowsProfileFolder = func(dir string) (bool, error) {
		return holdsProfileEntries(dir, func(path string) (os.FileInfo, error) {
			switch strings.ToLower(path) {
			case "c:/profiles/mandatory.v6/ntuser.man":
				return fakeEntry{}, nil
			case "c:/profiles/locked/ntuser.dat", "c:/profiles/locked/ntuser.man":
				return nil, os.ErrPermission
			}
			return nil, os.ErrNotExist
		})
	}
	const home = `C:\Users\r109yws.d-2`
	credentials := []string{`.netrc`, `.git-credentials`, `.aws\credentials`}
	for _, profile := range []string{"default", "permissive", "strict"} {
		connector := "windows-native-credential-mandatory-profile-" + profile
		installToolCallCorpusProfileConnector(t, connector, profile)
		for _, cwd := range []string{home + `\project`, `D:\work`, `C:\Profiles\mandatory.v6`} {
			for _, name := range credentials {
				target := `C:\Profiles\mandatory.v6\` + name
				if action, rules := windowsFileToolVerdictIn(t, connector, "Write", home, cwd, target); action != "block" || len(rules) == 0 {
					t.Errorf("%s cwd=%q %q: mandatory profile: %s %v, want block", profile, cwd, target, action, rules)
				}
			}
			for _, target := range []string{`C:\Profiles\mandatory.v6\notes.txt`, `C:\Profiles\mandatory.v6\.netrc.bak`, `C:\work\proj\.netrc`} {
				if action, rules := windowsFileToolVerdictIn(t, connector, "Write", home, cwd, target); action != "allow" {
					t.Errorf("%s cwd=%q %q: %s %v, want allow", profile, cwd, target, action, rules)
				}
			}
		}
		want := map[string]string{"default": "alert", "permissive": "alert", "strict": "block"}[profile]
		for _, name := range credentials {
			target := `C:\Profiles\locked\` + name
			findings := windowsFileToolFindings(t, connector, "Write", home, home+`\project`, target, true)
			var unverified []RuleFinding
			for _, finding := range findings {
				if finding.RuleID == windowsPathUnverifiedRuleID {
					unverified = append(unverified, finding)
				}
			}
			if len(unverified) != 1 {
				t.Errorf("%s %q: %d unverified findings %v, want one", profile, target, len(unverified), FindingStrings(findings))
				continue
			}
			if got := actionAtProfile(profile, unverified); got != want {
				t.Errorf("%s %q: unreadable hive: %s, want %s", profile, target, got, want)
			}
			// A read, and a project folder the file system answered for, take no finding.
			for _, c := range []struct{ tool, target string }{
				{"Read", target}, {"Write", `C:\Profiles\mandatory.v6\` + name}, {"Write", `C:\work\proj\` + name},
			} {
				for _, finding := range windowsFileToolFindings(t, connector, c.tool, home, home+`\project`, c.target, true) {
					if finding.RuleID == windowsPathUnverifiedRuleID {
						t.Errorf("%s %s %q: unexpected %s", profile, c.tool, c.target, finding.RuleID)
					}
				}
			}
		}
	}
}

// A profile folder the file system refuses to answer for is an unanswerable
// check. It is an alert in an OSS default or permissive install and a block in
// the strict tier (asserted above by actionAtProfile), and a managed deployment with local rules closes on it
// whatever its rule pack grades the finding: the default pack blocks only
// CRITICAL, so the managed install must not fall back to an alert.
func TestWindowsNativeFileToolUnreadableProfileHiveClosesInAManagedDeployment(t *testing.T) {
	previous := windowsProfileFolder
	t.Cleanup(func() { windowsProfileFolder = previous })
	windowsProfileFolder = func(dir string) (bool, error) {
		if strings.EqualFold(dir, "C:/Profiles/locked") {
			return false, os.ErrPermission
		}
		return false, nil
	}
	const home = `C:\Users\r109yws.d-2`
	const target = `C:\Profiles\locked\.netrc`
	managedConfig := func(pack string) *config.Config {
		cfg := &config.Config{}
		cfg.DeploymentMode = "managed_enterprise"
		cfg.Enterprise.Profile = "standalone"
		cfg.Guardrail.Mode = "action"
		cfg.Guardrail.RulePack = pack
		return cfg
	}
	perUserConfig := func(pack string) *config.Config {
		cfg := &config.Config{}
		cfg.Guardrail.Mode = "action"
		cfg.Guardrail.RulePack = pack
		return cfg
	}
	cases := []struct {
		name    string
		cfg     *config.Config
		profile string
		capable bool
		tool    string
		want    string
	}{
		{"managed default pack", managedConfig("default"), "default", true, "Write", "block"},
		{"managed permissive pack", managedConfig("permissive"), "permissive", true, "Write", "block"},
		{"managed strict pack", managedConfig("strict"), "strict", true, "Write", "block"},
		{"managed call that cannot enforce", managedConfig("default"), "default", false, "Write", "allow"},
		{"managed read", managedConfig("default"), "default", true, "Read", "allow"},
		{"per-user default", perUserConfig("default"), "default", true, "Write", "alert"},
		{"per-user permissive", perUserConfig("permissive"), "permissive", true, "Write", "alert"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			connector := "windows-native-unreadable-hive-" + strings.ReplaceAll(c.name, " ", "-")
			installToolCallCorpusProfileConnector(t, connector, c.profile)
			findings := windowsFileToolFindings(t, connector, c.tool, home, `D:\work`, target, c.capable)
			api := &APIServer{scannerCfg: c.cfg}
			ctx := context.WithValue(context.Background(), profileRuleScanConnectorKey{}, connector)
			if got := api.buildVerdict(ctx, findings, "tool_call", false).Action; got != c.want {
				t.Errorf("%s: %s, want %s (findings %v)", c.name, got, c.want, FindingStrings(findings))
			}
		})
	}
}

// A lookup of the profile hive that fails for any reason but "the name is not
// there" (an I/O error, a timeout) is cannot-tell, never "not a profile": the
// write of a credential file in that folder alerts in an OSS default or
// permissive install, blocks in the strict tier and in a managed deployment,
// and the finding names the failure. A hive that is absent, or a folder of the
// path that is a file, is a plain no and the project folder stays allowed.
func TestWindowsNativeFileToolProfileHiveLookupFailureIsCannotTell(t *testing.T) {
	const home = `C:\Users\r109yws.d-2`
	const target = `C:\Profiles\moved\.netrc`
	managedConfig := func(pack string) *config.Config {
		cfg := &config.Config{}
		cfg.DeploymentMode = "managed_enterprise"
		cfg.Enterprise.Profile = "standalone"
		cfg.Guardrail.Mode = "action"
		cfg.Guardrail.RulePack = pack
		return cfg
	}
	perUserConfig := func(pack string) *config.Config {
		cfg := &config.Config{}
		cfg.Guardrail.Mode = "action"
		cfg.Guardrail.RulePack = pack
		return cfg
	}
	failures := []struct {
		name    string
		failure error
		named   string
	}{
		{"I/O error", syscall.EIO, syscall.EIO.Error()},
		{"wrapped I/O error", &os.PathError{Op: "stat", Path: "C:/Profiles/moved/NTUSER.MAN", Err: syscall.EIO}, syscall.EIO.Error()},
		{"timeout", os.ErrDeadlineExceeded, os.ErrDeadlineExceeded.Error()},
		{"access denied", os.ErrPermission, os.ErrPermission.Error()},
	}
	cases := []struct {
		name    string
		cfg     *config.Config
		profile string
		want    string
	}{
		{"per-user default", perUserConfig("default"), "default", "alert"},
		{"per-user permissive", perUserConfig("permissive"), "permissive", "alert"},
		{"per-user strict", perUserConfig("strict"), "strict", "block"},
		{"managed default pack", managedConfig("default"), "default", "block"},
		{"managed permissive pack", managedConfig("permissive"), "permissive", "block"},
		{"managed strict pack", managedConfig("strict"), "strict", "block"},
	}
	previous := windowsProfileFolder
	t.Cleanup(func() { windowsProfileFolder = previous })
	for _, failure := range failures {
		windowsProfileFolder = func(dir string) (bool, error) {
			return holdsProfileEntries(dir, func(path string) (os.FileInfo, error) {
				if strings.HasPrefix(strings.ToLower(path), "c:/profiles/moved/") {
					return nil, failure.failure
				}
				return nil, os.ErrNotExist
			})
		}
		for _, c := range cases {
			t.Run(failure.name+" "+c.name, func(t *testing.T) {
				connector := "windows-native-hive-failure-" + strings.ReplaceAll(failure.name+"-"+c.name, " ", "-")
				installToolCallCorpusProfileConnector(t, connector, c.profile)
				findings := windowsFileToolFindings(t, connector, "Write", home, `D:\work`, target, true)
				var unverified []RuleFinding
				for _, finding := range findings {
					if finding.RuleID == windowsPathUnverifiedRuleID {
						unverified = append(unverified, finding)
					}
				}
				if len(unverified) != 1 || !strings.Contains(unverified[0].Title, failure.named) {
					t.Fatalf("findings %v, want one unverified finding that names %q", FindingStrings(findings), failure.named)
				}
				// A managed deployment is decided by its configuration; the
				// OSS postures by the profile (actionAtProfile), as above.
				got := actionAtProfile(c.profile, unverified)
				if c.cfg.EnterpriseProfile() != "" {
					api := &APIServer{scannerCfg: c.cfg}
					ctx := context.WithValue(context.Background(), profileRuleScanConnectorKey{}, connector)
					got = api.buildVerdict(ctx, findings, "tool_call", false).Action
				}
				if got != c.want {
					t.Errorf("%s: %s, want %s", c.name, got, c.want)
				}
			})
		}
	}

	// An answer of "not there" is a plain no: the folder is a project folder.
	for name, absent := range map[string]error{"absent hive": os.ErrNotExist, "folder of the path is a file": syscall.ENOTDIR} {
		windowsProfileFolder = func(dir string) (bool, error) {
			return holdsProfileEntries(dir, func(string) (os.FileInfo, error) { return nil, absent })
		}
		for _, c := range cases {
			t.Run(name+" "+c.name, func(t *testing.T) {
				connector := "windows-native-hive-absent-" + strings.ReplaceAll(name+"-"+c.name, " ", "-")
				installToolCallCorpusProfileConnector(t, connector, c.profile)
				findings := windowsFileToolFindings(t, connector, "Write", home, `D:\work`, target, true)
				for _, finding := range findings {
					if finding.RuleID == windowsPathUnverifiedRuleID {
						t.Fatalf("unexpected %s: %v", finding.RuleID, FindingStrings(findings))
					}
				}
				api := &APIServer{scannerCfg: c.cfg}
				ctx := context.WithValue(context.Background(), profileRuleScanConnectorKey{}, connector)
				if got := api.buildVerdict(ctx, findings, "tool_call", false).Action; got != "allow" {
					t.Errorf("%s: %s, want allow", c.name, got)
				}
			})
		}
	}
}

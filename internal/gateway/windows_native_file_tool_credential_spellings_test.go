// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/actionfacts"
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
	windowsProfileFolder = func(dir string) bool {
		switch strings.ToLower(dir) {
		case "c:/profiles/bob", "d:/staff/émile.x", "e:/data/appdata-user":
			return true
		}
		return false
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

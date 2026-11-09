// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"os"
	"strings"
	"testing"
)

// useShortNames makes the file system answer for 8.3 short names with the
// given long names, and names this machine "build-host".
func useShortNames(t *testing.T, long map[string]string) {
	t.Helper()
	previousExpand, previousHost := expandWindowsShortNames, windowsLocalHostname
	expandWindowsShortNames = func(path string) string {
		for short, name := range long {
			path = strings.ReplaceAll(path, short, name)
		}
		return path
	}
	windowsLocalHostname = func() (string, error) { return "build-host", nil }
	t.Cleanup(func() { expandWindowsShortNames, windowsLocalHostname = previousExpand, previousHost })
}

// A Windows operand is read as the path Windows opens: names with trailing
// dots or spaces, alternate data streams, extended-length and device
// prefixes, the admin share of this machine and 8.3 short names are the
// plain drive path of the file they open. A share of another machine keeps
// its server and share, and a name that merely resembles one is untouched.
func TestWindowsOpenedPathIsTheNameWindowsOpens(t *testing.T) {
	useShortNames(t, map[string]string{"NETRC~1": ".netrc", "NTRCFILE": ".netrc", "R109YW~1": "r109yws.d-2"})
	const home = "C:/Users/r109yws.d-2"
	for spelling, want := range map[string]string{
		`C:\Users\r109yws.d-2\.netrc`:                              home + "/.netrc",
		`c:/Users/r109yws.d-2/.netrc`:                              home + "/.netrc",
		`C:\Users\r109yws.d-2\NETRC~1`:                             home + "/.netrc",
		`C:\Users\r109yws.d-2\NTRCFILE`:                            home + "/.netrc",
		`C:\Users\r109yws.d-2\NTRCFILE.`:                           home + "/.netrc",
		`\\?\C:\Users\r109yws.d-2\NTRCFILE`:                        home + "/.netrc",
		`\\?\C:\Users\r109yws.d-2\.netrc.`:                         home + "/.netrc.",
		`\\?\C:\Users\r109yws.d-2\.netrc  `:                        home + "/.netrc  ",
		`\\?\C:\Users\r109yws.d-2\.aws.\credentials`:               home + "/.aws./credentials",
		`\\?\C:\Users\r109yws.d-2\.netrc::$DATA`:                   home + "/.netrc",
		`\\?\C:\Users\r109yws.d-2\x\..\.netrc`:                     home + "/.netrc",
		`C:\Users\R109YW~1\NETRC~1`:                                home + "/.netrc",
		`C:\Users\r109yws.d-2\.netrc.`:                             home + "/.netrc",
		`C:\Users\r109yws.d-2\.netrc...`:                           home + "/.netrc",
		`C:\Users\r109yws.d-2\.netrc  `:                            home + "/.netrc",
		`C:\Users\r109yws.d-2\.netrc. .`:                           home + "/.netrc",
		`C:\Users\r109yws.d-2\.netrc::$DATA`:                       home + "/.netrc",
		`C:\Users\r109yws.d-2\.netrc:stream`:                       home + "/.netrc",
		`C:\Users\r109yws.d-2\.netrc:stream:$DATA`:                 home + "/.netrc",
		`C:\Users\r109yws.d-2\.aws::$INDEX_ALLOCATION\credentials`: home + "/.aws/credentials",
		`C:\Users\r109yws.d-2\x\..\.netrc`:                         home + "/.netrc",
		`C:\Users\r109yws.d-2\\.\.netrc`:                           home + "/.netrc",
		`\\?\C:\Users\r109yws.d-2\.netrc`:                          home + "/.netrc",
		`\\.\C:\Users\r109yws.d-2\.netrc`:                          home + "/.netrc",
		`\\localhost\c$\Users\r109yws.d-2\.netrc`:                  home + "/.netrc",
		`\\LOCALHOST\C$\Users\r109yws.d-2\.netrc`:                  home + "/.netrc",
		`//127.0.0.1/c$/Users/r109yws.d-2/.netrc`:                  home + "/.netrc",
		`\\127.1.2.3\c$\Users\r109yws.d-2\.netrc`:                  home + "/.netrc",
		`\\0--1.ipv6-literal.net\c$\Users\r109yws.d-2\.netrc`:      home + "/.netrc",
		`\\build-host\c$\Users\r109yws.d-2\.netrc`:                 home + "/.netrc",
		`\\?\UNC\localhost\c$\Users\r109yws.d-2\.netrc`:            home + "/.netrc",
		`\\other-host\c$\Users\r109yws.d-2\.netrc`:                 "//other-host/c$/Users/r109yws.d-2/.netrc",
		`\\localhost\share\Users\r109yws.d-2\.netrc`:               "//localhost/share/Users/r109yws.d-2/.netrc",
		`C:\Users\r109yws.d-2\.netrc.bak`:                          home + "/.netrc.bak",
		`C:\Users\r109yws.d-2\notes~1.txt`:                         home + "/notes~1.txt",
		`C:\Users\r109yws.d-2\.netrc2`:                             home + "/.netrc2",
	} {
		got, ok := windowsOpenedPath(spelling)
		if !ok || got != want {
			t.Errorf("windowsOpenedPath(%q) = %q, %v; want %q", spelling, got, ok, want)
		}
	}
	for _, spelling := range []string{
		"", ".netrc", `relative\.netrc`, "/home/alice/.netrc", "~/.netrc", `\Users\alice\.netrc`,
		`\\?\GLOBALROOT\Device\x\.netrc`, `\\server`, `\\`,
	} {
		if got, ok := windowsOpenedPath(spelling); ok {
			t.Errorf("windowsOpenedPath(%q) = %q, want no Windows path", spelling, got)
		}
	}
}

// The text the path rules read for a Windows path is that of the user's home
// when the path is inside it, and that of any account home otherwise, for an
// account name of any shape and a home folder on any drive or depth. A path
// with no home folder is read as it is.
func TestWindowsRuleTextReadsAnyHomeFolderAsTheRulesWriteIt(t *testing.T) {
	const home = `C:\Users\r109yws.d-2`
	for opened, want := range map[string]string{
		"C:/Users/r109yws.d-2/.NETRC":           "~/.netrc",
		"c:/users/R109YWS.D-2/.Aws/Credentials": "~/.aws/credentials",
		"C:/Users/dcw-std2/.NETRC":              "C:/Users/account/.netrc",
		"C:/USERS/Émile/.Git-Credentials":       "C:/Users/account/.git-credentials",
		"C:/Users/fixture/.NETRC":               "C:/Users/fixture/.netrc",
		"C:/r109sfix/Home/fixture/.NETRC":       "C:/r109sfix/home/fixture/.netrc",
		"D:/home/fixture.x/.kube/Config":        "D:/home/account/.kube/config",
		"C:/r109sfix/.NETRC":                    "C:/r109sfix/.NETRC",
		"C:/Windows/System32/config/SAM":        "C:/Windows/System32/config/SAM",
		"//server/share/Users/bob-1/.NETRC":     "//server/share/Users/account/.netrc",
		"C:/Users/fixture":                      "C:/Users/fixture",
	} {
		if got := windowsRuleText(opened, home); got != want {
			t.Errorf("windowsRuleText(%q) = %q, want %q", opened, got, want)
		}
	}
}

// A file system that has no 8.3 names, or a path that does not exist, leaves
// a short-looking name as written.
func TestWindowsShortNameExpansionLeavesWhatItDoesNotKnow(t *testing.T) {
	path := strings.ReplaceAll(os.TempDir(), `\`, "/") + "/never-created~1/x"
	if windowsRootedSpelling(path) {
		if got := osExpandWindowsShortNames(path); !strings.HasSuffix(got, "/never-created~1/x") {
			t.Errorf("osExpandWindowsShortNames(%q) = %q, want the missing part kept", path, got)
		}
	}
	if got := osExpandWindowsShortNames("/no/such~1/dir"); !strings.HasSuffix(got, "/no/such~1/dir") {
		t.Errorf("osExpandWindowsShortNames of a non-Windows path = %q", got)
	}
}

// Every drive-letter path is asked for its long form, because an 8.3 short
// name need not contain a tilde; a path that is not a drive path is not.
func TestWindowsOpenedPathAsksTheFileSystemForEveryDrivePath(t *testing.T) {
	useShortNames(t, nil)
	var asked []string
	expandWindowsShortNames = func(path string) string {
		asked = append(asked, path)
		return strings.ReplaceAll(path, "NTRCFILE", ".netrc")
	}
	if got, ok := windowsOpenedPath(`C:\Users\bob\NTRCFILE`); !ok || got != "C:/Users/bob/.netrc" {
		t.Errorf("a tilde-free short name read as %q, %v", got, ok)
	}
	if _, ok := windowsOpenedPath(`\\server\share\NTRCFILE`); !ok || len(asked) != 1 {
		t.Errorf("a share path was asked for its long form: %v", asked)
	}
}

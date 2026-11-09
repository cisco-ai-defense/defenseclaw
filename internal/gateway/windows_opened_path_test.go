// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"errors"
	"os"
	"strings"
	"syscall"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/actionfacts"
)

// openedPath is windowsOpenedPath for an operand as the caller wrote it.
func openedPath(spelling string) (string, bool) {
	opened, ok, _ := windowsOpenedPath(spelling, windowsVerbatimOperand(spelling))
	return opened, ok
}

// useShortNames makes the file system answer for 8.3 short names with the
// given long names, and names this machine "build-host".
func useShortNames(t *testing.T, long map[string]string) {
	t.Helper()
	previousExpand, previousHost := expandWindowsShortNames, windowsLocalHostname
	expandWindowsShortNames = func(path string, _ bool) (string, error) {
		for short, name := range long {
			path = strings.ReplaceAll(path, short, name)
		}
		return path, nil
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
		`C:\Users\r109yws.d-2\...\.netrc`:                          home + "/.../.netrc",
		`C:\Users\r109yws.d-2\....\.aws\credentials`:               home + "/..../.aws/credentials",
		`\\?\C:\Users\r109yws.d-2\...\.netrc`:                      home + "/.../.netrc",
		`C:\Users\r109yws.d-2\...\..\.netrc`:                       home + "/.netrc",
		`C:\Users\r109yws.d-2\x\...`:                               home + "/x",
		`C:\Users\r109yws.d-2\x...\.netrc`:                         home + "/x/.netrc",
		`C:\Users\r109yws.d-2\... \.netrc`:                         home + "/... /.netrc",
		`C:\Users\r109yws.d-2\... \..\.netrc`:                      home + "/.netrc",
		`C:\Users\r109yws.d-2\.aws \credentials`:                   home + "/.aws /credentials",
		`C:\Users\r109yws.d-2\x. \.netrc`:                          home + "/x. /.netrc",
		`C:\Users\r109yws.d-2\x \..\.netrc`:                        home + "/.netrc",
		`C:\Users\r109yws.d-2\.aws..\credentials`:                  home + "/.aws/credentials",
		`C:\Users\r109yws.d-2\.netrc \`:                            home + "/.netrc ",
	} {
		got, ok := openedPath(spelling)
		if !ok || got != want {
			t.Errorf("windowsOpenedPath(%q) = %q, %v; want %q", spelling, got, ok, want)
		}
	}
	for _, spelling := range []string{
		"", ".netrc", `relative\.netrc`, "/home/alice/.netrc", "~/.netrc", `\Users\alice\.netrc`,
		`\\?\GLOBALROOT\Device\x\.netrc`, `\\server`, `\\`,
	} {
		if got, ok := openedPath(spelling); ok {
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
		if got, err := osExpandWindowsShortNames(path, false); err != nil || !strings.HasSuffix(got, "/never-created~1/x") {
			t.Errorf("osExpandWindowsShortNames(%q) = %q, %v, want the missing part kept", path, got, err)
		}
	}
	if got, err := osExpandWindowsShortNames("/no/such~1/dir", false); err != nil || !strings.HasSuffix(got, "/no/such~1/dir") {
		t.Errorf("osExpandWindowsShortNames of a non-Windows path = %q, %v", got, err)
	}
}

// Every drive-letter path is asked for its long form, because an 8.3 short
// name need not contain a tilde; a path that is not a drive path is not.
func TestWindowsOpenedPathAsksTheFileSystemForEveryDrivePath(t *testing.T) {
	useShortNames(t, nil)
	var asked []string
	expandWindowsShortNames = func(path string, _ bool) (string, error) {
		asked = append(asked, path)
		return strings.ReplaceAll(path, "NTRCFILE", ".netrc"), nil
	}
	if got, ok := openedPath(`C:\Users\bob\NTRCFILE`); !ok || got != "C:/Users/bob/.netrc" {
		t.Errorf("a tilde-free short name read as %q, %v", got, ok)
	}
	if _, ok := openedPath(`\\server\share\NTRCFILE`); !ok || len(asked) != 1 {
		t.Errorf("a share path was asked for its long form: %v", asked)
	}
}

// useWindowsLongPathModel makes the file system answer as the Windows API
// does: an 8.3 short name is expanded, a path asked without the
// extended-length prefix is normalized (a name loses its trailing dots and
// spaces, so it is answered as the file without them), a path asked with it is
// not, and a path under unreadable cannot be answered at all. It records the
// verbatim flag of each question.
func useWindowsLongPathModel(t *testing.T, unreadable string) *[]bool {
	t.Helper()
	useShortNames(t, nil)
	var asked []bool
	expandWindowsShortNames = func(path string, verbatim bool) (string, error) {
		asked = append(asked, verbatim)
		if unreadable != "" && strings.Contains(strings.ToLower(path), unreadable) {
			return path, errors.New("access is denied")
		}
		names := strings.Split(strings.ReplaceAll(path, "NETRC~1", ".netrc"), "/")
		if !verbatim {
			for index, name := range names {
				names[index] = strings.TrimRight(name, ". ")
			}
		}
		return strings.Join(names, "/"), nil
	}
	return &asked
}

// Only the exact backslash spelling of the extended-length prefix is not
// normalized by Win32: the forward-slash and mixed spellings of it, and the
// device prefix, are ordinary paths whose trailing dots and spaces are
// dropped. The file system is asked for the long name of the exact spelling
// with the prefix, so a name with trailing dots stays a file of its own.
func TestWindowsOpenedPathKeepsTheExactExtendedLengthPrefixThroughShortNameExpansion(t *testing.T) {
	asked := useWindowsLongPathModel(t, "")
	const home = "C:/Users/bob"
	for spelling, want := range map[string]string{
		`\\?\C:\Users\bob\.netrc.`:   home + "/.netrc.",
		`\\?\C:\Users\bob\.netrc  `:  home + "/.netrc  ",
		`\\?\C:\Users\bob\NETRC~1`:   home + "/.netrc",
		`//?/C:/Users/bob/.netrc.`:   home + "/.netrc",
		`\/?\C:\Users\bob\.netrc.`:   home + "/.netrc",
		`/\?/C:/Users/bob/.netrc.  `: home + "/.netrc",
		`//?/C:/Users/bob/NETRC~1.`:  home + "/.netrc",
		`\\.\C:\Users\bob\.netrc.`:   home + "/.netrc",
		`//./C:/Users/bob/.netrc. `:  home + "/.netrc",
		`C:\Users\bob\.netrc.`:       home + "/.netrc",
	} {
		*asked = nil
		fact := actionfacts.PathFact{Value: spelling, Normalized: strings.ReplaceAll(spelling, `\`, "/")}
		got, ok, err := windowsOpenedPathOfFact(fact)
		if !ok || err != nil || got != want {
			t.Errorf("windowsOpenedPathOfFact(%q) = %q, %v, %v; want %q", spelling, got, ok, err, want)
		}
		exact := strings.HasPrefix(spelling, `\\?\`)
		if len(*asked) != 1 || (*asked)[0] != exact {
			t.Errorf("windowsOpenedPathOfFact(%q) asked the file system with verbatim %v, want one question with %v", spelling, *asked, exact)
		}
	}
}

// A file system that cannot answer is reported with the path as written, for
// a drive path; a path that is not one is not asked.
func TestWindowsOpenedPathReportsWhatTheFileSystemCouldNotAnswer(t *testing.T) {
	useWindowsLongPathModel(t, "c:/users/locked")
	got, ok, err := windowsOpenedPath(`C:\Users\Locked\NETRC~1`, false)
	if !ok || err == nil || got != "C:/Users/Locked/NETRC~1" {
		t.Errorf("windowsOpenedPath = %q, %v, %v; want the path as written with an error", got, ok, err)
	}
	if got, ok, err := windowsOpenedPath(`C:\Users\Open\NETRC~1`, false); !ok || err != nil || got != "C:/Users/Open/.netrc" {
		t.Errorf("windowsOpenedPath of an open folder = %q, %v, %v", got, ok, err)
	}
	if _, ok, err := windowsOpenedPath("relative/NETRC~1", false); ok || err != nil {
		t.Errorf("a relative path was asked: %v, %v", ok, err)
	}
}

// A folder called NTUSER.DAT is not the registry hive of a user profile, and
// neither a project file called AppData nor an AppData folder with the Local
// and Roaming folders of a profile proves an account: a project can hold them.
func TestHoldsProfileEntriesNeedsTheKindOfEntryAProfileHolds(t *testing.T) {
	stat := func(entries map[string]bool) func(string) (os.FileInfo, error) {
		return func(path string) (os.FileInfo, error) {
			folder, found := entries[path]
			if !found {
				return nil, os.ErrNotExist
			}
			return fakeEntry{folder: folder}, nil
		}
	}
	for name, c := range map[string]struct {
		entries map[string]bool
		want    bool
	}{
		"AppData profile only": {map[string]bool{"C:/p/AppData": true, "C:/p/AppData/Local": true, "C:/p/AppData/Roaming": true}, false},
		"AppData folder only":  {map[string]bool{"C:/p/AppData": true}, false},
		"NTUSER.DAT file":      {map[string]bool{"C:/p/NTUSER.DAT": false}, true},
		"AppData file":         {map[string]bool{"C:/p/AppData": false}, false},
		"NTUSER.DAT folder":    {map[string]bool{"C:/p/NTUSER.DAT": true}, false},
		"hive and AppData":     {map[string]bool{"C:/p/AppData": true, "C:/p/NTUSER.DAT": false}, true},
		"neither":              {map[string]bool{"C:/p/notes.txt": false}, false},
		"NTUSER.MAN file":      {map[string]bool{"C:/p/NTUSER.MAN": false}, true},
		"NTUSER.MAN folder":    {map[string]bool{"C:/p/NTUSER.MAN": true}, false},
	} {
		if got, err := holdsProfileEntries("C:/p", stat(c.entries)); got != c.want || err != nil {
			t.Errorf("%s: holdsProfileEntries = %v, %v, want %v", name, got, err, c.want)
		}
	}
}

// A refusal of the file system (access denied) to say whether the hive is
// there is not an answer of no: the folder is no proven profile, and the error
// says so. A hive that can be seen proves the profile whatever the other one
// answered.
func TestHoldsProfileEntriesReportsARefusalOfTheFileSystem(t *testing.T) {
	refuse := func(refused map[string]bool) func(string) (os.FileInfo, error) {
		return func(path string) (os.FileInfo, error) {
			switch {
			case refused[path]:
				return nil, os.ErrPermission
			case path == "C:/p/NTUSER.MAN":
				return fakeEntry{}, nil
			}
			return nil, os.ErrNotExist
		}
	}
	if found, err := holdsProfileEntries("C:/q", refuse(map[string]bool{"C:/q/NTUSER.DAT": true})); found || !errors.Is(err, os.ErrPermission) {
		t.Errorf("a refused hive: %v, %v, want false and a refusal", found, err)
	}
	if found, err := holdsProfileEntries("C:/p", refuse(map[string]bool{"C:/p/NTUSER.DAT": true})); !found || err != nil {
		t.Errorf("a mandatory hive beside a refused one: %v, %v, want true", found, err)
	}
	if found, err := holdsProfileEntries("C:/r", refuse(nil)); found || err != nil {
		t.Errorf("no hive: %v, %v, want false and no error", found, err)
	}
}

// Any answer but "the name is not there" is a failure to look, not a no: an
// I/O error is kept and returned, a missing hive (or a folder of the path that
// is a file) is a plain no. A hive that can be seen proves the profile
// whatever the other lookup answered.
func TestHoldsProfileEntriesKeepsEveryFailureToLook(t *testing.T) {
	answer := func(dat, man error) func(string) (os.FileInfo, error) {
		return func(path string) (os.FileInfo, error) {
			switch {
			case strings.HasSuffix(path, "NTUSER.DAT") && dat != nil:
				return nil, dat
			case strings.HasSuffix(path, "NTUSER.MAN") && man != nil:
				return nil, man
			}
			return fakeEntry{}, nil
		}
	}
	for name, c := range map[string]struct {
		dat, man error
		found    bool
		failure  error
	}{
		"I/O error on the first hive":    {syscall.EIO, os.ErrNotExist, false, syscall.EIO},
		"I/O error on the second hive":   {os.ErrNotExist, syscall.EIO, false, syscall.EIO},
		"I/O error beside a refusal":     {syscall.EIO, os.ErrPermission, false, syscall.EIO},
		"timeout":                        {os.ErrDeadlineExceeded, os.ErrNotExist, false, os.ErrDeadlineExceeded},
		"wrapped I/O error":              {&os.PathError{Op: "stat", Path: "C:/p/NTUSER.DAT", Err: syscall.EIO}, os.ErrNotExist, false, syscall.EIO},
		"no hive":                        {os.ErrNotExist, os.ErrNotExist, false, nil},
		"a folder of the path is a file": {syscall.ENOTDIR, syscall.ENOTDIR, false, nil},
		"I/O error beside a seen hive":   {syscall.EIO, nil, true, nil},
	} {
		found, err := holdsProfileEntries("C:/p", answer(c.dat, c.man))
		if found != c.found || !errors.Is(err, c.failure) || (c.failure == nil) != (err == nil) {
			t.Errorf("%s: holdsProfileEntries = %v, %v, want %v, %v", name, found, err, c.found, c.failure)
		}
	}
}

// fakeEntry is a directory entry that is a folder or a file.
type fakeEntry struct {
	os.FileInfo
	folder bool
}

func (e fakeEntry) IsDir() bool { return e.folder }

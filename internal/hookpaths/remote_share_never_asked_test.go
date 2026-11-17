// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package hookpaths

import (
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/actionfacts"
)

// remoteShareSpellings are the spellings Windows opens a share on another
// machine by; {H} is the server, a fresh one for every row.
var remoteShareSpellings = []struct{ name, root string }{
	{"unc-back", `\\{H}\share`},
	{"unc-fwd", "//{H}/share"},
	{"unc-mixed", `\/{H}/share`},
	{"unc-4slash", "////{H}/share"},
	{"unc-server", `\\{H}`},
	{"qunc", `\\?\UNC\{H}\share`},
	{"qunc-fwd", "//?/UNC/{H}/share"},
	{"dunc", `\\.\UNC\{H}\share`},
	{"ntunc", `\??\UNC\{H}\share`},
	{"global-unc", `\\?\Global\UNC\{H}\share`},
	{"globalroot-q", `\\?\GLOBALROOT\Device\Mup\{H}\share`},
	{"globalroot-d", `\\.\GLOBALROOT\Device\Mup\{H}\share`},
	{"globalroot-lanman", `\\?\GLOBALROOT\Device\LanmanRedirector\;Z:0000000000012345\{H}\share`},
	{"globalroot-dos", `\\?\GLOBALROOT\GLOBAL??\UNC\{H}\share`},
	{"webdav-ssl", `\\{H}@SSL\DavWWWRoot`},
	{"webdav-port", `\\{H}@8443\share`},
	{"ipv4", `\\192.0.2.{N}\share`},
	{"ipv6-literal", `\\fd00--{N}.ipv6-literal.net\share`},
}

// remoteShareTails are what an operand names below the share: an ordinary
// file and a protected-looking one.
var remoteShareTails = []string{`team\notes.txt`, `Users\u\.ssh\authorized_keys`}

// localShareSpellings are shares of this machine: the gate asks them as rel
// does.
var localShareSpellings = []string{`\\localhost\C$`, `\\127.0.0.1\C$`, `\\?\UNC\localhost\C$`, `//127.0.0.2/C$`}

// remoteShareReaders are the commands each reader decides, by dialect, with
// the path in {P}.
var remoteShareReaders = []struct {
	dialect   actionfacts.Dialect
	templates []string
}{
	{actionfacts.DialectPOSIX, []string{`cat '{P}'`, `cp notes.txt '{P}'`, `mytool '{P}'`, `mytool --out='{P}'`, `source '{P}'`, `bash -c "cat '{P}'"`}},
	{actionfacts.DialectPowerShell, []string{`Get-Content '{P}'`, `Copy-Item notes.txt '{P}'`, `Set-Content -Path '{P}' -Value x`, `Test-Path '{P}'`, `& mytool '{P}'`, `. '{P}'`, `cmd /c type "{P}"`}},
	{actionfacts.DialectCMD, []string{`type "{P}"`, `copy notes.txt "{P}"`, `echo x > "{P}"`, `mytool "{P}"`, `cd /d "{P}"`, `powershell -Command Get-Content '{P}'`}},
	{actionfacts.DialectNone, []string{`mytool {P}`, `cat {P}`}},
}

// remoteShareDirectReaders are the bounded readers of this package and the
// ones the gateway proofs use.
var remoteShareDirectReaders = map[string]func(string){
	"pathStat":       func(p string) { _, _ = pathStat(p) },
	"pathStatPinned": func(p string) { _, _ = pathStatPinned(p) },
	"pathLstat":      func(p string) { _, _ = pathLstat(p) },
	"pathOpen": func(p string) {
		if f, err := pathOpen(p); err == nil {
			_ = f.Close()
		}
	},
	"pathOpenRoot": func(p string) {
		if r, err := pathOpenRoot(p); err == nil {
			_ = r.Close()
		}
	},
	"pathReadDir":          func(p string) { _, _ = pathReadDir(p) },
	"pathReadlink":         func(p string) { _, _ = pathReadlink(p) },
	"pathEvalSymlinks":     func(p string) { _, _ = pathEvalSymlinks(p) },
	"pathWalkDir":          func(p string) { _ = pathWalkDir(p, func(string, fs.DirEntry, error) error { return filepath.SkipAll }) },
	"Stat":                 func(p string) { _, _ = Stat(p) },
	"Lstat":                func(p string) { _, _ = Lstat(p) },
	"EvalSymlinks":         func(p string) { _, _ = EvalSymlinks(p) },
	"ReadDir":              func(p string) { _, _ = ReadDir(p) },
	"shareAnswersForLinks": func(p string) { _ = shareAnswersForLinks(p) },
}

// remoteShareRow is the spelling with a fresh server for the row. A native run
// sets DC_G1074_HOST_TAG so that the DNS client cache it reads afterwards
// tells its rows from any earlier run.
func remoteShareRow(spelling string, row int) string {
	host := fmt.Sprintf("g1074-%s%04d.example.test", os.Getenv("DC_G1074_HOST_TAG"), row)
	return strings.NewReplacer("{H}", host, "{N}", fmt.Sprint(row%250+1)).Replace(spelling)
}

// countRemoteShareAsks counts the shares the gate asks, keeping the real
// split of this machine's shares from other machines' (thisMachine nil).
func countRemoteShareAsks(t *testing.T, thisMachine func(string) bool) func() int {
	t.Helper()
	var mu sync.Mutex
	asked := 0
	t.Cleanup(OverrideRemoteSharesForTest(func(string) {
		mu.Lock()
		asked++
		mu.Unlock()
	}, thisMachine))
	return func() int {
		mu.Lock()
		defer mu.Unlock()
		return asked
	}
}

// No hook-path reader stats, opens or resolves a share on another machine, in
// any spelling Windows opens one by, on any route: the reader judges it by
// its text (rel-1-0-10:GAP-1074). A share of this machine is asked as before.
// Off Windows the readers read the Windows spellings through the override, so
// that the gate is the same on every host.
func TestRemoteShareSpellingIsNeverAskedOnAnyReader(t *testing.T) {
	asked := countRemoteShareAsks(t, nil)
	home := t.TempDir()
	cwd := filepath.Join(home, "project")
	for _, dir := range []string{filepath.Join(home, ".ssh"), cwd} {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	rows, contacts := 0, map[string]int{}
	check := func(spelling, reader string, read func()) {
		before := asked()
		end := HookCall()
		read()
		end()
		if n := asked() - before; n != 0 {
			contacts[spelling+" "+reader] += n
		}
	}
	for _, s := range remoteShareSpellings {
		for _, tail := range remoteShareTails {
			for name, read := range remoteShareDirectReaders {
				rows++
				path := remoteShareRow(s.root, rows) + `\` + tail
				check(s.name, name, func() { read(path) })
			}
			for _, reader := range remoteShareReaders {
				for _, template := range reader.templates {
					rows++
					command := strings.ReplaceAll(template, "{P}", remoteShareRow(s.root, rows)+`\`+tail)
					check(s.name, string(reader.dialect), func() {
						_ = ActionCommandDecisionWithDialectAndGlobFacts(command, cwd, home, reader.dialect, nil)
					})
				}
			}
		}
	}
	total := 0
	for key, n := range contacts {
		total += n
		t.Errorf("remote share asked %d time(s): %s", n, key)
	}
	t.Logf("GAP1074 rows %d remote contacts %d", rows, total)
	for _, root := range localShareSpellings {
		before := asked()
		_, _ = pathStat(root + `\Windows\win.ini`)
		if asked() == before {
			t.Errorf("a share of this machine (%s) was not asked", root)
		}
	}
}

// A remote share is judged by its text, never as a clean allow because it was
// not read: every finding the decision makes when the share answers (as rel
// read an answering share) it still makes unread. Off Windows only: on Windows
// an answering share is a real read of the network.
func TestRemoteShareUnreadKeepsTheAnsweredDecision(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("an answering share would be read on the network")
	}
	home := t.TempDir()
	cwd := filepath.Join(home, "project")
	for _, dir := range []string{filepath.Join(home, ".ssh"), cwd} {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	decide := func(thisMachine func(string) bool, dialect actionfacts.Dialect, command string) string {
		restore := OverrideRemoteSharesForTest(func(string) {}, thisMachine)
		defer restore()
		end := HookCall()
		defer end()
		return ActionCommandDecisionWithDialectAndGlobFacts(command, cwd, home, dialect, nil)
	}
	rows, weaker := 0, 0
	for _, s := range remoteShareSpellings {
		for _, tail := range remoteShareTails {
			for _, reader := range remoteShareReaders {
				for _, template := range reader.templates {
					rows++
					command := strings.ReplaceAll(template, "{P}", remoteShareRow(s.root, rows)+`\`+tail)
					answered := decide(func(string) bool { return true }, reader.dialect, command)
					unread := decide(nil, reader.dialect, command)
					if answered != "" && unread == "" {
						weaker++
						t.Errorf("%s %s %q: answered %q, unread allows", s.name, reader.dialect, template, answered)
					}
				}
			}
		}
	}
	t.Logf("GAP1074 decision rows %d weaker %d", rows, weaker)
}

// Every Windows spelling of a share names its server (rel-1-0-10:GAP-1074),
// and a share of this machine is told from one of another.
func TestWindowsShareRootSpellings(t *testing.T) {
	for _, s := range remoteShareSpellings {
		path := remoteShareRow(s.root, 7) + `\dir\f.txt`
		root, server := windowsShareRoot(path)
		if root == "" || !strings.HasPrefix(path, root) || server == "" {
			t.Errorf("%s: windowsShareRoot(%q) = %q, %q", s.name, path, root, server)
			continue
		}
		if shareOfThisMachine(root) {
			t.Errorf("%s: %q read as a share of this machine", s.name, root)
		}
	}
	for _, root := range localShareSpellings {
		if got, _ := windowsShareRoot(root + `\x`); got != root || !shareOfThisMachine(got) {
			t.Errorf("windowsShareRoot(%q) = %q, this machine %t", root+`\x`, got, shareOfThisMachine(got))
		}
	}
	for _, path := range []string{`C:\Users\u\.ssh\authorized_keys`, `\\?\C:\Users\u`, `\\.\pipe\name`, `relative\path`,
		`\??\C:\Users\u`, `\\?\GLOBALROOT\Device\HarddiskVolume3\Users`, `\\?\Volume{0}\x`, `\Device\Mup\h\s`, `\\`, `\\?\UNC\`} {
		if root, _ := windowsShareRoot(path); root != "" {
			t.Errorf("windowsShareRoot(%q) = %q, want none", path, root)
		}
	}
}

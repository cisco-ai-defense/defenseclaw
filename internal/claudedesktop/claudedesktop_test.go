// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package claudedesktop

import (
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"
	"testing"
)

// The table is the measured layout (GAP-0024, cowork-1-0-8): both
// deployments on every OS, and the MSIX folders on Windows.
func TestRootsListBothDeploymentsOnEveryOS(t *testing.T) {
	type row struct {
		deployment Deployment
		base       Base
		path       string
		prefer     string
	}
	want := map[string][]row{
		"darwin": {
			{FirstParty, BaseHome, "Library/Application Support/Claude", ""},
			{ThirdParty, BaseHome, "Library/Application Support/Claude-3p", ""},
		},
		"linux": {
			{FirstParty, BaseConfig, "Claude", ""},
			{ThirdParty, BaseConfig, "Claude-3p", ""},
		},
		"windows": {
			{FirstParty, BaseAppData, "Claude", ""},
			{FirstParty, BaseLocalAppData, "Claude-Data/claude_*", "Packages/Claude_*"},
			{FirstParty, BaseLocalAppData, "Packages/Claude_*/LocalCache/Roaming/Claude", ""},
			{ThirdParty, BaseLocalAppData, "Claude-3p", ""},
			{ThirdParty, BaseLocalAppData, "Packages/Claude_*/LocalCache/Local/Claude-3p", ""},
		},
	}
	for goos, rows := range want {
		var got []row
		for _, root := range Roots(goos) {
			got = append(got, row{root.Deployment, root.Base, root.Path, root.Prefer})
		}
		if !reflect.DeepEqual(got, rows) {
			t.Errorf("%s roots = %+v, want %+v", goos, got, rows)
		}
	}
	if len(roots) != len(want) {
		t.Errorf("roots.json lists %d OSes, want %d", len(roots), len(want))
	}
	if Roots("plan9") != nil {
		t.Error("an unknown OS has roots")
	}
	// Roots returns a copy.
	list := Roots("darwin")
	list[0].Path = "x"
	if Roots("darwin")[0].Path == "x" {
		t.Error("Roots shares the table")
	}
}

func TestRootsJSONIsValidated(t *testing.T) {
	for name, raw := range map[string]string{
		"deployment":    `{"darwin":[{"deployment":"2p","base":"home","path":"x"}]}`,
		"windows home":  `{"windows":[{"deployment":"1p","base":"home","path":"x"}]}`,
		"absolute":      `{"darwin":[{"deployment":"1p","base":"home","path":"/x"}]}`,
		"parent":        `{"linux":[{"deployment":"1p","base":"config","path":"../x"}]}`,
		"two globs":     `{"windows":[{"deployment":"1p","base":"localappdata","path":"a*/b*"}]}`,
		"backslash":     `{"windows":[{"deployment":"1p","base":"appdata","path":"a\\b"}]}`,
		"linux appdata": `{"linux":[{"deployment":"1p","base":"appdata","path":"x"}]}`,
		"unknown field": `{"windows":[{"deployment":"1p","base":"appdata","path":"x","msix":true}]}`,
		"prefer, no *":  `{"windows":[{"deployment":"1p","base":"appdata","path":"x","prefer":"y*"}]}`,
		"prefer plain":  `{"windows":[{"deployment":"1p","base":"appdata","path":"x*","prefer":"y"}]}`,
		"glob meta":     `{"windows":[{"deployment":"1p","base":"appdata","path":"x?"}]}`,
		"not json":      `{`,
	} {
		func() {
			defer func() {
				if recover() == nil {
					t.Errorf("%s: roots.json accepted", name)
				}
			}()
			mustParseRoots([]byte(raw))
		}()
	}
}

func TestFolders(t *testing.T) {
	// Absolute on every OS (a Windows path needs its volume).
	home := filepath.Join(t.TempDir(), "u", "alice")
	if got := FoldersForHome("windows", home); got.AppData != filepath.Join(home, "AppData", "Roaming") || got.LocalAppData != filepath.Join(home, "AppData", "Local") || got.Config != "" {
		t.Errorf("windows folders = %+v", got)
	}
	if got := FoldersForHome("linux", home); got.Config != filepath.Join(home, ".config") || got.AppData != "" {
		t.Errorf("linux folders = %+v", got)
	}
	if got := FoldersForHome("darwin", home); got != (Folders{Home: home}) {
		t.Errorf("darwin folders = %+v", got)
	}
	if got := FoldersForHome("linux", ""); got != (Folders{}) {
		t.Errorf("no home = %+v", got)
	}
	abs := filepath.Join(t.TempDir(), "x", "cfg")
	env := map[string]string{"XDG_CONFIG_HOME": abs, "APPDATA": "relative", "LOCALAPPDATA": abs}
	getenv := func(name string) string { return env[name] }
	if got := FoldersFromEnv("linux", home, getenv); got.Config != abs {
		t.Errorf("linux env folders = %+v", got)
	}
	if got := FoldersFromEnv("windows", home, getenv); got.AppData != filepath.Join(home, "AppData", "Roaming") || got.LocalAppData != abs {
		t.Errorf("windows env folders = %+v (a relative APPDATA must be ignored)", got)
	}
}

// filled is root's pattern under f with the "*" filled in.
func filled(root Root, f Folders) string {
	return strings.Replace(root.Pattern(f), "*", "pzs8sxrjxfjjc", 1)
}

// Every root of every OS is found under an account's folders, with its
// deployment; a root with a "*" only when a matching folder exists.
func TestDataAndEngineDirsCoverEveryRoot(t *testing.T) {
	for _, goos := range []string{"darwin", "linux", "windows"} {
		home := t.TempDir()
		f := FoldersForHome(goos, home)
		var fixed []string
		for _, root := range Roots(goos) {
			if !strings.Contains(root.Path, "*") {
				fixed = append(fixed, root.Pattern(f))
			}
		}
		var listed []string
		dirs, overflow := DataDirs(goos, f)
		for _, dir := range dirs {
			listed = append(listed, dir.Path)
		}
		if overflow {
			t.Errorf("%s: overflow without a glob match", goos)
		}
		if !reflect.DeepEqual(listed, fixed) {
			t.Errorf("%s data dirs without MSIX folders = %q, want %q", goos, listed, fixed)
		}
		for _, root := range Roots(goos) {
			if err := os.MkdirAll(filled(root, f), 0o700); err != nil {
				t.Fatal(err)
			}
		}
		dirs, _ = EngineDirs(goos, f)
		if len(dirs) != len(Roots(goos)) {
			t.Fatalf("%s engine dirs = %+v", goos, dirs)
		}
		for i, root := range Roots(goos) {
			want := filepath.Join(filled(root, f), EngineFolder)
			if dirs[i].Path != want || dirs[i].Root != root {
				t.Errorf("%s engine dir %d = %+v, want %s (%s)", goos, i, dirs[i], want, root.Deployment)
			}
		}
	}
	if got, _ := DataDirs("windows", Folders{Home: "/h"}); got != nil {
		t.Errorf("windows without AppData folders = %+v", got)
	}
}

// A "*" root lists at most MaxGlobMatches folders and says when it left one
// out. Folders the user made cannot crowd out the one the installed MSIX
// package uses: its publisher id (Packages\Claude_<id>) is tried first
// (cowork-1-0-8 GAP-0024 review 1).
func TestMSIXGlobOverflowIsReportedAndPrefersThePackage(t *testing.T) {
	home := t.TempDir()
	f := FoldersForHome("windows", home)
	genuine := filepath.Join(f.LocalAppData, "Claude-Data", "claude_pzs8sxrjxfjjc")
	for _, dir := range []string{"claude_0", "claude_1", "claude_2", "claude_3", "claude_pzs8sxrjxfjjc"} {
		if err := os.MkdirAll(filepath.Join(f.LocalAppData, "Claude-Data", dir), 0o700); err != nil {
			t.Fatal(err)
		}
	}
	listed := func() ([]Dir, bool) {
		dirs, overflow := DataDirs("windows", f)
		var data []Dir
		for _, dir := range dirs {
			if strings.Contains(dir.Path, "Claude-Data") {
				data = append(data, dir)
			}
		}
		return data, overflow
	}
	// No package folder: the fifth, genuine folder is left out, and that is
	// reported.
	data, overflow := listed()
	if len(data) != MaxGlobMatches || !overflow || !data[0].Overflow {
		t.Fatalf("Claude-Data folders = %+v overflow=%v", data, overflow)
	}
	for _, dir := range data {
		if dir.Path == genuine {
			t.Fatalf("%s listed although it sorts after the cap", genuine)
		}
	}
	if engines, over := EngineDirs("windows", f); !over || len(engines) == 0 {
		t.Fatalf("EngineDirs overflow = %v", over)
	}
	// The installed package's folder (any case) names the publisher id.
	if err := os.MkdirAll(filepath.Join(f.LocalAppData, "Packages", "claude_PZS8SXRJXFJJC"), 0o700); err != nil {
		t.Fatal(err)
	}
	data, overflow = listed()
	if len(data) != MaxGlobMatches || !overflow || data[0].Path != genuine {
		t.Fatalf("with the package folder, Claude-Data folders = %+v overflow=%v, want %s first", data, overflow, genuine)
	}
	// At the cap nothing overflows.
	for _, dir := range []string{"claude_0", "claude_1"} {
		if err := os.Remove(filepath.Join(f.LocalAppData, "Claude-Data", dir)); err != nil {
			t.Fatal(err)
		}
	}
	if data, overflow = listed(); len(data) != 3 || overflow || data[0].Overflow {
		t.Fatalf("below the cap: %+v overflow=%v", data, overflow)
	}
}

func TestLinuxEngineExecutable(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Windows has no execute bit; the check is for Linux version folders")
	}
	version := filepath.Join(t.TempDir(), "2.1.317")
	if err := os.MkdirAll(filepath.Join(version, "a33aa5518497"), 0o755); err != nil {
		t.Fatal(err)
	}
	if got := LinuxEngineExecutable(version); got != "" {
		t.Fatalf("an empty version folder has engine %s", got)
	}
	engine := filepath.Join(version, "a33aa5518497", "claude")
	if err := os.WriteFile(engine, []byte("ELF"), 0o644); err != nil {
		t.Fatal(err)
	}
	if got := LinuxEngineExecutable(version); got != "" {
		t.Fatalf("a non-executable file is engine %s", got)
	}
	if err := os.Chmod(engine, 0o755); err != nil {
		t.Fatal(err)
	}
	if got := LinuxEngineExecutable(version); got != engine {
		t.Fatalf("engine = %q, want %s", got, engine)
	}
	link := filepath.Join(t.TempDir(), "2.1.318")
	if err := os.MkdirAll(link, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(engine, filepath.Join(link, "claude")); err != nil {
		t.Fatal(err)
	}
	if got := LinuxEngineExecutable(link); got != "" {
		t.Fatalf("a link is engine %s", got)
	}
}

// Each measured engine executable (2026-11-03, Claude Desktop 4.16336.0) is
// recognized as a Claude Desktop engine build by its path, on any OS.
func TestEngineBuildPath(t *testing.T) {
	for _, path := range []string{
		"/Users/ec2-user/Library/Application Support/Claude-3p/claude-code/2.1.317/91184d3d9ba3/claude.app/Contents/MacOS/claude",
		"/Users/ec2-user/Library/Application Support/Claude/claude-code/2.1.317/91184d3d9ba3/claude.app/Contents/MacOS/claude",
		`C:\Users\dcadmin\AppData\Local\Claude-3p\claude-code\2.1.317\a33aa5518497\claude.exe`,
		`C:\Users\dcadmin\AppData\Local\Claude-Data\claude_pzs8sxrjxfjjc\claude-code\2.1.317\a33aa5518497\claude.exe`,
		`C:\Users\dcadmin\AppData\Roaming\Claude\claude-code\2.1.309\claude.exe`,
		`C:\Users\d\AppData\Local\Packages\Claude_pzs8sxrjxfjjc\LocalCache\Roaming\Claude\claude-code\2.1.309\claude.exe`,
		`C:\Users\d\AppData\Local\Packages\Claude_pzs8sxrjxfjjc\LocalCache\Local\Claude-3p\claude-code\2.1.309\claude.exe`,
		"/home/dccw-u1/.config/Claude/claude-code/2.1.317/claude",
		"/home/dccw-u1/.config/Claude-3p/claude-code/2.1.317/claude",
	} {
		if !EngineBuildPath(path) {
			t.Errorf("%s is not an engine build path", path)
		}
	}
	for _, path := range []string{
		"/home/u/.local/share/claude/versions/2.1.317",
		"/home/u/.config/Claude-3p/claude-code",
		"/home/u/.config/Claude-3p/claude-code-vm/2.1.317/claude",
		"/home/u/.config/Claude-4p/claude-code/2.1.317/claude",
		"/usr/lib/node_modules/@anthropic-ai/claude-code/cli.js",
		"",
	} {
		if EngineBuildPath(path) {
			t.Errorf("%s is an engine build path", path)
		}
	}
}

// The folder names EngineBuildPath accepts (and the shell hook renders) are
// the last elements of every root of every OS.
func TestEngineFolderNames(t *testing.T) {
	got := EngineFolderNames()
	if want := []string{"claude", "claude-3p", "claude_*"}; strings.Join(got, ",") != strings.Join(want, ",") {
		t.Fatalf("EngineFolderNames() = %q, want %q", got, want)
	}
	got[0] = "changed"
	if EngineFolderNames()[0] != "claude" {
		t.Fatal("EngineFolderNames returned its own slice")
	}
}

func TestCutEngineDir(t *testing.T) {
	base := t.TempDir()
	for _, goos := range []string{"darwin", "linux", "windows"} {
		home := filepath.Join(base, "home", "alice")
		f := FoldersForHome(goos, home)
		for _, root := range Roots(goos) {
			exe := filepath.Join(filled(root, f), EngineFolder, "2.1.317", "a33aa5518497", "claude")
			rest, ok := CutEngineDir(goos, f, exe)
			if !ok || rest != filepath.Join("2.1.317", "a33aa5518497", "claude") {
				t.Errorf("%s %s: rest %q ok %v", goos, root.Path, rest, ok)
			}
			upper := strings.ReplaceAll(exe, "Claude", "CLAUDE")
			if _, ok := CutEngineDir(goos, f, upper); ok != (goos != "linux") {
				t.Errorf("%s: %s matched %v (case folds only on macOS and Windows)", goos, upper, ok)
			}
			if _, ok := CutEngineDir(goos, f, filepath.Join(filled(root, f), EngineFolder)); ok {
				t.Errorf("%s: the engine folder itself matched", goos)
			}
			other := FoldersForHome(goos, filepath.Join(base, "home", "bob"))
			if _, ok := CutEngineDir(goos, other, exe); ok {
				t.Errorf("%s: alice's engine matched bob's folders", goos)
			}
		}
	}
	if _, ok := CutEngineDir("plan9", Folders{Home: "/h"}, "/h/x/claude-code/1/claude"); ok {
		t.Error("an unknown OS matched")
	}
}

func TestCandidates(t *testing.T) {
	want := map[string][]string{
		"darwin": {"~/Library/Application Support/Claude", "~/Library/Application Support/Claude-3p"},
		"linux":  {"~/.config/Claude", "~/.config/Claude-3p"},
		"windows": {"$APPDATA/Claude", "$LOCALAPPDATA/Claude-Data/claude_*",
			"$LOCALAPPDATA/Packages/Claude_*/LocalCache/Roaming/Claude", "$LOCALAPPDATA/Claude-3p",
			"$LOCALAPPDATA/Packages/Claude_*/LocalCache/Local/Claude-3p"},
	}
	for goos, list := range want {
		var got []string
		for _, root := range Roots(goos) {
			got = append(got, root.Candidate())
		}
		if !reflect.DeepEqual(got, list) {
			t.Errorf("%s candidates = %q, want %q", goos, got, list)
		}
	}
}

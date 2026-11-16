// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

// Package claudedesktop is the one list of the folders Claude Desktop keeps
// its per-user data in, per operating system and deployment. Every caller
// that looks for Claude Desktop's data or for the Claude Code engine it runs
// for Cowork and the Code tab (<data>/claude-code/<version>/...) takes the
// folders from here, so a new folder is added once.
//
// Claude Desktop keeps a separate data folder for each deployment: first
// party (signed in to Claude, "1p") and third-party inference (Amazon
// Bedrock, Google Vertex AI, Microsoft Foundry, "3p"; claude_desktop_config.json
// there says "deploymentMode": "3p"). The deployment of a folder comes from
// the table, not from that file. Measured on 2026-11-03 with Claude Desktop
// 4.16336.0 and engine 2.1.317 (macOS 1p also on 4.4212.0):
//
//	macOS    ~/Library/Application Support/Claude      (1p)
//	         ~/Library/Application Support/Claude-3p   (3p)
//	Windows  %APPDATA%\Claude                          (1p, installer build)
//	         %LOCALAPPDATA%\Claude-Data\claude_<id>    (1p, MSIX package; its
//	                                                   LocalCache\Roaming\Claude
//	                                                   keeps only a marker)
//	         %LOCALAPPDATA%\Claude-3p                  (3p, also for the MSIX
//	                                                   package)
//	Linux    ~/.config/Claude                          (1p)
//
// Linux 3p (~/.config/Claude-3p), the older MSIX folder
// (Packages\Claude_*\LocalCache\Roaming\Claude) and a virtualized MSIX 3p
// folder (Packages\Claude_*\LocalCache\Local\Claude-3p) are not measured;
// they are listed so a build that uses them is found. The table is
// roots.json, which cli/defenseclaw/cowork.py also reads in its tests.
//
// Linux base folder: a process of the account itself (the gateway, the
// per-user CLI) honours an absolute XDG_CONFIG_HOME (FoldersFromEnv). A
// service or administrator scan of another account cannot know that
// account's environment and uses ~/.config (FoldersForHome,
// Root.Candidate). A relative XDG_CONFIG_HOME is ignored, as the XDG Base
// Directory specification requires.
//
// Globs: one element of a root may hold a "*" (an MSIX publisher id). Glob
// reads at most maxGlobEntries entries of the folder the "*" is matched in
// and returns at most MaxGlobMatches paths; its overflow result says a
// match may have been left out, and callers report their coverage as
// incomplete. A root's Prefer names the MSIX package folder whose publisher
// id is tried first, so folders the user made cannot crowd out the one the
// installed package uses.
//
// MSIX migration: once Claude Desktop has moved an MSIX install's data to
// Claude-Data, the old folder keeps only a .user-data-left.<package>
// marker (MigrationMarkerPrefix). Such a folder holds no data.
//
// Trust: a data folder is the user's own, so finding an engine build here
// never identifies it. On macOS and Windows callers trust a build by its
// code signature (internal/codesig), never by the folder it is in, and pick
// the newest build that verifies in each data folder. Linux builds carry no
// vendor signature: a Linux build counts only when its version folder holds
// an executable engine (LinuxEngineExecutable), it is never verified, and
// status reports it as unsigned. Its version still enrolls the account, as
// before, and machine policy's launch coverage keeps treating it as an
// unsigned, user-writable engine, so nothing machine policy covered is
// refused anew.
package claudedesktop

import (
	"bytes"
	_ "embed"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

// Deployment says which Claude Desktop deployment a data folder belongs to.
type Deployment string

const (
	// FirstParty is Claude Desktop signed in to a Claude account.
	FirstParty Deployment = "1p"
	// ThirdParty is Claude Desktop on third-party inference (Bedrock,
	// Vertex AI, Foundry).
	ThirdParty Deployment = "3p"
)

// Base is the per-user folder a data root sits in.
type Base string

const (
	// BaseHome is the user's home folder.
	BaseHome Base = "home"
	// BaseConfig is the Linux user configuration folder ($XDG_CONFIG_HOME,
	// by default ~/.config), where Electron keeps app data.
	BaseConfig Base = "config"
	// BaseAppData is the Windows roaming application data folder
	// (%APPDATA%, by default <home>\AppData\Roaming).
	BaseAppData Base = "appdata"
	// BaseLocalAppData is the Windows local application data folder
	// (%LOCALAPPDATA%, by default <home>\AppData\Local).
	BaseLocalAppData Base = "localappdata"
)

// EngineFolder is the folder under a data root that holds the Claude Code
// engine builds Claude Desktop runs, as <EngineFolder>/<version>/....
const EngineFolder = "claude-code"

// MigrationMarkerPrefix starts the name of the marker Claude Desktop leaves
// in an MSIX data folder it has moved to Claude-Data
// (.user-data-left.claude_<id>, measured on 4.16336.0).
const MigrationMarkerPrefix = ".user-data-left."

// MaxGlobMatches bounds the paths one pattern with a "*" expands to.
const MaxGlobMatches = 4

// maxGlobEntries bounds the entries read from the folder a "*" is matched
// in (a user's Packages folder holds one per installed MSIX app).
const maxGlobEntries = 4096

// Root is one Claude Desktop data folder.
type Root struct {
	Deployment Deployment `json:"deployment"`
	Base       Base       `json:"base"`
	// Path is slash-separated and relative to Base. One element may hold
	// a "*" (an MSIX package or publisher id).
	Path string `json:"path"`
	// Prefer, for a Path with a "*", is a pattern relative to the same base
	// whose "*" values Glob tries first for Path's "*": the MSIX package
	// folder Packages/Claude_<id> names the publisher id of claude_<id>.
	Prefer string `json:"prefer,omitempty"`
}

//go:embed roots.json
var rootsJSON []byte

var roots = mustParseRoots(rootsJSON)

func mustParseRoots(raw []byte) map[string][]Root {
	var table map[string][]Root
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&table); err != nil {
		panic(fmt.Sprintf("claudedesktop: roots.json: %v", err))
	}
	for goos, list := range table {
		for _, root := range list {
			if err := root.validate(goos); err != nil {
				panic(fmt.Sprintf("claudedesktop: roots.json %s: %v", goos, err))
			}
		}
	}
	return table
}

func (r Root) validate(goos string) error {
	switch r.Deployment {
	case FirstParty, ThirdParty:
	default:
		return fmt.Errorf("deployment %q", r.Deployment)
	}
	switch {
	case goos == "windows" && (r.Base == BaseAppData || r.Base == BaseLocalAppData):
	case goos == "linux" && r.Base == BaseConfig:
	case goos != "windows" && r.Base == BaseHome:
	default:
		return fmt.Errorf("base %q", r.Base)
	}
	if !validRelPath(r.Path) {
		return fmt.Errorf("path %q", r.Path)
	}
	if r.Prefer != "" && (!strings.Contains(r.Path, "*") || !validRelPath(r.Prefer) || !strings.Contains(r.Prefer, "*")) {
		return fmt.Errorf("prefer %q", r.Prefer)
	}
	return nil
}

// validRelPath: slash-separated, relative, no "." or ".." elements, and at
// most one "*", which Glob supports.
func validRelPath(path string) bool {
	if path == "" || strings.HasPrefix(path, "/") || strings.ContainsAny(path, `\?[`) || strings.Count(path, "*") > 1 {
		return false
	}
	for _, element := range strings.Split(path, "/") {
		if element == "" || element == "." || element == ".." {
			return false
		}
	}
	return true
}

// Roots returns the data roots of goos ("darwin", "linux", "windows"), first
// party first.
func Roots(goos string) []Root {
	return append([]Root(nil), roots[goos]...)
}

// Folders are the per-user folders of one account that roots are relative
// to. An empty field leaves out the roots on that base.
type Folders struct {
	Home, Config, AppData, LocalAppData string
}

// FoldersForHome returns the default per-user folders of the account whose
// home (profile) folder is home, for a caller that reads another account's
// files (a service, an administrator scan).
func FoldersForHome(goos, home string) Folders {
	if home == "" {
		return Folders{}
	}
	f := Folders{Home: home}
	switch goos {
	case "linux":
		f.Config = filepath.Join(home, ".config")
	case "windows":
		f.AppData = filepath.Join(home, "AppData", "Roaming")
		f.LocalAppData = filepath.Join(home, "AppData", "Local")
	}
	return f
}

// FoldersFromEnv returns the per-user folders of the calling account: those
// of home, with the folders its environment names (XDG_CONFIG_HOME, APPDATA,
// LOCALAPPDATA) when they are absolute.
func FoldersFromEnv(goos, home string, getenv func(string) string) Folders {
	f := FoldersForHome(goos, home)
	if getenv == nil {
		getenv = os.Getenv
	}
	set := func(field *string, name string) {
		if value := strings.TrimSpace(getenv(name)); filepath.IsAbs(value) {
			*field = value
		}
	}
	switch goos {
	case "linux":
		set(&f.Config, "XDG_CONFIG_HOME")
	case "windows":
		set(&f.AppData, "APPDATA")
		set(&f.LocalAppData, "LOCALAPPDATA")
	}
	return f
}

func (f Folders) base(b Base) string {
	switch b {
	case BaseHome:
		return f.Home
	case BaseConfig:
		return f.Config
	case BaseAppData:
		return f.AppData
	case BaseLocalAppData:
		return f.LocalAppData
	}
	return ""
}

// Pattern is the absolute path of r under f, still holding its "*"; "" when
// f does not name r's base.
func (r Root) Pattern(f Folders) string {
	base := f.base(r.Base)
	if base == "" || !filepath.IsAbs(base) {
		return ""
	}
	return filepath.Join(base, filepath.FromSlash(r.Path))
}

// Candidate is r as an AI Discovery catalog path: "~/..." under the home,
// "$APPDATA/..." or "$LOCALAPPDATA/..." on Windows. Linux roots use the
// default ~/.config (a service scan does not know the account's
// XDG_CONFIG_HOME).
func (r Root) Candidate() string {
	switch r.Base {
	case BaseHome:
		return "~/" + r.Path
	case BaseConfig:
		return "~/.config/" + r.Path
	case BaseAppData:
		return "$APPDATA/" + r.Path
	case BaseLocalAppData:
		return "$LOCALAPPDATA/" + r.Path
	}
	return ""
}

// Dir is one data folder (or engine folder) of an account.
type Dir struct {
	Path string
	Root Root
	// Overflow: Root matched more folders than were listed (Glob), so a
	// folder of that root may be missing.
	Overflow bool
}

// DataDirs returns the data folders of goos under f: every root, with a "*"
// expanded by Glob to the folders that exist. A folder is listed whether or
// not it exists unless its root holds a "*". overflow is true when a root's
// glob left a folder out.
func DataDirs(goos string, f Folders) (dirs []Dir, overflow bool) {
	seen := map[string]bool{}
	for _, root := range roots[goos] {
		pattern := root.Pattern(f)
		if pattern == "" {
			continue
		}
		paths, over := Glob(goos, pattern)
		overflow = overflow || over
		for _, path := range paths {
			if key := foldName(goos, path); !seen[key] {
				seen[key] = true
				dirs = append(dirs, Dir{Path: path, Root: root, Overflow: over})
			}
		}
	}
	return dirs, overflow
}

// EngineDirs returns the engine folders (<data>/claude-code) of DataDirs.
func EngineDirs(goos string, f Folders) ([]Dir, bool) {
	dirs, overflow := DataDirs(goos, f)
	for i := range dirs {
		dirs[i].Path = filepath.Join(dirs[i].Path, EngineFolder)
	}
	return dirs, overflow
}

// Glob expands the one "*" of pattern, an absolute path written with this
// OS's separator, to the paths that exist, for goos: sorted, with the paths
// whose "*" is a preferred value (a root's Prefer) first, at most
// MaxGlobMatches. It reads at most maxGlobEntries entries of the folder the
// "*" is matched in, matches names ignoring case on macOS and Windows, and
// does not follow a link in place of that folder's entries. overflow is
// true when a matching path may have been left out. A pattern without "*"
// is returned as is, whether or not it exists.
func Glob(goos, pattern string) (matches []string, overflow bool) {
	if !strings.Contains(pattern, "*") {
		return []string{pattern}, false
	}
	found, overflow := globOne(goos, pattern)
	if len(found) > 1 {
		if preferred := preferredNames(goos, pattern); len(preferred) > 0 {
			sort.SliceStable(found, func(i, j int) bool {
				return preferred[foldName(goos, found[i].name)] && !preferred[foldName(goos, found[j].name)]
			})
		}
	}
	if len(found) > MaxGlobMatches {
		found, overflow = found[:MaxGlobMatches], true
	}
	for _, match := range found {
		matches = append(matches, match.path)
	}
	return matches, overflow
}

type globMatch struct{ path, name string }

// globOne lists the existing paths pattern's one "*" matches, sorted by
// path; overflow when the folder holds more entries than are read.
func globOne(goos, pattern string) (found []globMatch, overflow bool) {
	parent, element, rest, ok := splitGlob(pattern)
	if !ok {
		return nil, false
	}
	dir, err := os.Open(parent)
	if err != nil {
		return nil, false
	}
	defer dir.Close()
	entries, _ := dir.ReadDir(maxGlobEntries + 1)
	if len(entries) > maxGlobEntries {
		entries, overflow = entries[:maxGlobEntries], true
	}
	want := foldName(goos, element)
	for _, entry := range entries {
		name := entry.Name()
		if matched, _ := filepath.Match(want, foldName(goos, name)); !matched {
			continue
		}
		path := filepath.Join(parent, name) + rest
		if rest != "" {
			if _, err := os.Lstat(path); err != nil {
				continue
			}
		}
		found = append(found, globMatch{path: path, name: name})
	}
	sort.Slice(found, func(i, j int) bool { return found[i].path < found[j].path })
	return found, overflow
}

// splitGlob cuts an absolute pattern with exactly one "*" into the folder
// holding the element with the "*", that element and the rest (starting
// with a separator, or "").
func splitGlob(pattern string) (parent, element, rest string, ok bool) {
	star := strings.IndexByte(pattern, '*')
	if star < 0 || strings.Count(pattern, "*") != 1 || !filepath.IsAbs(pattern) {
		return "", "", "", false
	}
	start := strings.LastIndexByte(pattern[:star], os.PathSeparator)
	if start < 0 {
		return "", "", "", false
	}
	end := strings.IndexByte(pattern[star:], os.PathSeparator)
	if end < 0 {
		end = len(pattern)
	} else {
		end += star
	}
	parent = pattern[:start]
	if parent == "" || strings.HasSuffix(parent, ":") {
		parent += string(os.PathSeparator)
	}
	return parent, pattern[start+1 : end], pattern[end:], true
}

// preferredNames are the names pattern's "*" element takes for the values a
// root's Prefer pattern matches next to it: Claude-Data/claude_<id> for each
// Packages/Claude_<id> folder of the same base.
func preferredNames(goos, pattern string) map[string]bool {
	var out map[string]bool
	hay := asciiLower(filepath.ToSlash(pattern)) + "/"
	for _, root := range roots[goos] {
		if root.Prefer == "" {
			continue
		}
		at := strings.Index(hay, "/"+asciiLower(root.Path)+"/")
		if at < 0 {
			continue
		}
		found, _ := globOne(goos, filepath.Join(pattern[:at], filepath.FromSlash(root.Prefer)))
		before, after := starAffixes(root.Prefer)
		wantBefore, wantAfter := starAffixes(root.Path)
		for _, match := range found {
			if len(match.name) < len(before)+len(after) {
				continue
			}
			if out == nil {
				out = map[string]bool{}
			}
			out[foldName(goos, wantBefore+match.name[len(before):len(match.name)-len(after)]+wantAfter)] = true
		}
	}
	return out
}

// starAffixes are the text before and after the "*" in its element of a
// slash-separated path.
func starAffixes(path string) (before, after string) {
	for _, element := range strings.Split(path, "/") {
		if i := strings.IndexByte(element, '*'); i >= 0 {
			return element[:i], element[i+1:]
		}
	}
	return "", ""
}

// foldName is name as goos compares it: lower case on macOS and Windows.
func foldName(goos, name string) string {
	if goos == "windows" || goos == "darwin" {
		return strings.ToLower(name)
	}
	return name
}

// asciiLower lowers ASCII letters only, so byte offsets stay the same.
func asciiLower(s string) string {
	b := []byte(s)
	for i, c := range b {
		if 'A' <= c && c <= 'Z' {
			b[i] = c + 'a' - 'A'
		}
	}
	return string(b)
}

// linuxEngineBuildsMax bounds the build folders one Linux version folder is
// searched for an engine.
const linuxEngineBuildsMax = 4

// LinuxEngineExecutable returns the engine of a Linux version folder
// (<versionDir>/claude, or <versionDir>/<build>/claude like the measured
// macOS and Windows layouts; live check): a regular file, not a link, with
// an execute bit. It is "" when there is none. It reads names and modes
// only and runs nothing. Linux builds carry no vendor signature, so the
// result is the evidence that a build is there, never that it is genuine.
func LinuxEngineExecutable(versionDir string) string {
	executable := func(path string) bool {
		info, err := os.Lstat(path)
		return err == nil && info.Mode().IsRegular() && info.Mode().Perm()&0o111 != 0
	}
	if path := filepath.Join(versionDir, "claude"); executable(path) {
		return path
	}
	if info, err := os.Lstat(versionDir); err != nil || !info.IsDir() {
		return ""
	}
	dir, err := os.Open(versionDir)
	if err != nil {
		return ""
	}
	defer dir.Close()
	entries, _ := dir.ReadDir(64)
	sort.Slice(entries, func(i, j int) bool { return entries[i].Name() < entries[j].Name() })
	checked := 0
	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		if checked++; checked > linuxEngineBuildsMax {
			break
		}
		if path := filepath.Join(versionDir, entry.Name(), "claude"); executable(path) {
			return path
		}
	}
	return ""
}

// EngineBuildPath reports whether path, an executable path of any OS
// (either separator, any case), is inside an engine folder of a data root
// of any OS: the last element of a root's Path (a "*" matches within the
// element) followed by claude-code and at least one more element. It names
// where a process runs from, for classification and attribution; it is not
// a trust decision.
func EngineBuildPath(path string) bool {
	elements := strings.Split(strings.ToLower(strings.ReplaceAll(path, `\`, "/")), "/")
	for i := 0; i+2 < len(elements); i++ {
		if elements[i+1] != EngineFolder || elements[i] == "" {
			continue
		}
		for _, name := range dataFolderNames {
			if ok, _ := filepath.Match(name, elements[i]); ok {
				return true
			}
		}
	}
	return false
}

// EngineFolderNames returns the data folder names EngineBuildPath accepts
// before an engine folder: the last element of every root of every OS, lower
// case and sorted, a "*" matching within the element. The per-user Claude
// Code shell hook renders its engine check from them
// (connector.ClaudeDesktopEngineCaseSH).
func EngineFolderNames() []string {
	return append([]string(nil), dataFolderNames...)
}

// dataFolderNames are the last elements of every root of every OS, lower
// case, with "/" never inside one.
var dataFolderNames = func() []string {
	seen := map[string]bool{}
	var out []string
	for _, list := range roots {
		for _, root := range list {
			name := strings.ToLower(root.Path[strings.LastIndex(root.Path, "/")+1:])
			if !seen[name] {
				seen[name] = true
				out = append(out, name)
			}
		}
	}
	sort.Strings(out)
	return out
}()

// CutEngineDir finds the engine folder of goos under f that holds path and
// returns the rest of path below it (OS separators). A root with a "*"
// matches any one folder name in that place; on Windows and macOS the
// match ignores case.
func CutEngineDir(goos string, f Folders, path string) (rest string, ok bool) {
	fold := goos == "windows" || goos == "darwin"
	sep := string(filepath.Separator)
	clean := filepath.Clean(path)
	for _, root := range roots[goos] {
		pattern := root.Pattern(f)
		if pattern == "" {
			continue
		}
		pattern = filepath.Join(pattern, EngineFolder)
		want := strings.Split(pattern, sep)
		got := strings.Split(clean, sep)
		if len(got) <= len(want) {
			continue
		}
		matched := true
		for i, element := range want {
			have := got[i]
			if fold {
				element, have = strings.ToLower(element), strings.ToLower(have)
			}
			if strings.Contains(element, "*") {
				if ok, _ := filepath.Match(element, have); !ok || have == "" {
					matched = false
					break
				}
				continue
			}
			if element != have {
				matched = false
				break
			}
		}
		if matched {
			return strings.Join(got[len(want):], sep), true
		}
	}
	return "", false
}

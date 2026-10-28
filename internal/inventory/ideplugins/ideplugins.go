// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
// SPDX-License-Identifier: Apache-2.0

// Package ideplugins lists the IDE installations in one user home and the
// extensions or plugins each one has, with their enabled state. It reads
// only small metadata files (extensions.json, package.json, plugin.xml,
// extension.vsixmanifest, extension.toml, bundles.info, lazy-lock.json and
// the VS Code state database), every read is bounded, and nothing is
// executed. It knows nothing about users, hashing or AI signatures: the
// caller attributes and classifies the result.
package ideplugins

import (
	"errors"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"
)

// IDE families.
const (
	FamilyVSCode       = "vscode"
	FamilyJetBrains    = "jetbrains"
	FamilyVisualStudio = "visualstudio"
	FamilyZed          = "zed"
	FamilyEclipse      = "eclipse"
	FamilyVim          = "vim"
)

// Enabled states. They match the defenseclaw.ide.plugin.enabled enum.
const (
	EnabledOn                = "enabled"
	EnabledOff               = "disabled"
	EnabledClientSideUnknown = "client_side_unknown"
	EnabledUnknown           = "unknown"
)

// Where an enabled state came from.
const (
	SourceStateDB         = "state_vscdb"
	SourceDefault         = "default"
	SourceRemoteServer    = "remote_server"
	SourceDisabledPlugins = "disabled_plugins_txt"
	SourcePrivateRegistry = "privateregistry"
	SourceAlways          = "always"
	SourceLockfile        = "lockfile"
	SourcePackStart       = "pack_start"
	SourcePackOpt         = "pack_opt"
	SourcePluginDir       = "plugin_dir"
	SourceBundlesInfo     = "bundles_info"
	SourceUnknown         = "unknown"
)

// Remote kinds.
const (
	RemoteSSHServer       = "ssh_server"
	RemoteJetBrainsDevEnv = "jetbrains_remote_dev"
)

// Plugin scopes.
const (
	ScopeUser    = "user"
	ScopeRemote  = "remote"
	ScopeMachine = "machine"
)

// Defaults for Limits.
const (
	DefaultMaxPlugins     = 4096
	DefaultMaxFiles       = 16384
	DefaultMaxBytes       = 64 << 20
	DefaultMaxFileBytes   = 1 << 20
	DefaultStateDBTimeout = 2 * time.Second

	maxFieldLen = 256
	// maxProductLen bounds an installation's product token, as the
	// inventory's per-user report check does.
	maxProductLen = 64
)

// Limits bounds one Scan. Zero values take the defaults.
type Limits struct {
	// MaxPlugins bounds the plugins reported for the home.
	MaxPlugins int
	// MaxFiles bounds the metadata files and directories read.
	MaxFiles int
	// MaxBytes bounds the metadata bytes read in total.
	MaxBytes int64
	// MaxFileBytes bounds one metadata file.
	MaxFileBytes int64
	// StateDBTimeout bounds one VS Code state database read.
	StateDBTimeout time.Duration
	// FollowSymlinks lets the scan follow links inside the home. A scan
	// running as the home's own account may; a service reading another
	// account's home must not, so a planted link cannot pull another
	// directory into that account's inventory.
	FollowSymlinks bool
	// RoamingAppData and LocalAppData override %APPDATA% and
	// %LOCALAPPDATA% for a Windows home (default: <home>\AppData\Roaming
	// and <home>\AppData\Local). A scan that does not follow links stays in
	// the home and in these folders when folder redirection moved them out
	// of it.
	RoamingAppData string
	LocalAppData   string
	// ProgramFiles lists the Program Files roots ScanMachine reads.
	ProgramFiles []string
}

func (l Limits) normalize() Limits {
	if l.MaxPlugins <= 0 {
		l.MaxPlugins = DefaultMaxPlugins
	}
	if l.MaxFiles <= 0 {
		l.MaxFiles = DefaultMaxFiles
	}
	if l.MaxBytes <= 0 {
		l.MaxBytes = DefaultMaxBytes
	}
	if l.MaxFileBytes <= 0 {
		l.MaxFileBytes = DefaultMaxFileBytes
	}
	if l.StateDBTimeout <= 0 {
		l.StateDBTimeout = DefaultStateDBTimeout
	}
	return l
}

// Install is one IDE installation (or remote server) found in the home.
type Install struct {
	Family     string
	Product    string
	Channel    string
	RemoteKind string
	Version    string
	// Root is the directory the installation was found at (its
	// extensions or plugins directory). It never leaves the process
	// unhashed.
	Root    string
	Plugins []Plugin
	// Partial is set when a limit cut the installation's list short.
	Partial bool
}

// Plugin is one extension or plugin.
type Plugin struct {
	ID            string
	DisplayName   string
	Description   string
	Publisher     string
	Version       string
	Enabled       string
	EnabledSource string
	Scope         string
	InstalledAt   *time.Time
	// Path is the plugin's directory or file.
	Path string
}

// Scan lists the IDE installations in home. goos selects the platform
// layout ("darwin", "linux", "windows"); limits bounds the work.
func Scan(home, goos string, limits Limits) []Install {
	home = filepath.Clean(strings.TrimSpace(home))
	if home == "" || home == "." {
		return nil
	}
	s := newScanner(goos, limits)
	s.layout = newLayout(home, goos, s.limits)
	s.roots = []scanRoot{{path: home}}
	if goos == "windows" {
		for _, dir := range []string{s.layout.appSupport, s.layout.localData} {
			if dir = filepath.Clean(dir); filepath.IsAbs(dir) && s.rootOf(dir) == nil {
				s.roots = append(s.roots, scanRoot{path: dir, exact: true})
			}
		}
	}
	s.scanVSCode()
	s.scanJetBrains()
	s.scanVisualStudio()
	s.scanZed()
	s.scanEclipse()
	s.scanVim()
	return s.result()
}

// ScanMachine lists the machine-wide Visual Studio extensions on Windows
// (Common7\IDE\Extensions under every Visual Studio installation). Other
// platforms have no machine-wide surface and return nil.
func ScanMachine(goos string, limits Limits) []Install {
	if goos != "windows" {
		return nil
	}
	s := newScanner(goos, limits)
	s.scanVisualStudioMachine()
	return s.result()
}

type scanner struct {
	goos   string
	limits Limits
	layout layout
	files  int
	bytes  int64
	full   bool
	out    []Install
	// roots are the folders a scan that does not follow links stays in: the
	// home, then a Windows %APPDATA% or %LOCALAPPDATA% outside it.
	roots []scanRoot
}

// scanRoot is one folder a scan stays in.
type scanRoot struct {
	path string
	// exact marks a redirected AppData folder: it must be reached without a
	// link. Its owner can swap it for a link to another profile's folder
	// between the enumerator's check and the scan, and that profile's files
	// would then be named in place below the link's target.
	exact bool
	// real is the path as the system names an opened handle of it, read
	// once (resolvedRoot).
	real     string
	realRead bool
}

// rootOf returns the root that holds path, the deepest one, or nil.
func (s *scanner) rootOf(path string) *scanRoot {
	var best *scanRoot
	for i := range s.roots {
		root := &s.roots[i]
		inside := path == root.path ||
			strings.HasPrefix(path, strings.TrimSuffix(root.path, string(filepath.Separator))+string(filepath.Separator))
		if inside && (best == nil || len(root.path) > len(best.path)) {
			best = root
		}
	}
	return best
}

func newScanner(goos string, limits Limits) *scanner {
	return &scanner{goos: goos, limits: limits.normalize()}
}

func (s *scanner) result() []Install {
	out := make([]Install, 0, len(s.out))
	for _, inst := range s.out {
		sort.SliceStable(inst.Plugins, func(i, j int) bool {
			a, b := inst.Plugins[i], inst.Plugins[j]
			if a.ID != b.ID {
				return a.ID < b.ID
			}
			return a.Scope < b.Scope
		})
		out = append(out, inst)
	}
	return out
}

// add records an installation, keeping plugins within MaxPlugins.
func (s *scanner) add(inst Install) {
	// Bound each installation independently so an earlier IDE cannot hide a later one.
	room := s.limits.MaxPlugins
	if len(inst.Plugins) > room {
		inst.Plugins = inst.Plugins[:room]
		inst.Partial = true
		s.full = true
	}
	if s.full {
		// A budget ran out while this installation was read.
		inst.Partial = true
	}
	s.out = append(s.out, inst)
	// The next installation starts with its own work budget. In particular,
	// a large VS Code family must not make later JetBrains plugins vanish.
	s.files, s.bytes, s.full = 0, 0, false
}

// charge takes one file (or directory listing) from the budget.
func (s *scanner) charge(bytes int64) bool {
	if s.files >= s.limits.MaxFiles || s.bytes+bytes > s.limits.MaxBytes {
		s.full = true
		return false
	}
	s.files++
	s.bytes += bytes
	return true
}

// isDir reports whether path is a directory, without following a link
// unless the scan may.
func (s *scanner) isDir(path string) bool {
	info, err := s.stat(path)
	return err == nil && info.IsDir()
}

// isFile reports whether path is a regular file, with the same link rule.
func (s *scanner) isFile(path string) bool {
	info, err := s.stat(path)
	return err == nil && info.Mode().IsRegular()
}

var errLinkAbove = errors.New("a link or junction above the path")

// stat follows links only when the scan may. Lstat and O_NOFOLLOW see only
// the last element, so a scan that must not follow links first checks
// every directory between the home and path: a link or junction there
// (%USERPROFILE%\.vscode pointing at another profile's) would put another
// account's plugins in this one's inventory.
func (s *scanner) stat(path string) (os.FileInfo, error) {
	if s.limits.FollowSymlinks {
		return os.Stat(path)
	}
	if !s.plainDirsAbove(path) {
		return nil, errLinkAbove
	}
	return os.Lstat(path)
}

// plainDirsAbove reports whether every directory between the root that
// holds path (the home, or a redirected AppData folder) and path is a plain
// directory; Lstat reports a link, and a Windows junction, as no directory.
// A path in no root is not plain. The machine-wide scan has no home:
// Program Files is the administrator's.
func (s *scanner) plainDirsAbove(path string) bool {
	if s.layout.home == "" {
		return true
	}
	root := s.rootOf(path)
	if root == nil {
		return false
	}
	var dirs []string
	for dir := filepath.Dir(path); path != root.path && dir != root.path; dir = filepath.Dir(dir) {
		if filepath.Dir(dir) == dir {
			return false
		}
		dirs = append(dirs, dir)
	}
	for i := len(dirs) - 1; i >= 0; i-- {
		info, err := os.Lstat(dirs[i])
		if err == nil && info.IsDir() {
			continue
		}
		// A managed gateway may read a folder without the right to read
		// the attributes of a folder above it: the guardian keeps the .kiro
		// folder of a user enrolled for Kiro at its exact DACL (GAP-0897).
		// The path is then plain when it resolves to itself, because a link
		// or junction above it would resolve elsewhere.
		return errors.Is(err, os.ErrPermission) && resolvesToItself(path)
	}
	return true
}

// listDir returns up to limit entries of dir, sorted by name. Entries
// that are links are dropped unless the scan follows links.
func (s *scanner) listDir(dir string, limit int) []os.DirEntry {
	if !s.isDir(dir) || !s.charge(0) {
		return nil
	}
	if beforeOpen != nil {
		beforeOpen(dir)
	}
	f, err := os.Open(dir)
	if err != nil {
		s.full = true
		return nil
	}
	defer f.Close()
	if !s.openedInPlace(f, dir) {
		return nil
	}
	// Read one extra entry so hitting the cap cannot look like a full listing.
	entries, err := f.ReadDir(limit + 1)
	if err != nil && !errors.Is(err, io.EOF) {
		s.full = true
		return nil
	}
	if len(entries) > limit {
		s.full = true
		entries = entries[:limit]
	}
	out := entries[:0]
	for _, e := range entries {
		if e.Type()&os.ModeSymlink != 0 && !s.limits.FollowSymlinks {
			continue
		}
		out = append(out, e)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name() < out[j].Name() })
	return out
}

// subdirs returns the names of the directories in dir.
func (s *scanner) subdirs(dir string, limit int) []string {
	var out []string
	for _, e := range s.listDir(dir, limit) {
		if e.IsDir() || (e.Type()&os.ModeSymlink != 0 && s.isDir(filepath.Join(dir, e.Name()))) {
			out = append(out, e.Name())
		}
	}
	return out
}

// readFile reads a small regular file within the per-file and total
// budgets. A link is refused unless the scan follows links; a FIFO never
// blocks the read.
func (s *scanner) readFile(path string) ([]byte, bool) {
	return s.readFileLimit(path, s.limits.MaxFileBytes)
}

func (s *scanner) readFileLimit(path string, limit int64) ([]byte, bool) {
	f, ok := s.openFile(path)
	if !ok {
		return nil, false
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Size() > limit || !s.openedInPlace(f, path) {
		return nil, false
	}
	if !s.charge(info.Size()) {
		return nil, false
	}
	data, err := io.ReadAll(io.LimitReader(f, limit+1))
	if err != nil || int64(len(data)) > limit {
		return nil, false
	}
	return data, true
}

// beforeOpen, when set, runs between the checks on a path and its open;
// tests use it to change a folder above the path in that window.
var beforeOpen func(path string)

// openFile opens a regular file the link rule admits (isFile).
func (s *scanner) openFile(path string) (*os.File, bool) {
	if !s.isFile(path) {
		return nil, false
	}
	if beforeOpen != nil {
		beforeOpen(path)
	}
	f, err := openNonblocking(path, s.limits.FollowSymlinks)
	if err != nil {
		return nil, false
	}
	return f, true
}

// openedInPlace reports whether f, opened for path, is the object path
// names below its root (the home, or a redirected AppData folder): the
// checks of the folders above path ran before the open, so a folder swapped
// for a link to another profile in between would otherwise put that
// profile's plugins in this home's inventory (GAP-1138). It compares the
// path the system gives the opened handle with the root's. Where the system
// cannot name an opened file (macOS), the folders above path are checked
// again after the open and the opened object must be the one path names
// now. A Windows file with more than one name is refused: through a hard
// link another profile's file would be read as this one's. A scan that
// follows links and the machine-wide scan keep the checks made before the
// open.
func (s *scanner) openedInPlace(f *os.File, path string) bool {
	if s.limits.FollowSymlinks || s.layout.home == "" {
		return true
	}
	root := s.rootOf(path)
	if root == nil || !openedOneName(f) {
		return false
	}
	got, ok := openedPath(f)
	real := s.resolvedRoot(root)
	if root.exact && (!ok || real == "") {
		return false
	}
	if !ok || real == "" {
		return s.openedObjectIsPath(f, path)
	}
	rel, err := filepath.Rel(root.path, path)
	if err != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
		return false
	}
	want := filepath.Join(real, rel)
	if s.goos == "linux" {
		return filepath.Clean(got) == want
	}
	return strings.EqualFold(filepath.Clean(got), want)
}

// openedObjectIsPath reports whether f is the object path names now, through
// plain folders only.
func (s *scanner) openedObjectIsPath(f *os.File, path string) bool {
	opened, err := f.Stat()
	if err != nil || !s.plainDirsAbove(path) {
		return false
	}
	current, err := os.Lstat(path)
	return err == nil && os.SameFile(opened, current)
}

// resolvedRoot is root's opened path, or "" when it cannot be named.
func (s *scanner) resolvedRoot(root *scanRoot) string {
	if root.realRead {
		return root.real
	}
	root.realRead = true
	if root.exact {
		if info, err := os.Lstat(root.path); err != nil || !info.IsDir() {
			return ""
		}
	}
	f, err := os.Open(root.path)
	if err != nil {
		return ""
	}
	defer f.Close()
	if real, ok := openedPath(f); ok {
		real = filepath.Clean(real)
		if root.exact && !samePath(real, root.path) {
			return ""
		}
		root.real = real
	}
	return root.real
}

// samePath compares two cleaned paths as this system names files.
func samePath(a, b string) bool {
	if runtime.GOOS == "windows" {
		return strings.EqualFold(a, b)
	}
	return a == b
}

// clean bounds a metadata value: printable, single line, at most
// maxFieldLen bytes. Format characters (Unicode Cf: the bidi overrides and
// isolates, zero-width characters) are dropped, so a display name such as
// "safe <U+202E>gnp.exe" cannot render reversed in a table or a board, and
// every other control character (a newline, a tab, ESC) becomes one space
// (GAP-0670).
func clean(value string) string {
	var b strings.Builder
	space := false
	for _, r := range value {
		if r == utf8.RuneError || unicode.Is(unicode.Cf, r) {
			continue
		}
		if unicode.IsControl(r) || unicode.IsSpace(r) {
			space = b.Len() > 0
			continue
		}
		width := utf8.RuneLen(r)
		if space {
			width++
		}
		if b.Len()+width > maxFieldLen {
			break
		}
		if space {
			b.WriteByte(' ')
			space = false
		}
		b.WriteRune(r)
	}
	return b.String()
}

// safeName reports whether name is a single path element.
func safeName(name string) bool {
	return name != "" && name != "." && name != ".." && !strings.ContainsAny(name, `/\`) && !strings.ContainsRune(name, 0)
}

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
	// and <home>\AppData\Local).
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

// plainDirsAbove reports whether every directory between the home and path
// is a plain directory; Lstat reports a link, and a Windows junction, as
// no directory. The machine-wide scan has no home: Program Files is the
// administrator's.
func (s *scanner) plainDirsAbove(path string) bool {
	home := s.layout.home
	if home == "" || path == home {
		return true
	}
	var dirs []string
	for dir := filepath.Dir(path); dir != home; dir = filepath.Dir(dir) {
		if filepath.Dir(dir) == dir {
			return false // not inside the home
		}
		dirs = append(dirs, dir)
	}
	for i := len(dirs) - 1; i >= 0; i-- {
		if info, err := os.Lstat(dirs[i]); err != nil || !info.IsDir() {
			return false
		}
	}
	return true
}

// listDir returns up to limit entries of dir, sorted by name. Entries
// that are links are dropped unless the scan follows links.
func (s *scanner) listDir(dir string, limit int) []os.DirEntry {
	if !s.isDir(dir) || !s.charge(0) {
		return nil
	}
	f, err := os.Open(dir)
	if err != nil {
		s.full = true
		return nil
	}
	defer f.Close()
	entries, err := f.ReadDir(limit)
	if err != nil && !errors.Is(err, io.EOF) {
		s.full = true
		return nil
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
	if !s.isFile(path) {
		return nil, false
	}
	f, err := openNonblocking(path, s.limits.FollowSymlinks)
	if err != nil {
		return nil, false
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Size() > limit {
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

// clean bounds a metadata value: printable, single line, at most
// maxFieldLen bytes.
func clean(value string) string {
	value = strings.TrimSpace(value)
	if value == "" {
		return ""
	}
	var b strings.Builder
	for _, r := range value {
		if r == utf8.RuneError || unicode.IsControl(r) {
			continue
		}
		if b.Len()+utf8.RuneLen(r) > maxFieldLen {
			break
		}
		b.WriteRune(r)
	}
	return strings.TrimSpace(b.String())
}

// safeName reports whether name is a single path element.
func safeName(name string) bool {
	return name != "" && name != "." && name != ".." && !strings.ContainsAny(name, `/\`) && !strings.ContainsRune(name, 0)
}

// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package enterprisehooks

import (
	"context"
	"encoding/json"
	"io"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"sort"
	"strings"
)

// PrivateAgentInstall is static evidence of one agent copy an enrolled
// account can run: in its home, in a version manager, in a machine npm
// prefix or a native installer's version directory. It is deliberately
// separate from the selected version in a manifest row: a supported copy
// must never hide an older copy the user can launch.
//
// Each copy is identified by the real path its package or executable
// resolves to, so one copy reached through a link, an equivalent spelling
// or two prefixes that share a directory is reported once.
type PrivateAgentInstall struct {
	Connector  string `json:"connector"`
	Version    string `json:"version,omitempty"`
	Path       string `json:"path,omitempty"`
	Incomplete bool   `json:"incomplete,omitempty"`
	// Skipped names, for an incomplete entry, the part of the scan that
	// could not be finished (a PrivateInstallSkipped* code), so status
	// says what was not inspected and why instead of truncating silently.
	Skipped string `json:"skipped,omitempty"`
	// Untrusted marks a copy in a location another account can change: its
	// package metadata cannot prove the version, so the copy is reported
	// as unverified whatever it claims.
	Untrusted bool `json:"untrusted,omitempty"`
}

const privateAgentInstallMaxFindings = 64
const PrivateAgentInstallMaxFindings = privateAgentInstallMaxFindings

// privateAgentInstallMaxVersionDirs bounds the installed Node versions (or
// native release directories) the separate-copy scan inspects per version
// manager or installer. Selecting the hook contract's version reads only
// the newest few; the scan reads every one up to this bound and reports
// the scan incomplete when a manager holds more.
const privateAgentInstallMaxVersionDirs = 64

// privateInstallWalkMaxEntries bounds the directory entries the scan lists
// below one home while it looks for npm prefixes at any depth (GAP-0988).
// Inside a node_modules tree it lists package names only, never package
// contents. Tests lower it.
var privateInstallWalkMaxEntries = 1 << 19

// privateInstallWalk is one bounded walk of a home (walkPrivateNPMPrefixes).
// open opens a directory to list; unreachable reports a listing error that
// hides nothing the account can run below dir.
type privateInstallWalk struct {
	open        func(dir string) (*os.File, error)
	openChild   func(parent *os.File, name string) (*os.File, error)
	unreachable func(dir string, err error) bool
	// homeLinks returns a link directly below the home that names a
	// directory as a prefix, without descending into it (Unix only: the
	// Windows scan never follows a reparse point as LocalSystem).
	homeLinks bool
	budget    int
	complete  bool
	ctx       context.Context
}

const privateInstallWalkMaxDepth = 64

// walkPrivateNPMPrefixes returns every npm prefix below home, at any depth:
// each directory that holds a node_modules directory (npm install --prefix
// anywhere, a project's own dependencies) and, inside node_modules, each
// package or pnpm store entry with a node_modules of its own. It never
// descends through a link or other reparse point, so a link cannot loop
// it or lead it outside the home. complete is false when the walk ran out
// of its bound or a directory could not be listed: the scan then says so
// instead of reporting the account clean.
func walkPrivateNPMPrefixes(ctx context.Context, home string, w privateInstallWalk) (prefixes []string, complete bool) {
	w.budget, w.complete, w.ctx = privateInstallWalkMaxEntries, true, ctx
	if w.ctx == nil {
		w.ctx = context.Background()
	}
	var visit func(dir string, parent *os.File, name string, modules bool, depth int, held *os.File)
	var probe func(pkg string, parent *os.File, name string, depth int)
	open := func(dir string, parent *os.File, name string) (*os.File, error) {
		if parent != nil && w.openChild != nil {
			return w.openChild(parent, name)
		}
		return w.open(dir)
	}
	probe = func(pkg string, parent *os.File, name string, depth int) {
		moduleDir := filepath.Join(pkg, "node_modules")
		if depth+2 > privateInstallWalkMaxDepth {
			w.complete = false
			return
		}
		if w.openChild == nil {
			if info, err := os.Lstat(moduleDir); err != nil || info.Mode().Type() != fs.ModeDir {
				return
			}
			prefixes = append(prefixes, pkg)
			visit(moduleDir, nil, "", true, depth+2, nil)
			return
		}
		packageHandle, err := open(pkg, parent, name)
		if err != nil {
			if !w.unreachable(pkg, err) {
				w.complete = false
			}
			return
		}
		defer packageHandle.Close()
		// A pathname Lstat of pkg/node_modules would traverse a raced
		// junction in pkg as LocalSystem. Check both components through
		// held handles instead, and list the same modules handle.
		modulesHandle, err := open(moduleDir, packageHandle, "node_modules")
		if err != nil {
			if !w.unreachable(moduleDir, err) {
				w.complete = false
			}
			return
		}
		prefixes = append(prefixes, pkg)
		visit(moduleDir, nil, "", true, depth+2, modulesHandle)
	}
	visit = func(dir string, parent *os.File, name string, modules bool, depth int, held *os.File) {
		if w.ctx.Err() != nil || w.budget < 0 || depth > privateInstallWalkMaxDepth {
			w.complete = false
			if held != nil {
				_ = held.Close()
			}
			return
		}
		f := held
		if f == nil {
			var err error
			f, err = open(dir, parent, name)
			if err != nil {
				if !w.unreachable(dir, err) {
					w.complete = false
				}
				return
			}
		}
		defer f.Close()
		for _, entry := range w.list(f, dir) {
			if w.ctx.Err() != nil || w.budget < 0 {
				w.complete = false
				return
			}
			name, child := entry.Name(), filepath.Join(dir, entry.Name())
			if entry.Type() != fs.ModeDir {
				if w.homeLinks && dir == home && entry.Type()&fs.ModeSymlink != 0 {
					if info, err := os.Stat(child); err == nil && info.IsDir() {
						prefixes = append(prefixes, child)
					}
				}
				continue
			}
			switch {
			case !modules && name == "node_modules":
				prefixes = append(prefixes, dir)
				visit(child, f, name, true, depth+1, nil)
			case !modules:
				visit(child, f, name, false, depth+1, nil)
			case strings.HasPrefix(name, "@") || name == ".pnpm":
				if depth+1 > privateInstallWalkMaxDepth {
					w.complete = false
					continue
				}
				scope, err := open(child, f, name)
				if err != nil {
					if !w.unreachable(child, err) {
						w.complete = false
					}
					continue
				}
				for _, inner := range w.list(scope, child) {
					if inner.Type() == fs.ModeDir && w.ctx.Err() == nil {
						probe(filepath.Join(child, inner.Name()), scope, inner.Name(), depth+1)
					}
				}
				_ = scope.Close()
			default:
				probe(child, f, name, depth)
			}
		}
	}
	visit(home, nil, "", false, 0, nil)
	return prefixes, w.complete && w.budget >= 0 && w.ctx.Err() == nil
}

// list reads dir's entries in batches, charging each to the walk's bound.
func (w *privateInstallWalk) list(f *os.File, dir string) []fs.DirEntry {
	if w.budget < 0 || w.ctx.Err() != nil {
		w.complete = false
		return nil
	}
	var out []fs.DirEntry
	for {
		if w.ctx.Err() != nil {
			w.complete = false
			return out
		}
		batch, err := f.ReadDir(256)
		if w.budget -= len(batch); w.budget < 0 {
			return nil
		}
		out = append(out, batch...)
		if err != nil {
			if err != io.EOF && !w.unreachable(dir, err) {
				w.complete = false
			}
			return out
		}
	}
}

// The parts of the separate-copy scan that can be left unfinished.
const (
	PrivateInstallSkippedHome            = "home_unreadable"
	PrivateInstallSkippedVersionManagers = "version_manager_limit"
	PrivateInstallSkippedNativeVersions  = "native_versions_limit"
	PrivateInstallSkippedFindings        = "finding_limit"
	PrivateInstallSkippedLocation        = "location_unreadable"
	PrivateInstallSkippedOutsideRoots    = "path_outside_scan_roots"
	PrivateInstallSkippedUnresolved      = "account_not_inspected"
	PrivateInstallSkippedExtensions      = "extensions_folder_limit"
)

var privateInstallSkippedText = map[string]string{
	PrivateInstallSkippedHome:            "the account's home could not be fully listed within the scan bounds",
	PrivateInstallSkippedVersionManagers: "a Node version manager holds more installed versions than the scan inspects",
	PrivateInstallSkippedNativeVersions:  "a native installer or Homebrew cask holds more releases than the scan inspects",
	PrivateInstallSkippedFindings:        "the account has more unsupported agent copies than the record holds",
	PrivateInstallSkippedLocation:        "an install location could not be read safely",
	PrivateInstallSkippedOutsideRoots:    "discovery named a copy outside the locations DefenseClaw scans",
	PrivateInstallSkippedUnresolved:      "the enrolled account could not be inspected this cycle",
	PrivateInstallSkippedExtensions:      "an editor's extensions folder holds more entries than the scan reads, or could not be read",
}

// KnownPrivateInstallSkipped returns code when it is a PrivateInstallSkipped*
// code, else "". The root parent keeps only known codes from the per-user
// worker's user-influenced answer.
func KnownPrivateInstallSkipped(code string) string {
	if _, ok := privateInstallSkippedText[code]; ok {
		return code
	}
	return ""
}

func privateInstallIncompleteReason(skipped string) string {
	why := ""
	if text := privateInstallSkippedText[skipped]; text != "" {
		why = " (" + text + ")"
	}
	return "the bounded scan of this account's private agent installs was incomplete" + why +
		"; use application control to exclude unapproved agent binaries"
}

const privateInstallUntrustedReason = "another account can change this copy, so its version cannot be verified; " +
	"this copy may ignore managed hooks or the documented version floor, so its tool calls are not protected"

func privateInstallReason(connector, version string) string {
	if version == "" {
		return "the installed agent's version could not be read, so its managed hook contract cannot be verified"
	}
	if refused := privateInstallContractReason(connector, version); refused != "" {
		return refused + "; this copy may ignore managed hooks or the documented version floor, so its tool calls are not protected"
	}
	return ""
}

// privateInstallUnprotected is the unprotected-agents entry for one scan
// finding, without its account; ok is false for a supported copy.
func privateInstallUnprotected(install PrivateAgentInstall) (agent UnprotectedAgent, ok bool) {
	if install.Incomplete {
		return UnprotectedAgent{Connector: install.Connector, Code: UnprotectedCodeInstallScanIncomplete,
			Reason: privateInstallIncompleteReason(install.Skipped)}, true
	}
	reason := privateInstallReason(install.Connector, install.Version)
	if install.Untrusted {
		reason = privateInstallUntrustedReason
		install.Version = ""
	}
	if reason == "" {
		return UnprotectedAgent{}, false
	}
	return UnprotectedAgent{Connector: install.Connector, Version: install.Version, InstallPath: install.Path,
		Code: UnprotectedCodeHookContractUnverified, Reason: reason}, true
}

// privateInstallScan collects one account's findings. seen holds the
// identity of every copy already judged; incomplete the connectors whose
// scan was left unfinished, with the first reason.
type privateInstallScan struct {
	seen       map[string]bool
	found      []PrivateAgentInstall
	incomplete map[string]string
	order      []string
	full       bool
}

func newPrivateInstallScan() *privateInstallScan {
	return &privateInstallScan{seen: map[string]bool{}, incomplete: map[string]string{}}
}

// judge reports whether the copy with identity is new, recording it.
func (s *privateInstallScan) judge(identity string) bool {
	if s.seen[identity] {
		return false
	}
	s.seen[identity] = true
	return true
}

func (s *privateInstallScan) add(install PrivateAgentInstall) {
	if s.full {
		return
	}
	if len(s.found) >= privateAgentInstallMaxFindings {
		s.full = true
		s.skip(install.Connector, PrivateInstallSkippedFindings)
		return
	}
	s.found = append(s.found, install)
}

func (s *privateInstallScan) skip(connector, code string) {
	if _, known := s.incomplete[connector]; known {
		return
	}
	s.incomplete[connector] = code
	s.order = append(s.order, connector)
}

func (s *privateInstallScan) skipAll(connectors []string, code string) {
	for _, connector := range connectors {
		s.skip(connector, code)
	}
}

// result lists the copies found, then one incomplete entry per connector
// whose scan was left unfinished.
func (s *privateInstallScan) result() []PrivateAgentInstall {
	out := append([]PrivateAgentInstall(nil), s.found...)
	for _, connector := range s.order {
		out = append(out, PrivateAgentInstall{Connector: connector, Incomplete: true, Skipped: s.incomplete[connector]})
	}
	return out
}

func privateInstallConnectors(names []string, known func(string) bool) []string {
	var out []string
	seen := map[string]bool{}
	for _, name := range names {
		name = strings.ToLower(strings.TrimSpace(name))
		if known(name) && !seen[name] {
			seen[name] = true
			out = append(out, name)
		}
	}
	return out
}

// privateNPMEntryPoints are the files each agent's npm package starts from,
// relative to the package: Claude Code's cli.js (to 2.1.112) or native
// bin/claude.exe (from 2.1.113), Codex's bin/codex.js, and Copilot's
// npm-loader.js (index.js in early releases). The targets of the package's
// own "bin" field count too: npm links those. A package folder with none of
// them is leftover metadata, not a copy the account can run.
var privateNPMEntryPoints = map[string][]string{
	"claudecode": {"cli.js", "bin/claude.exe"},
	"codex":      {"bin/codex.js"},
	"copilot":    {"npm-loader.js", "index.js"},
}

// privateNPMMaxBinTargets bounds the "bin" targets read from one package.
const privateNPMMaxBinTargets = 16

// privateNPMEntries lists the entry points to look for in a connector's
// package whose package.json holds manifest (nil when it has none): the
// known ones, then each "bin" target (a string, or a map of command names
// to files) that stays inside the package, slash-separated.
func privateNPMEntries(connector string, manifest []byte) []string {
	entries := append([]string(nil), privateNPMEntryPoints[connector]...)
	var parsed struct {
		Bin json.RawMessage `json:"bin"`
	}
	if len(manifest) == 0 || json.Unmarshal(manifest, &parsed) != nil || len(parsed.Bin) == 0 {
		return entries
	}
	var targets []string
	var one string
	var named map[string]string
	switch {
	case json.Unmarshal(parsed.Bin, &one) == nil:
		targets = []string{one}
	case json.Unmarshal(parsed.Bin, &named) == nil:
		for _, target := range named {
			targets = append(targets, target)
		}
		sort.Strings(targets)
	}
	seen := map[string]bool{}
	for _, entry := range entries {
		seen[entry] = true
	}
	added := 0
	for _, target := range targets {
		clean := path.Clean(strings.ReplaceAll(strings.TrimSpace(target), `\`, "/"))
		if clean == "." || clean == ".." || strings.HasPrefix(clean, "../") || path.IsAbs(clean) ||
			strings.ContainsAny(clean, ":\x00") || seen[clean] {
			continue
		}
		if added == privateNPMMaxBinTargets {
			break
		}
		seen[clean] = true
		entries = append(entries, clean)
		added++
	}
	return entries
}

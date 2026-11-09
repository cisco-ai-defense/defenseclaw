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

package gateway

import (
	"errors"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"runtime"
	"slices"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/hookpaths"

	"github.com/defenseclaw/defenseclaw/internal/actionfacts"
)

// activeStateNameIndexLimit bounds one walk of the protected trees. A
// larger state counts as holding every name (fail closed). An upgraded
// account's previous/ holds a whole Python venv (about 25000 entries), so
// the limit is far above it.
const activeStateNameIndexLimit = 400000

// activeStateNameIndexTTL is how long one walk of a state root is reused.
// The index is also rebuilt when the root or a protected tree directory
// changes (its modification time), which an upgrade, a rollback or a new
// hook does.
const activeStateNameIndexTTL = 10 * time.Minute

// activeStateProtectedTrees are the directories of the state root whose
// files are protected state (not logs/, backups/ or the uv cache).
var activeStateProtectedTrees = hookpaths.ActiveStateProtectedTrees

type activeStateNameIndex struct {
	built time.Time
	stamp string
	names map[string]struct{}
	// whole is set when a tree could not be read or the walk passed the
	// limit: every pattern then counts as a match.
	whole bool
}

var activeStateNameIndexes = struct {
	sync.Mutex
	byRoot map[string]*activeStateNameIndex
}{byRoot: map[string]*activeStateNameIndex{}}

// activeStateNamesOf returns the distinct file and directory names of the
// protected state under root (the root's own files and every protected
// tree, at any depth), walked once and reused (GAP-2267 pod check9: a
// size-capped walk per call counted every upgraded account's previous/ as
// a match and ran in the hook hot path).
func activeStateNamesOf(root string) *activeStateNameIndex {
	if runtime.GOOS == "windows" && strings.HasPrefix(root, "/") && actionfacts.DriveSlashPath(root[1:]) {
		// A Git Bash drive view root (/C:/Users/x/.defenseclaw, GAP-2577).
		root = root[1:]
	}
	stamp := activeStateNameIndexStamp(root)
	activeStateNameIndexes.Lock()
	defer activeStateNameIndexes.Unlock()
	if index, ok := activeStateNameIndexes.byRoot[root]; ok && index.stamp == stamp &&
		time.Since(index.built) < activeStateNameIndexTTL {
		return index
	}
	index := buildActiveStateNameIndex(root)
	index.stamp = stamp
	activeStateNameIndexes.byRoot[root] = index
	return index
}

// activeStateNameIndexStamp is the modification time of the root and of
// each protected tree directory.
func activeStateNameIndexStamp(root string) string {
	var stamp strings.Builder
	for _, name := range append([]string{""}, activeStateProtectedTrees...) {
		info, err := os.Stat(filepath.Join(root, name))
		if err != nil {
			stamp.WriteString("-;")
			continue
		}
		stamp.WriteString(info.ModTime().UTC().Format(time.RFC3339Nano))
		stamp.WriteByte(';')
	}
	return stamp.String()
}

func buildActiveStateNameIndex(root string) *activeStateNameIndex {
	index := &activeStateNameIndex{built: time.Now(), names: map[string]struct{}{}}
	entries, err := os.ReadDir(root)
	if errors.Is(err, fs.ErrNotExist) {
		return index
	}
	if err != nil {
		index.whole = true
		return index
	}
	seen := 0
	for _, entry := range entries {
		name := entry.Name()
		if !entry.IsDir() {
			index.names[name] = struct{}{}
			continue
		}
		protected := false
		for _, tree := range activeStateProtectedTrees {
			protected = protected || name == tree
		}
		if !protected {
			continue
		}
		walkErr := filepath.WalkDir(filepath.Join(root, name), func(_ string, item fs.DirEntry, err error) error {
			seen++
			if err != nil || seen > activeStateNameIndexLimit {
				index.whole = true
				return fs.SkipAll
			}
			index.names[item.Name()] = struct{}{}
			return nil
		})
		if walkErr != nil {
			index.whole = true
		}
		if index.whole {
			return index
		}
	}
	return index
}

// activeStateTreeHasName reports a file or directory of the protected
// state (the root's own files and its protected trees; not logs/ or the
// uv cache) whose name the find pattern matches. A tree that cannot be
// read counts as a match.
func activeStateTreeHasName(root, pattern string, fold bool) bool {
	index := activeStateNamesOf(root)
	if index.whole {
		return true
	}
	if fold {
		pattern = strings.ToLower(pattern)
	}
	for name := range index.names {
		if fold {
			name = strings.ToLower(name)
		}
		if matched, err := path.Match(pattern, name); err != nil || matched {
			return true
		}
	}
	return false
}

// clientStateTreeNames keeps the hook client's state-tree name answers
// (hookpaths.StateTreeNameKey) of a resolved target map, so every check of
// the action's facts, the semantic owners included, reads them
// (actionfacts.Input.ActiveStateTreeNames, GAP-2404 pod check21).
func clientStateTreeNames(targets map[string]string) map[string]string {
	var names map[string]string
	for key, value := range targets {
		if !strings.HasPrefix(key, hookpaths.StateTreeNamePrefix) {
			continue
		}
		if names == nil {
			names = map[string]string{}
		}
		names[key] = value
	}
	return names
}

// clientResolvedPathTargets keeps the plain path answers (absolute spelling ->
// absolute physical path) of a resolved target map, not its metadata keys, for
// the checks of the action facts that judge a write through a link
// (actionfacts.Input.ClientResolvedTargets).
func clientResolvedPathTargets(targets map[string]string) map[string]string {
	var paths map[string]string
	for spelling, physical := range targets {
		if !strings.HasPrefix(spelling, "/") || !strings.HasPrefix(physical, "/") {
			continue
		}
		if paths == nil {
			paths = map[string]string{}
		}
		paths[spelling] = physical
	}
	// A link into a directory the user cannot open has no physical answer;
	// the client lists the file its link text leads to instead
	// (hookpaths.LinkTextFactPrefix), which is judged by its name.
	for key, text := range targets {
		spelling, ok := strings.CutPrefix(key, hookpaths.LinkTextFactPrefix)
		if !ok || !strings.HasPrefix(spelling, "/") || !strings.HasPrefix(text, "/") {
			continue
		}
		if _, answered := paths[spelling]; !answered {
			if paths == nil {
				paths = map[string]string{}
			}
			paths[spelling] = text
		}
	}
	return paths
}

// clientWorkingDirectories keeps the directory spellings the hook client keyed
// its path answers in (hookpaths.DirectoryFactPrefix, the physical directory
// as value) that name the directory the gateway judges in, cwd. The gateway
// resolves a project reached through a link, the client keys a relative
// operand by the name it was given, so the lookup asks both
// (actionfacts.Input.ClientWorkingDirectories). With no absolute cwd the
// gateway has nothing to compare and keeps every directory the client names.
func clientWorkingDirectories(targets map[string]string, cwd string) []string {
	var dirs []string
	cwd = filepath.Clean(cwd)
	for key, physical := range targets {
		logical, ok := strings.CutPrefix(key, hookpaths.DirectoryFactPrefix)
		if !ok || !filepath.IsAbs(logical) || !filepath.IsAbs(physical) {
			continue
		}
		if filepath.IsAbs(cwd) && filepath.Clean(logical) != cwd && filepath.Clean(physical) != cwd {
			continue
		}
		dirs = append(dirs, filepath.Clean(logical))
	}
	// The directory the hook client ran the call in is the one it keyed a
	// relative operand by, whether or not it listed it as a directory fact.
	if client := targets[hookpaths.CWDKey]; !filepath.IsAbs(cwd) && filepath.IsAbs(client) &&
		!slices.Contains(dirs, filepath.Clean(client)) {
		dirs = append(dirs, filepath.Clean(client))
	}
	sort.Strings(dirs)
	return dirs
}

// activeStateTreeHasNameFor is activeStateTreeHasName with the hook
// client's answer (hookpaths.StateTreeHasName, read as the user) used
// first: a managed gateway cannot read the home, so its own index counts
// every pattern as a match (GAP-2404 pod check20).
func activeStateTreeHasNameFor(targets map[string]string, root, pattern string, fold bool) bool {
	if value, present := targets[hookpaths.StateTreeNameKey(root, pattern, fold)]; present {
		return value != "0"
	}
	return activeStateTreeHasName(root, pattern, fold)
}

// findPatternIsRegenerableBytecode reports a -name/-iname pattern that
// matches only Python bytecode (`*.pyc`, `*.pyo`, `*.py[co]`,
// `__pycache__`). Python writes it again on the next import, so a find
// from above the state root that removes it (`find ~ -name '*.pyc'
// -delete`, `find ~ -name __pycache__ -exec rm -rf {} +`) is ordinary
// cleanup, even though the saved venv under previous/ holds bytecode
// (GAP-2267 pod check9).
func findPatternIsRegenerableBytecode(pattern string, fold bool) bool {
	if fold {
		pattern = strings.ToLower(pattern)
	}
	switch pattern {
	case "*.pyc", "*.pyo", "*.py[co]", "*.py[oc]", "__pycache__":
		return true
	}
	return false
}

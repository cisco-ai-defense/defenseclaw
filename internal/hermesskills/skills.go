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

// Package hermesskills identifies the mixed-provenance Hermes skill tree.
package hermesskills

import (
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"

	"github.com/defenseclaw/defenseclaw/internal/hermespath"
	"github.com/defenseclaw/defenseclaw/internal/pathidentity"
	"github.com/defenseclaw/defenseclaw/internal/safefile"
	"github.com/defenseclaw/defenseclaw/internal/skillrootsafe"
)

const (
	DefaultDirectoryLimit = 32768
	// FullScanDirectoryLimit is used after a bounded walk reaches its directory,
	// entry, or depth budget. It keeps the same provenance checks while allowing
	// the off-reader worker to finish the tree.
	FullScanDirectoryLimit = int(^uint(0)>>1) / 8
	DefaultDepthLimit      = 128
	markerMaxBytes         = 64 * 1024
	maxSkillFileBytes      = 64 * 1024 * 1024
	maxSkillTreeBytes      = 256 * 1024 * 1024
)

var ErrDirectoryLimit = errors.New("Hermes skill discovery directory limit exceeded")

// Seams for tests of a service account's denied profile folders.
var (
	evalSymlinks           = filepath.EvalSymlinks
	readRegularFileBounded = safefile.ReadRegularFileBounded
)

// Entry is one actual SKILL.md directory, not a Hermes category container.
type Entry struct {
	Name    string
	Path    string
	Bundled bool
}

// Root returns the resolved default-profile Hermes skills directory.
func Root() string {
	home := strings.TrimSpace(hermespath.HomeDir())
	if home == "" {
		return ""
	}
	return filepath.Join(home, "skills")
}

// IsRoot reports whether path is the exact resolved Hermes skills root.
func IsRoot(path string) bool {
	root := Root()
	return root != "" && samePath(path, root)
}

// ProfileRootTails are where a Hermes skills root sits in a user profile:
// %LOCALAPPDATA%\hermes\skills on Windows, ~/.hermes/skills elsewhere (the
// catalog's two Hermes skill paths).
var ProfileRootTails = []string{
	filepath.Join("AppData", "Local", "hermes", "skills"),
	filepath.Join(".hermes", "skills"),
}

// IsProfileRoot reports whether path is a Hermes skills root by its place in
// a user profile (it ends in one of ProfileRootTails). A service-context
// watcher or scan (the managed Windows gateway) sees every user's root,
// while IsRoot resolves only this process's own Hermes home; list such a
// root with DiscoverProfileRoot.
func IsProfileRoot(path string) bool {
	clean := filepath.Clean(path)
	for _, tail := range ProfileRootTails {
		if len(clean) <= len(tail) {
			continue
		}
		head, end := clean[:len(clean)-len(tail)], clean[len(clean)-len(tail):]
		if !strings.HasSuffix(head, string(filepath.Separator)) {
			continue
		}
		if end == tail || (runtime.GOOS == "windows" && strings.EqualFold(end, tail)) {
			return true
		}
	}
	return false
}

// Discover recursively returns actual Hermes skills and their provenance.
// Copies are bundled only when their complete tree matches a pinned vendor
// digest; every other copy remains scanable.
func Discover(root string, directoryLimit int) ([]Entry, error) {
	if !IsRoot(root) {
		return nil, fmt.Errorf("not the resolved Hermes skills root: %s", root)
	}
	if !canonicalPath(root) {
		return nil, fmt.Errorf("Hermes skills root is linked or unavailable: %s", root)
	}
	return discover(root, root, directoryLimit)
}

// DiscoverProfileRoot is Discover for the Hermes skills root of a profile
// the caller resolved itself: a service-context scan (managed Windows)
// reads every user's profile, while IsRoot resolves only this process's
// own Hermes home. Provenance uses the same pinned vendor digests.
func DiscoverProfileRoot(root string, directoryLimit int) ([]Entry, error) {
	if filepath.Base(filepath.Clean(root)) != "skills" {
		return nil, fmt.Errorf("not a Hermes skills root: %s", root)
	}
	if !profileRootUnlinked(root) {
		return nil, fmt.Errorf("Hermes skills root is linked or unavailable: %s", root)
	}
	return discover(root, root, directoryLimit)
}

// DiscoverUnder lists only the subtree named by a watcher directory event.
// The vendor digest is checked for each skill in the selected subtree. This
// keeps a move into an existing category from walking every installed skill.
func DiscoverUnder(root, subtree string, directoryLimit int) ([]Entry, error) {
	if !IsRoot(root) && !IsProfileRoot(root) {
		return nil, fmt.Errorf("not a Hermes skills root: %s", root)
	}
	if !profileRootUnlinked(root) || !pathAtOrBelow(subtree, root) || samePath(subtree, root) {
		return nil, fmt.Errorf("invalid Hermes skill subtree: %s", subtree)
	}
	for dir := filepath.Clean(subtree); !samePath(dir, root); dir = filepath.Dir(dir) {
		if !plainDirectory(dir) {
			return nil, fmt.Errorf("linked or unavailable Hermes skill subtree: %s", subtree)
		}
	}
	return discover(root, subtree, directoryLimit)
}

// DiscoverUnderFull completes a moved-in subtree after the bounded walk hits
// its budget. Callers run it off the event reader.
func DiscoverUnderFull(root, subtree string) ([]Entry, error) {
	return DiscoverUnder(root, subtree, FullScanDirectoryLimit)
}

// DiscoverTrusted lists a root whose account-owned link path has already
// passed the shared ownership check. The ordinary Discover entry points keep
// their existing no-link behavior for callers outside the install watcher.
func DiscoverTrusted(root string, directoryLimit int) ([]Entry, error) {
	if !IsRoot(root) && !IsProfileRoot(root) {
		return nil, fmt.Errorf("not a Hermes skills root: %s", root)
	}
	return discoverTrusted(root, root, directoryLimit)
}

// DiscoverUnderTrusted applies the same root proof to an event subtree. A
// link below the root remains unavailable, as in DiscoverUnder.
func DiscoverUnderTrusted(root, subtree string, directoryLimit int) ([]Entry, error) {
	if !IsRoot(root) && !IsProfileRoot(root) {
		return nil, fmt.Errorf("not a Hermes skills root: %s", root)
	}
	if _, err := skillrootsafe.Resolve(root, evalSymlinks); err != nil ||
		!pathAtOrBelow(subtree, root) || samePath(subtree, root) {
		return nil, fmt.Errorf("invalid Hermes skill subtree: %s", subtree)
	}
	for dir := filepath.Clean(subtree); !samePath(dir, root); dir = filepath.Dir(dir) {
		if !plainDirectory(dir) {
			return nil, fmt.Errorf("linked or unavailable Hermes skill subtree: %s", subtree)
		}
	}
	return discoverTrusted(root, subtree, directoryLimit)
}

// Discover through the validated physical root so the vendor digest proof
// sees ordinary paths even when a configured ancestor is linked. Keep the
// configured spelling in returned entries for watcher identity and events.
func discoverTrusted(root, subtree string, directoryLimit int) ([]Entry, error) {
	walkRoot, err := skillrootsafe.Resolve(root, evalSymlinks)
	if err != nil {
		return nil, err
	}
	absoluteRoot, err := filepath.Abs(root)
	if err != nil {
		return nil, err
	}
	absoluteSubtree, err := filepath.Abs(subtree)
	if err != nil {
		return nil, err
	}
	relative, err := filepath.Rel(absoluteRoot, absoluteSubtree)
	if err != nil || relative == ".." || strings.HasPrefix(relative, ".."+string(filepath.Separator)) {
		return nil, fmt.Errorf("hermes subtree outside skills root: %s", subtree)
	}
	walkSubtree := filepath.Join(walkRoot, relative)
	entries, err := discover(walkRoot, walkSubtree, directoryLimit)
	if err != nil {
		return nil, err
	}
	for i := range entries {
		relative, err := filepath.Rel(walkRoot, entries[i].Path)
		if err != nil {
			return nil, err
		}
		entries[i].Path = filepath.Join(root, relative)
	}
	return entries, nil
}

// profileRootUnlinked is canonicalPath for a profile's skills root. The
// managed Windows gateway runs as a virtual service account that is
// granted read on the skills folder only, not list on the profile folders
// above it, so resolving the path is denied and every user's Hermes skills
// went unlisted (GAP-2263). On that denial every existing ancestor must be
// a plain directory too, or a linked profile parent could redirect the walk.
func profileRootUnlinked(root string) bool {
	absolute, err := filepath.Abs(filepath.Clean(root))
	if err != nil {
		return false
	}
	resolved, err := evalSymlinks(absolute)
	if err == nil {
		return samePath(absolute, resolved)
	}
	if !errors.Is(err, fs.ErrPermission) {
		return false
	}
	return UnlinkedAncestors(absolute)
}

// UnlinkedAncestors checks every existing directory up to the volume root.
// It is the no-link proof used when resolving a readable skills folder is
// denied by permissions on one of its parents.
func UnlinkedAncestors(path string) bool {
	for dir := filepath.Clean(path); ; dir = filepath.Dir(dir) {
		if !plainDirectory(dir) {
			return false
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			return true
		}
	}
}

func plainDirectory(path string) bool {
	info, err := os.Lstat(path)
	return err == nil && info.IsDir() && info.Mode()&(os.ModeSymlink|os.ModeIrregular) == 0
}

func discover(root, subtree string, directoryLimit int) ([]Entry, error) {
	if directoryLimit <= 0 {
		directoryLimit = DefaultDirectoryLimit
	}
	entries := make([]Entry, 0)
	visited := 0
	visitedEntries := 0
	err := filepath.WalkDir(subtree, func(path string, entry os.DirEntry, walkErr error) error {
		if walkErr != nil {
			if !samePath(path, subtree) && errors.Is(walkErr, fs.ErrPermission) {
				return filepath.SkipDir
			}
			return walkErr
		}
		if !samePath(subtree, root) {
			visitedEntries++
			if visitedEntries > 8*directoryLimit {
				return ErrDirectoryLimit
			}
		}
		if entry.Type()&os.ModeSymlink != 0 {
			if entry.IsDir() {
				return filepath.SkipDir
			}
			return nil
		}
		if !entry.IsDir() {
			return nil
		}
		if !samePath(subtree, root) && directoryLimit != FullScanDirectoryLimit &&
			strings.Count(path[len(subtree):], string(filepath.Separator)) > DefaultDepthLimit {
			return ErrDirectoryLimit
		}
		visited++
		if visited > directoryLimit {
			return ErrDirectoryLimit
		}
		if samePath(path, root) {
			return nil
		}
		name, ok := readSkillName(path)
		if !ok {
			return nil
		}
		entries = append(entries, Entry{
			Name:    name,
			Path:    path,
			Bundled: matchesVendorDigest(root, path, name),
		})
		return nil
	})
	if err != nil {
		return nil, err
	}
	return entries, nil
}

// IsBundledPath reports whether path is a digest-pinned Hermes bundle or a
// descendant of one.
func IsBundledPath(path string) bool {
	trimmed := strings.TrimSpace(path)
	root := Root()
	if trimmed == "" || root == "" || !pathAtOrBelow(trimmed, root) || samePath(trimmed, root) {
		return false
	}
	current := filepath.Clean(trimmed)
	if info, err := os.Stat(current); err == nil && !info.IsDir() {
		current = filepath.Dir(current)
	}
	for pathAtOrBelow(current, root) && !samePath(current, root) {
		name, ok := readSkillName(current)
		if ok {
			return matchesVendorDigest(root, current, name)
		}
		parent := filepath.Dir(current)
		if parent == current {
			break
		}
		current = parent
	}
	return false
}

// matchesVendorDigest uses the digest shipped with DefenseClaw, independent
// of the installed manifest, launcher, and local Hermes checkout.
func matchesVendorDigest(root, skillDir, name string) bool {
	relative, err := filepath.Rel(root, skillDir)
	if err != nil || relative == "." || relative == ".." ||
		strings.HasPrefix(relative, ".."+string(filepath.Separator)) {
		return false
	}
	if name != filepath.Base(relative) {
		return false
	}
	want := vendorDigests[filepath.ToSlash(relative)]
	if want == "" {
		return false
	}
	current, err := treeSHA256(skillDir)
	return err == nil && current == want
}

func readSkillName(skillDir string) (string, bool) {
	payload, err := readSkillFile(filepath.Join(skillDir, "SKILL.md"))
	if err != nil {
		return "", false
	}
	fallback := filepath.Base(filepath.Clean(skillDir))
	inFrontmatter := false
	for _, raw := range strings.Split(string(payload), "\n") {
		line := strings.TrimSpace(strings.TrimSuffix(raw, "\r"))
		if line == "---" {
			if inFrontmatter {
				break
			}
			inFrontmatter = true
			continue
		}
		if inFrontmatter && strings.HasPrefix(line, "name:") {
			name := strings.Trim(strings.TrimSpace(strings.TrimPrefix(line, "name:")), `"'`)
			if name != "" {
				return name, true
			}
		}
	}
	return fallback, true
}

// readSkillFile reads a SKILL.md with safefile. safefile checks every
// folder above the file for reparse points, which a service account
// granted read on the skills folder only is denied (GAP-2263); then the
// file itself must be a regular file, read as the same file it stat'ed.
func readSkillFile(path string) ([]byte, error) {
	payload, err := readRegularFileBounded(path, markerMaxBytes)
	if err == nil || !errors.Is(err, fs.ErrPermission) {
		return payload, err
	}
	info, err := pathidentity.LstatPinned(path)
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() || info.Size() > markerMaxBytes {
		return nil, fmt.Errorf("not a regular skill file within %d bytes: %s", markerMaxBytes, path)
	}
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	opened, err := file.Stat()
	if err != nil {
		return nil, err
	}
	if !os.SameFile(info, opened) {
		return nil, fmt.Errorf("skill file changed while opening: %s", path)
	}
	payload, err = io.ReadAll(io.LimitReader(file, markerMaxBytes+1))
	if err != nil {
		return nil, err
	}
	if len(payload) > markerMaxBytes {
		return nil, fmt.Errorf("skill file exceeds %d bytes: %s", markerMaxBytes, path)
	}
	return payload, nil
}

func treeSHA256(root string) (string, error) {
	if !canonicalPath(root) {
		return "", fmt.Errorf("skill root is linked or unavailable: %s", root)
	}
	type snapshot struct {
		path string
		info os.FileInfo
	}
	files := make([]snapshot, 0)
	dirs := make([]snapshot, 0)
	var treeBytes int64
	err := filepath.WalkDir(root, func(path string, entry os.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if entry.Type()&os.ModeSymlink != 0 {
			return fmt.Errorf("linked Hermes skill content: %s", path)
		}
		info, err := pathidentity.LstatPinned(path)
		if err != nil {
			return err
		}
		switch {
		case info.IsDir():
			dirs = append(dirs, snapshot{path: path, info: info})
		case info.Mode().IsRegular():
			if info.Size() > maxSkillFileBytes {
				return fmt.Errorf("oversized Hermes skill file: %s", path)
			}
			treeBytes += info.Size()
			if treeBytes > maxSkillTreeBytes {
				return fmt.Errorf("oversized Hermes skill tree: %s", root)
			}
			files = append(files, snapshot{path: path, info: info})
		default:
			return fmt.Errorf("non-regular Hermes skill content: %s", path)
		}
		return nil
	})
	if err != nil {
		return "", err
	}
	sort.Slice(files, func(i, j int) bool {
		left, _ := filepath.Rel(root, files[i].path)
		right, _ := filepath.Rel(root, files[j].path)
		return vendorDigestRelativePath(left) < vendorDigestRelativePath(right)
	})
	digest := sha256.New()
	for _, file := range files {
		relative, err := filepath.Rel(root, file.path)
		if err != nil {
			return "", err
		}
		payload, err := safefile.ReadRegularFileBounded(file.path, maxSkillFileBytes)
		if err != nil {
			return "", err
		}
		_, _ = digest.Write([]byte(vendorDigestRelativePath(relative)))
		_, _ = digest.Write(payload)
	}
	for _, item := range append(dirs, files...) {
		current, err := os.Lstat(item.path)
		if err != nil || !os.SameFile(item.info, current) ||
			item.info.Size() != current.Size() || !item.info.ModTime().Equal(current.ModTime()) {
			return "", fmt.Errorf("Hermes skill changed while hashing: %s", item.path)
		}
	}
	return fmt.Sprintf("%x", digest.Sum(nil)), nil
}

func vendorDigestRelativePath(relative string) string {
	return strings.ReplaceAll(relative, `\`, "/")
}

func canonicalPath(path string) bool {
	absolute, err := filepath.Abs(filepath.Clean(path))
	if err != nil {
		return false
	}
	resolved, err := filepath.EvalSymlinks(absolute)
	return err == nil && samePath(absolute, resolved)
}

func samePath(left, right string) bool {
	leftAbs, leftErr := filepath.Abs(filepath.Clean(left))
	rightAbs, rightErr := filepath.Abs(filepath.Clean(right))
	if leftErr != nil || rightErr != nil {
		return false
	}
	if runtime.GOOS == "windows" {
		return strings.EqualFold(leftAbs, rightAbs)
	}
	return leftAbs == rightAbs
}

func pathAtOrBelow(path, root string) bool {
	pathAbs, err := filepath.Abs(filepath.Clean(path))
	if err != nil {
		return false
	}
	rootAbs, err := filepath.Abs(filepath.Clean(root))
	if err != nil {
		return false
	}
	relative, err := filepath.Rel(rootAbs, pathAbs)
	if err != nil {
		return false
	}
	return relative == "." || (relative != ".." && !strings.HasPrefix(relative, ".."+string(filepath.Separator)))
}

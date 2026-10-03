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
	"bufio"
	"bytes"
	"crypto/md5" // #nosec G501 -- required by Hermes's manifest contract.
	"encoding/hex"
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
	"github.com/defenseclaw/defenseclaw/internal/safefile"
)

const (
	ManifestName          = ".bundled_manifest"
	DefaultDirectoryLimit = 32768
	manifestMaxBytes      = 2 * 1024 * 1024
	markerMaxBytes        = 64 * 1024
	maxSkillFileBytes     = 64 * 1024 * 1024
	maxSkillTreeBytes     = 256 * 1024 * 1024
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

// Discover recursively returns actual Hermes skills and their provenance.
// Copies are bundled only when the manifest, user copy, and matching source in
// the exact Hermes checkout all agree; every other copy remains scanable.
func Discover(root string, directoryLimit int) ([]Entry, error) {
	if !IsRoot(root) {
		return nil, fmt.Errorf("not the resolved Hermes skills root: %s", root)
	}
	if !canonicalPath(root) {
		return nil, fmt.Errorf("Hermes skills root is linked or unavailable: %s", root)
	}
	return discover(root, directoryLimit)
}

// DiscoverProfileRoot is Discover for the Hermes skills root of a profile
// the caller resolved itself: a service-context scan (managed Windows)
// reads every user's profile, while IsRoot resolves only this process's
// own Hermes home. Provenance is decided the same way, against that
// profile's own manifest and Hermes checkout.
func DiscoverProfileRoot(root string, directoryLimit int) ([]Entry, error) {
	if filepath.Base(filepath.Clean(root)) != "skills" {
		return nil, fmt.Errorf("not a Hermes skills root: %s", root)
	}
	if !profileRootUnlinked(root) {
		return nil, fmt.Errorf("Hermes skills root is linked or unavailable: %s", root)
	}
	return discover(root, directoryLimit)
}

// profileRootUnlinked is canonicalPath for a profile's skills root. The
// managed Windows gateway runs as a virtual service account that is
// granted read on the skills folder only, not list on the profile folders
// above it, so resolving the path is denied and every user's Hermes skills
// went unlisted (GAP-2263). On that denial the root itself must still be a
// plain directory; the walk below it skips links.
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
	return plainDirectory(absolute)
}

func plainDirectory(path string) bool {
	info, err := os.Lstat(path)
	return err == nil && info.IsDir() && info.Mode()&(os.ModeSymlink|os.ModeIrregular) == 0
}

func discover(root string, directoryLimit int) ([]Entry, error) {
	if directoryLimit <= 0 {
		directoryLimit = DefaultDirectoryLimit
	}
	manifest := readManifest(root)
	entries := make([]Entry, 0)
	visited := 0
	err := filepath.WalkDir(root, func(path string, entry os.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
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
			Bundled: matchesInstalledSource(root, path, name, manifest[name]),
		})
		return nil
	})
	if err != nil {
		return nil, err
	}
	return entries, nil
}

// IsBundledPath reports whether path is a source-bound Hermes bundle or a
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
	manifest := readManifest(root)
	for pathAtOrBelow(current, root) && !samePath(current, root) {
		name, ok := readSkillName(current)
		if ok {
			return matchesInstalledSource(root, current, name, manifest[name])
		}
		parent := filepath.Dir(current)
		if parent == current {
			break
		}
		current = parent
	}
	return false
}

// matchesInstalledSource binds the writable manifest and user copy to the
// matching source in the exact Hermes installation checkout. If any of the
// three inputs is missing, linked, oversized, modified, or mismatched, the
// skill deliberately remains scanable.
func matchesInstalledSource(root, skillDir, name, manifestHash string) bool {
	origin := strings.ToLower(strings.TrimSpace(manifestHash))
	if origin == "" {
		return false
	}
	current, err := treeMD5(skillDir)
	if err != nil || current != origin {
		return false
	}
	relative, err := filepath.Rel(root, skillDir)
	if err != nil || relative == "." || relative == ".." ||
		strings.HasPrefix(relative, ".."+string(filepath.Separator)) {
		return false
	}
	sourceRoot := filepath.Join(filepath.Dir(root), "hermes-agent", "skills")
	source := filepath.Join(sourceRoot, relative)
	if !pathAtOrBelow(source, sourceRoot) {
		return false
	}
	sourceName, ok := readSkillName(source)
	if !ok || sourceName != name {
		return false
	}
	sourceHash, err := treeMD5(source)
	return err == nil && sourceHash == origin
}

func readManifest(root string) map[string]string {
	payload, err := safefile.ReadRegularFileBounded(
		filepath.Join(root, ManifestName),
		manifestMaxBytes,
	)
	if err != nil {
		return nil
	}
	result := make(map[string]string)
	scanner := bufio.NewScanner(bytes.NewReader(payload))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		name, digest, ok := strings.Cut(line, ":")
		name = strings.TrimSpace(name)
		digest = strings.ToLower(strings.TrimSpace(digest))
		decoded, decodeErr := hex.DecodeString(digest)
		if !ok || name == "" || decodeErr != nil || len(decoded) != md5.Size {
			continue
		}
		result[name] = digest
	}
	return result
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
	info, err := os.Lstat(path)
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

func treeMD5(root string) (string, error) {
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
		info, err := entry.Info()
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
		if runtime.GOOS == "windows" {
			left = strings.ToLower(left)
			right = strings.ToLower(right)
		}
		return left < right
	})
	digest := md5.New() // #nosec G401 -- required by Hermes's manifest contract.
	for _, file := range files {
		relative, err := filepath.Rel(root, file.path)
		if err != nil {
			return "", err
		}
		payload, err := safefile.ReadRegularFileBounded(file.path, maxSkillFileBytes)
		if err != nil {
			return "", err
		}
		_, _ = digest.Write([]byte(relative))
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

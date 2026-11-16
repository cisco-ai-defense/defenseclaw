// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package watcher

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/hermesskills"
	"github.com/defenseclaw/defenseclaw/internal/skillrootsafe"
	"github.com/fsnotify/fsnotify"
)

// Hermes and Cursor discover SKILL.md folders recursively. The first subtree
// pass uses connector budgets; a limit triggers a complete pass off the event
// reader. Live watch registration also runs off the reader.
const nestedSkillDirectoryLimit = hermesskills.DefaultDirectoryLimit
const nestedSkillEntryLimit = 8 * nestedSkillDirectoryLimit
const nestedSkillDepthLimit = hermesskills.DefaultDepthLimit

var watcherEvalSymlinks = filepath.EvalSymlinks

// linkedRootRefusal is the error for a skill root whose link route is not
// trusted. When a folder on the route is writable by another account it names
// that folder and the one change that restores admission scanning (GAP-0905).
func linkedRootRefusal(root string, cause error) error {
	var writable *skillrootsafe.WritableAncestorError
	if errors.As(cause, &writable) {
		return fmt.Errorf("linked or unavailable skill root: %s: %w", root, writable)
	}
	return fmt.Errorf("linked or unavailable skill root: %s", root)
}

// trustedWalkRoot gives WalkDir a real starting directory when the final
// component is a trusted link. WalkDir does not descend through a final link.
// A link below that starting directory remains a non-directory entry.
func trustedWalkRoot(root string) (string, error) {
	info, err := os.Lstat(root)
	if err != nil {
		return "", err
	}
	if info.Mode()&os.ModeSymlink == 0 {
		return root, nil
	}
	return skillrootsafe.Resolve(root, watcherEvalSymlinks)
}

func logicalWalkPath(root, walkRoot, path string) (string, error) {
	if sameWatcherPath(root, walkRoot) {
		return path, nil
	}
	relative, err := filepath.Rel(walkRoot, path)
	if err != nil || relative == ".." || strings.HasPrefix(relative, ".."+string(filepath.Separator)) {
		return "", fmt.Errorf("walk path outside root: %s", path)
	}
	return filepath.Join(root, relative), nil
}

func (w *InstallWatcher) recursiveSkillRoot(path string) (root, connector string, ok bool) {
	if w.secureClientActive() {
		return "", "", false
	}
	for _, candidate := range w.skillDirs {
		if !watcherPathAtOrBelow(path, candidate) || len(candidate) <= len(root) {
			continue
		}
		switch {
		case hermesskills.IsRoot(candidate), hermesskills.IsProfileRoot(candidate):
			root, connector = candidate, "hermes"
		case w.connectorForPath(candidate) == "cursor":
			root, connector = candidate, "cursor"
		}
	}
	return root, connector, root != ""
}

func (w *InstallWatcher) nestedSkillEvents(root, path, connector string) ([]InstallEvent, error) {
	if w.inSkillInstallStaging(root, path, 0) {
		return nil, nil
	}
	var out []InstallEvent
	switch connector {
	case "hermes":
		discover := hermesskills.DiscoverUnder
		if !w.secureClientActive() {
			discover = hermesskills.DiscoverUnderTrusted
		}
		entries, err := discover(root, path, nestedSkillDirectoryLimit)
		if errors.Is(err, hermesskills.ErrDirectoryLimit) {
			entries, err = discover(root, path, hermesskills.FullScanDirectoryLimit)
		}
		if err != nil {
			return nil, err
		}
		for _, entry := range entries {
			if w.inSkillInstallStaging(root, entry.Path, 0) {
				continue
			}
			out = append(out, InstallEvent{Type: InstallSkill, Name: entry.Name, Path: entry.Path,
				Connector: "hermes", Timestamp: time.Now().UTC()})
		}
	case "cursor":
		paths, err := cursorSkillFolders(root, path)
		if errors.Is(err, hermesskills.ErrDirectoryLimit) {
			paths, err = cursorSkillFoldersFull(root, path)
		}
		if err != nil {
			return nil, err
		}
		for _, skill := range paths {
			if w.inSkillInstallStaging(root, skill, 0) || isBundledSkillWatchPath(skill) {
				continue
			}
			evt := w.classifyEvent(skill)
			evt.Type = InstallSkill
			out = append(out, evt)
		}
	}
	return out, nil
}

// cursorSkillFolders visits only the directory named by an event. WalkDir
// itself does not follow child links; the root and event subtree need an
// explicit check before the walk begins.
func cursorSkillFolders(root, subtree string) ([]string, error) {
	return cursorSkillFoldersWithLimit(root, subtree, nestedSkillDirectoryLimit, nestedSkillEntryLimit, nestedSkillDepthLimit)
}

func cursorSkillFoldersFull(root, subtree string) ([]string, error) {
	return cursorSkillFoldersWithLimit(root, subtree, 0, 0, 0)
}

func cursorSkillFoldersWithLimit(root, subtree string, directoryLimit, entryLimit, depthLimit int) ([]string, error) {
	if err := unlinkedSkillTreePath(root, subtree); err != nil {
		return nil, err
	}
	walkSubtree := subtree
	if sameWatcherPath(root, subtree) {
		var err error
		walkSubtree, err = trustedWalkRoot(root)
		if err != nil {
			return nil, err
		}
	}
	var paths []string
	visited := 0
	entries := 0
	err := filepath.WalkDir(walkSubtree, func(path string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			if !sameWatcherPath(path, walkSubtree) && errors.Is(walkErr, fs.ErrPermission) {
				return filepath.SkipDir
			}
			return walkErr
		}
		entries++
		if entryLimit > 0 && entries > entryLimit {
			return hermesskills.ErrDirectoryLimit
		}
		if !entry.IsDir() {
			return nil
		}
		visited++
		if directoryLimit > 0 && visited > directoryLimit {
			return hermesskills.ErrDirectoryLimit
		}
		if depthLimit > 0 && strings.Count(path[len(walkSubtree):], string(filepath.Separator)) > depthLimit {
			return hermesskills.ErrDirectoryLimit
		}
		if (!sameWatcherPath(root, subtree) || !sameWatcherPath(path, walkSubtree)) && hasSkillMarker(path) {
			logical, err := logicalWalkPath(subtree, walkSubtree, path)
			if err != nil {
				return err
			}
			paths = append(paths, logical)
		}
		return nil
	})
	return paths, err
}

// unlinkedSkillTreePath permits a trusted link in the configured root path,
// while still refusing links below that root before discovery or registration.
// WalkDir skips links below the subtree it is given.
func unlinkedSkillTreePath(root, subtree string) error {
	if !watcherPathAtOrBelow(subtree, root) {
		return fmt.Errorf("skill subtree outside watched root: %s", subtree)
	}
	absoluteRoot, err := filepath.Abs(root)
	if err != nil {
		return fmt.Errorf("resolve skill root %s: %w", root, err)
	}
	absoluteSubtree, err := filepath.Abs(subtree)
	if err != nil {
		return fmt.Errorf("resolve skill subtree %s: %w", subtree, err)
	}
	resolvedRoot, err := skillrootsafe.Resolve(absoluteRoot, watcherEvalSymlinks)
	if err != nil {
		return linkedRootRefusal(root, err)
	}
	for dir := filepath.Clean(absoluteSubtree); !sameWatcherPath(dir, absoluteRoot); dir = filepath.Dir(dir) {
		info, err := os.Lstat(dir)
		if err != nil || !info.IsDir() || info.Mode()&(os.ModeSymlink|os.ModeIrregular) != 0 {
			return fmt.Errorf("linked or unavailable skill subtree: %s", subtree)
		}
	}
	relative, err := filepath.Rel(absoluteRoot, absoluteSubtree)
	if err != nil {
		return fmt.Errorf("resolve skill subtree %s: %w", subtree, err)
	}
	want := filepath.Join(resolvedRoot, relative)
	resolvedSubtree, err := watcherEvalSymlinks(absoluteSubtree)
	if err == nil && !sameWatcherPath(resolvedSubtree, want) {
		return fmt.Errorf("skill subtree escapes watched root: %s", subtree)
	}
	if err != nil && (!errors.Is(err, fs.ErrPermission) || !skillrootsafe.UnlinkedAncestors(want)) {
		return fmt.Errorf("skill subtree unavailable: %s", subtree)
	}
	return nil
}

func addNestedSkillWatches(ctx context.Context, fsw *fsnotify.Watcher, root, subtree string, watched map[string]struct{}, mu *sync.Mutex, progress func()) {
	if err := unlinkedSkillTreePath(root, subtree); err != nil {
		return
	}
	walkSubtree := subtree
	if sameWatcherPath(root, subtree) {
		var err error
		walkSubtree, err = trustedWalkRoot(root)
		if err != nil {
			return
		}
	}
	visited := 0
	_ = filepath.WalkDir(walkSubtree, func(path string, entry fs.DirEntry, err error) error {
		if ctx.Err() != nil {
			return fs.SkipAll
		}
		if err != nil {
			return fs.SkipDir
		}
		if !entry.IsDir() {
			return nil
		}
		visited++
		if visited == 1024 && progress != nil {
			progress()
		}
		logical, err := logicalWalkPath(subtree, walkSubtree, path)
		if err != nil {
			return err
		}
		key := strings.ToLower(filepath.Clean(logical))
		if mu != nil {
			mu.Lock()
			defer mu.Unlock()
		}
		if _, exists := watched[key]; !exists {
			if addErr := fsw.Add(logical); addErr == nil {
				watched[key] = struct{}{}
			}
		}
		return nil
	})
}

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
	"runtime"
	"strings"
	"sync"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/hermesskills"
	"github.com/fsnotify/fsnotify"
)

// Hermes and Cursor discover SKILL.md folders recursively. The first subtree
// pass uses connector budgets; a limit triggers a complete pass off the event
// reader. Live watch registration also runs off the reader.
const nestedSkillDirectoryLimit = hermesskills.DefaultDirectoryLimit
const nestedSkillEntryLimit = 8 * nestedSkillDirectoryLimit
const nestedSkillDepthLimit = hermesskills.DefaultDepthLimit

var watcherEvalSymlinks = filepath.EvalSymlinks

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
		entries, err := hermesskills.DiscoverUnder(root, path, nestedSkillDirectoryLimit)
		if errors.Is(err, hermesskills.ErrDirectoryLimit) {
			entries, err = hermesskills.DiscoverUnderFull(root, path)
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
	var paths []string
	visited := 0
	entries := 0
	err := filepath.WalkDir(subtree, func(path string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			if !sameWatcherPath(path, subtree) && errors.Is(walkErr, fs.ErrPermission) {
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
		if depthLimit > 0 && strings.Count(path[len(subtree):], string(filepath.Separator)) > depthLimit {
			return hermesskills.ErrDirectoryLimit
		}
		if !sameWatcherPath(path, root) && hasSkillMarker(path) {
			paths = append(paths, path)
		}
		return nil
	})
	return paths, err
}

// unlinkedSkillTreePath refuses a linked skills root, a linked ancestor of
// that root, or a linked subtree before recursive discovery or registration.
// Comparing resolved paths also catches Windows junctions. Every directory
// from root to subtree must be a real directory; WalkDir skips links below it.
func unlinkedSkillTreePath(root, subtree string) error {
	if !watcherPathAtOrBelow(subtree, root) {
		return fmt.Errorf("skill subtree outside watched root: %s", subtree)
	}
	absoluteRoot, err := filepath.Abs(root)
	if err != nil {
		return fmt.Errorf("resolve skill root %s: %w", root, err)
	}
	resolvedRoot, ok := resolvedUnlinkedSkillPath(absoluteRoot)
	if !ok {
		return fmt.Errorf("linked or unavailable skill root: %s", root)
	}
	for dir := filepath.Clean(subtree); ; dir = filepath.Dir(dir) {
		info, err := os.Lstat(dir)
		if err != nil || !info.IsDir() || info.Mode()&(os.ModeSymlink|os.ModeIrregular) != 0 {
			return fmt.Errorf("linked or unavailable skill subtree: %s", subtree)
		}
		if sameWatcherPath(dir, root) {
			break
		}
	}
	absoluteSubtree, err := filepath.Abs(subtree)
	if err != nil {
		return fmt.Errorf("resolve skill subtree %s: %w", subtree, err)
	}
	resolvedSubtree, ok := resolvedUnlinkedSkillPath(absoluteSubtree)
	if !ok || !watcherPathAtOrBelow(resolvedSubtree, resolvedRoot) {
		return fmt.Errorf("skill subtree escapes watched root: %s", subtree)
	}
	return nil
}

func resolvedUnlinkedSkillPath(path string) (string, bool) {
	canonical := canonicalSkillSystemPath(path)
	resolved, err := watcherEvalSymlinks(path)
	if err == nil {
		return resolved, sameWatcherPath(canonical, resolved)
	}
	if !errors.Is(err, fs.ErrPermission) || !hermesskills.UnlinkedAncestors(canonical) {
		return "", false
	}
	return canonical, true
}

// macOS exposes these root-owned system directories through /private. Accept
// only the exact platform aliases; links below them still fail validation.
func canonicalSkillSystemPath(path string) string {
	if runtime.GOOS != "darwin" {
		return path
	}
	for _, alias := range []string{"/etc", "/var", "/tmp"} {
		if path != alias && !strings.HasPrefix(path, alias+string(filepath.Separator)) {
			continue
		}
		resolved, err := filepath.EvalSymlinks(alias)
		if err != nil || resolved != "/private"+alias {
			return path
		}
		if path == alias {
			return resolved
		}
		return filepath.Join(resolved, strings.TrimPrefix(path, alias+string(filepath.Separator)))
	}
	return path
}

func addNestedSkillWatches(ctx context.Context, fsw *fsnotify.Watcher, root, subtree string, watched map[string]struct{}, mu *sync.Mutex, progress func()) {
	if err := unlinkedSkillTreePath(root, subtree); err != nil {
		return
	}
	visited := 0
	_ = filepath.WalkDir(subtree, func(path string, entry fs.DirEntry, err error) error {
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
		key := strings.ToLower(filepath.Clean(path))
		if mu != nil {
			mu.Lock()
			defer mu.Unlock()
		}
		if _, exists := watched[key]; !exists {
			if addErr := fsw.Add(path); addErr == nil {
				watched[key] = struct{}{}
			}
		}
		return nil
	})
}

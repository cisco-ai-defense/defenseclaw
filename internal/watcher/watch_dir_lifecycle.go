// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package watcher

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"github.com/fsnotify/fsnotify"
)

type ownedWatchDir struct {
	path     string
	identity os.FileInfo
}

func ensureAndWatch(fsw *fsnotify.Watcher, dir string) ([]ownedWatchDir, error) {
	created, err := createWatchDir(dir)
	if err != nil {
		return nil, fmt.Errorf("create dir: %w", err)
	}

	path, err := filepath.Abs(dir)
	if err != nil {
		_ = cleanupOwnedWatchDirs(created)
		return nil, fmt.Errorf("resolve watch dir: %w", err)
	}
	if err := fsw.Add(path); err != nil {
		cleanupErr := cleanupOwnedWatchDirs(created)
		if cleanupErr != nil {
			return nil, fmt.Errorf("watch: %w; cleanup: %v", err, cleanupErr)
		}
		return nil, fmt.Errorf("watch: %w", err)
	}

	return created, nil
}

func createWatchDir(dir string) ([]ownedWatchDir, error) {
	if dir == "" {
		return nil, errors.New("watch path is empty")
	}
	path, err := filepath.Abs(dir)
	if err != nil {
		return nil, err
	}
	path = filepath.Clean(path)
	if info, statErr := os.Lstat(path); statErr == nil && watchDirIsLinkOrReparse(path, info) {
		target, targetErr := os.Stat(path)
		if targetErr != nil {
			return nil, fmt.Errorf("inspect linked watch directory: %w", targetErr)
		}
		if !target.IsDir() {
			return nil, fmt.Errorf("linked watch path target is not a real directory: %s", path)
		}
		return nil, nil
	}

	missing := make([]string, 0, 2)
	for current := path; ; current = filepath.Dir(current) {
		info, statErr := os.Lstat(current)
		if statErr == nil {
			if watchDirIsLinkOrReparse(current, info) || !info.IsDir() {
				return nil, fmt.Errorf("watch path component is not a real directory: %s", current)
			}
			break
		}
		if !errors.Is(statErr, os.ErrNotExist) {
			return nil, statErr
		}
		missing = append(missing, current)
		parent := filepath.Dir(current)
		if parent == current {
			return nil, fmt.Errorf("watch path has no existing directory ancestor: %s", path)
		}
	}

	created := make([]ownedWatchDir, 0, len(missing))
	for i := len(missing) - 1; i >= 0; i-- {
		current := missing[i]
		mkdirErr := os.Mkdir(current, 0o700)
		if mkdirErr != nil && !errors.Is(mkdirErr, os.ErrExist) {
			_ = cleanupOwnedWatchDirs(created)
			return nil, mkdirErr
		}
		info, statErr := os.Lstat(current)
		if statErr != nil {
			_ = cleanupOwnedWatchDirs(created)
			return nil, statErr
		}
		if watchDirIsLinkOrReparse(current, info) || !info.IsDir() {
			_ = cleanupOwnedWatchDirs(created)
			return nil, fmt.Errorf("watch path component is not a real directory: %s", current)
		}
		if mkdirErr == nil {
			identity, identityErr := snapshotWatchDirIdentity(current)
			if identityErr != nil {
				_ = cleanupOwnedWatchDirs(created)
				return nil, fmt.Errorf("record watch path identity: %w", identityErr)
			}
			created = append(created, ownedWatchDir{path: current, identity: identity})
		}
	}

	return created, nil
}

func snapshotWatchDirIdentity(path string) (os.FileInfo, error) {
	dir, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	info, statErr := dir.Stat()
	closeErr := dir.Close()
	if statErr != nil {
		return nil, errors.Join(statErr, closeErr)
	}
	if closeErr != nil {
		return nil, closeErr
	}
	return info, nil
}

func cleanupOwnedWatchDirs(created []ownedWatchDir) error {
	var cleanupErr error
	for i := len(created) - 1; i >= 0; i-- {
		owned := created[i]
		current, err := os.Lstat(owned.path)
		if errors.Is(err, os.ErrNotExist) {
			continue
		}
		if err != nil {
			cleanupErr = errors.Join(cleanupErr, fmt.Errorf("inspect %s: %w", owned.path, err))
			continue
		}
		if watchDirIsLinkOrReparse(owned.path, current) || !current.IsDir() || !os.SameFile(owned.identity, current) {
			continue
		}
		entries, err := os.ReadDir(owned.path)
		if err != nil {
			cleanupErr = errors.Join(cleanupErr, fmt.Errorf("inspect contents of %s: %w", owned.path, err))
			continue
		}
		if len(entries) != 0 {
			continue
		}
		verified, err := os.Lstat(owned.path)
		if errors.Is(err, os.ErrNotExist) {
			continue
		}
		if err != nil {
			cleanupErr = errors.Join(cleanupErr, fmt.Errorf("revalidate %s: %w", owned.path, err))
			continue
		}
		if watchDirIsLinkOrReparse(owned.path, verified) || !verified.IsDir() ||
			!os.SameFile(owned.identity, verified) || !os.SameFile(current, verified) {
			continue
		}
		if err := os.Remove(owned.path); err != nil {
			if errors.Is(err, os.ErrNotExist) {
				continue
			}
			remaining, readErr := os.ReadDir(owned.path)
			if readErr == nil && len(remaining) != 0 {
				continue
			}
			if errors.Is(readErr, os.ErrNotExist) {
				continue
			}
			cleanupErr = errors.Join(cleanupErr, fmt.Errorf("remove %s: %w", owned.path, err))
		}
	}
	return cleanupErr
}

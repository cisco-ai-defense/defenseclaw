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

package connector

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"

	"github.com/defenseclaw/defenseclaw/internal/safefile"
)

const atomicTransformMaxAttempts = 8

var errAtomicTransformConflict = errors.New("atomic transform target changed")

// atomicTransformResult is the next state returned by a read/merge
// transformation. Remove is used by teardown when the connector originally
// created a config file that did not exist before setup.
type atomicTransformResult struct {
	Data   []byte
	Remove bool
	Perm   os.FileMode
}

type atomicFileSnapshot struct {
	writePath string
	exists    bool
	data      []byte
	info      os.FileInfo
}

// atomicTransformFile performs an optimistic read/merge/compare-and-swap.
//
// The advisory connector lock serializes DefenseClaw processes, but Codex,
// Claude Code, an editor, or an enterprise policy agent can update the same
// config without taking that lock. Each attempt therefore reads an exact file
// snapshot, reruns the complete caller-supplied transformation, stages the
// replacement, and then verifies the target's file identity and bytes
// immediately before replacement. A changed snapshot is never overwritten;
// it causes a fresh read/merge attempt. Persistent contention fails closed.
func atomicTransformFile(
	path string,
	perm os.FileMode,
	transform func(current []byte, exists bool) (atomicTransformResult, error),
) error {
	for attempt := 0; attempt < atomicTransformMaxAttempts; attempt++ {
		snapshot, err := readAtomicFileSnapshot(path)
		if err != nil {
			return err
		}
		result, err := transform(append([]byte(nil), snapshot.data...), snapshot.exists)
		if err != nil {
			return err
		}

		semanticNoop := (!snapshot.exists && result.Remove) ||
			(snapshot.exists && !result.Remove && bytes.Equal(snapshot.data, result.Data))

		var tmpPath string
		if !result.Remove && !semanticNoop {
			writePerm := result.Perm
			if writePerm == 0 {
				writePerm = perm
			}
			tmpPath, err = stageAtomicTransformFile(snapshot.writePath, result.Data, writePerm)
			if err != nil {
				return err
			}
		}

		runAtomicTransformBeforeCompareHook(path, attempt)
		matches, err := atomicFileSnapshotStillMatches(path, snapshot)
		if err != nil {
			if tmpPath != "" {
				_ = os.Remove(tmpPath)
			}
			return err
		}
		if !matches {
			if tmpPath != "" {
				_ = os.Remove(tmpPath)
			}
			continue
		}
		// A semantic no-op must not churn mtime, ACLs, or formatting, but it
		// still participates in the optimistic compare. Otherwise an editor can
		// change the file after our read and Setup/Teardown can incorrectly
		// report success without establishing its postcondition.
		if semanticNoop {
			return nil
		}

		runAtomicTransformBeforeCommitHook(path, attempt)
		if result.Remove {
			if err := os.Remove(snapshot.writePath); err != nil {
				if os.IsNotExist(err) {
					continue
				}
				return fmt.Errorf("remove %s after compare: %w", snapshot.writePath, err)
			}
		} else if !snapshot.exists {
			if err := installAtomicTransformFile(tmpPath, snapshot.writePath); err != nil {
				_ = os.Remove(tmpPath)
				if errors.Is(err, errAtomicTransformConflict) {
					continue
				}
				return fmt.Errorf("install %s after compare: %w", snapshot.writePath, err)
			}
		} else if err := safefile.ReplaceFile(tmpPath, snapshot.writePath); err != nil {
			_ = os.Remove(tmpPath)
			return fmt.Errorf("replace %s after compare: %w", snapshot.writePath, err)
		}
		if err := syncAtomicTransformParent(filepath.Dir(snapshot.writePath)); err != nil {
			return err
		}
		return nil
	}
	return fmt.Errorf(
		"config %s changed during each of %d read/merge attempts; refusing to overwrite concurrent edits",
		path,
		atomicTransformMaxAttempts,
	)
}

func loadManagedFileBackupForTransform(
	dataDir, connectorName, logicalName, targetPath string,
) (*managedFileBackup, error) {
	backup, err := loadManagedFileBackupPath(managedFileBackupPath(dataDir, connectorName, logicalName))
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	if _, err := validateManagedFileBackupTarget(backup, connectorName, logicalName, targetPath); err != nil {
		return nil, err
	}
	return &backup, nil
}

// managedFileBackupTransform returns the exact pristine state only when the
// bytes being transformed still match the connector's recorded post-setup
// state. A drifted file falls through to the caller's surgical merge.
func managedFileBackupTransform(
	backup *managedFileBackup,
	current []byte,
	exists bool,
) (atomicTransformResult, bool) {
	if backup == nil {
		return atomicTransformResult{}, false
	}
	if !managedFileBackupMatchesSnapshot(backup, current, exists) {
		return atomicTransformResult{}, false
	}
	if !backup.Existed {
		return atomicTransformResult{Remove: true}, true
	}
	mode := os.FileMode(backup.Mode)
	if mode == 0 {
		mode = 0o600
	}
	return atomicTransformResult{
		Data: append([]byte(nil), backup.PristineBytes...),
		Perm: mode,
	}, true
}

func readAtomicFileSnapshot(path string) (atomicFileSnapshot, error) {
	writePath, err := resolveAtomicWritePath(path)
	if err != nil {
		return atomicFileSnapshot{}, err
	}
	snapshot := atomicFileSnapshot{writePath: writePath}
	file, err := os.Open(writePath)
	if err != nil {
		if os.IsNotExist(err) {
			return snapshot, nil
		}
		return snapshot, fmt.Errorf("open %s for compare-and-swap: %w", writePath, err)
	}
	defer file.Close()

	info, err := file.Stat()
	if err != nil {
		return snapshot, fmt.Errorf("stat open config %s: %w", writePath, err)
	}
	if !info.Mode().IsRegular() {
		return snapshot, fmt.Errorf("config %s is not a regular file", writePath)
	}
	data, err := io.ReadAll(file)
	if err != nil {
		return snapshot, fmt.Errorf("read open config %s: %w", writePath, err)
	}
	pathInfo, err := os.Lstat(writePath)
	if err != nil {
		if os.IsNotExist(err) {
			return readAtomicFileSnapshot(path)
		}
		return snapshot, fmt.Errorf("lstat config %s after read: %w", writePath, err)
	}
	if pathInfo.Mode()&os.ModeSymlink != 0 || !os.SameFile(info, pathInfo) {
		return readAtomicFileSnapshot(path)
	}
	snapshot.exists = true
	snapshot.data = data
	snapshot.info = info
	return snapshot, nil
}

func atomicFileSnapshotStillMatches(path string, snapshot atomicFileSnapshot) (bool, error) {
	writePath, err := resolveAtomicWritePath(path)
	if err != nil {
		return false, err
	}
	if !atomicTransformPathsEqual(writePath, snapshot.writePath) {
		return false, nil
	}
	if !snapshot.exists {
		_, err := os.Lstat(writePath)
		if os.IsNotExist(err) {
			return true, nil
		}
		if err != nil {
			return false, fmt.Errorf("lstat config %s before create: %w", writePath, err)
		}
		return false, nil
	}

	file, err := os.Open(writePath)
	if err != nil {
		if os.IsNotExist(err) {
			return false, nil
		}
		return false, fmt.Errorf("open config %s before replacement: %w", writePath, err)
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil {
		return false, fmt.Errorf("stat config %s before replacement: %w", writePath, err)
	}
	if !os.SameFile(snapshot.info, info) {
		return false, nil
	}
	data, err := io.ReadAll(file)
	if err != nil {
		return false, fmt.Errorf("read config %s before replacement: %w", writePath, err)
	}
	if !bytes.Equal(snapshot.data, data) {
		return false, nil
	}
	pathInfo, err := os.Lstat(writePath)
	if err != nil {
		if os.IsNotExist(err) {
			return false, nil
		}
		return false, fmt.Errorf("lstat config %s before replacement: %w", writePath, err)
	}
	if pathInfo.Mode()&os.ModeSymlink != 0 || !os.SameFile(info, pathInfo) {
		return false, nil
	}
	resolvedAgain, err := resolveAtomicWritePath(path)
	if err != nil {
		return false, err
	}
	return atomicTransformPathsEqual(resolvedAgain, snapshot.writePath), nil
}

func stageAtomicTransformFile(writePath string, data []byte, perm os.FileMode) (string, error) {
	dir := filepath.Dir(writePath)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return "", fmt.Errorf("create directory for %s: %w", writePath, err)
	}
	tmp, err := os.CreateTemp(dir, ".tmp-cas-*")
	if err != nil {
		return "", fmt.Errorf("create compare-and-swap temp file: %w", err)
	}
	tmpPath := tmp.Name()
	cleanup := func(cause error) (string, error) {
		_ = tmp.Close()
		_ = os.Remove(tmpPath)
		return "", cause
	}
	if runtime.GOOS == "windows" && perm.Perm()&0o077 == 0 {
		if err := safefile.ProtectFile(tmpPath); err != nil {
			return cleanup(fmt.Errorf("protect compare-and-swap temp file: %w", err))
		}
	}
	if _, err := tmp.Write(data); err != nil {
		return cleanup(fmt.Errorf("write compare-and-swap temp file: %w", err))
	}
	if err := tmp.Chmod(perm); err != nil {
		return cleanup(fmt.Errorf("chmod compare-and-swap temp file: %w", err))
	}
	if err := tmp.Sync(); err != nil {
		return cleanup(fmt.Errorf("sync compare-and-swap temp file: %w", err))
	}
	if err := tmp.Close(); err != nil {
		_ = os.Remove(tmpPath)
		return "", fmt.Errorf("close compare-and-swap temp file: %w", err)
	}
	return tmpPath, nil
}

func syncAtomicTransformParent(dir string) error {
	if runtime.GOOS == "windows" {
		// safefile.ReplaceFile uses MOVEFILE_WRITE_THROUGH on Windows.
		return nil
	}
	parent, err := os.Open(dir)
	if err != nil {
		return fmt.Errorf("open config parent for sync: %w", err)
	}
	syncErr := parent.Sync()
	closeErr := parent.Close()
	if syncErr != nil {
		return fmt.Errorf("sync config parent: %w", syncErr)
	}
	if closeErr != nil {
		return fmt.Errorf("close config parent after sync: %w", closeErr)
	}
	return nil
}

func atomicTransformPathsEqual(a, b string) bool {
	a = filepath.Clean(a)
	b = filepath.Clean(b)
	if runtime.GOOS == "windows" {
		return strings.EqualFold(a, b)
	}
	return a == b
}

// A path-keyed injection seam makes concurrent-edit tests deterministic while
// allowing unrelated parallel package tests to continue safely.
var atomicTransformTestHooks = struct {
	sync.RWMutex
	byPath map[string]func(attempt int)
}{byPath: map[string]func(int){}}

var atomicTransformBeforeCommitTestHooks = struct {
	sync.RWMutex
	byPath map[string]func(attempt int)
}{byPath: map[string]func(int){}}

func setAtomicTransformBeforeCompareHookForTest(path string, hook func(attempt int)) func() {
	key := filepath.Clean(path)
	atomicTransformTestHooks.Lock()
	previous := atomicTransformTestHooks.byPath[key]
	atomicTransformTestHooks.byPath[key] = hook
	atomicTransformTestHooks.Unlock()
	return func() {
		atomicTransformTestHooks.Lock()
		defer atomicTransformTestHooks.Unlock()
		if previous == nil {
			delete(atomicTransformTestHooks.byPath, key)
			return
		}
		atomicTransformTestHooks.byPath[key] = previous
	}
}

func runAtomicTransformBeforeCompareHook(path string, attempt int) {
	key := filepath.Clean(path)
	atomicTransformTestHooks.RLock()
	hook := atomicTransformTestHooks.byPath[key]
	atomicTransformTestHooks.RUnlock()
	if hook != nil {
		hook(attempt)
	}
}

func setAtomicTransformBeforeCommitHookForTest(path string, hook func(attempt int)) func() {
	key := filepath.Clean(path)
	atomicTransformBeforeCommitTestHooks.Lock()
	previous := atomicTransformBeforeCommitTestHooks.byPath[key]
	atomicTransformBeforeCommitTestHooks.byPath[key] = hook
	atomicTransformBeforeCommitTestHooks.Unlock()
	return func() {
		atomicTransformBeforeCommitTestHooks.Lock()
		defer atomicTransformBeforeCommitTestHooks.Unlock()
		if previous == nil {
			delete(atomicTransformBeforeCommitTestHooks.byPath, key)
			return
		}
		atomicTransformBeforeCommitTestHooks.byPath[key] = previous
	}
}

func runAtomicTransformBeforeCommitHook(path string, attempt int) {
	key := filepath.Clean(path)
	atomicTransformBeforeCommitTestHooks.RLock()
	hook := atomicTransformBeforeCommitTestHooks.byPath[key]
	atomicTransformBeforeCommitTestHooks.RUnlock()
	if hook != nil {
		hook(attempt)
	}
}

// Keep errors imported through errors.Is in callers without exposing the
// snapshot implementation. This helper also normalizes Windows path-not-found
// variants wrapped by os.PathError.
func atomicTransformIsNotExist(err error) bool {
	return errors.Is(err, os.ErrNotExist)
}

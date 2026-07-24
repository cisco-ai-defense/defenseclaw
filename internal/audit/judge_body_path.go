// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// SPDX-License-Identifier: Apache-2.0

package audit

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
)

type judgeBodyPathHooks struct {
	chmodFile        func(*os.File, os.FileMode) error
	chmodPath        func(string, os.FileMode) error
	beforeSQLiteOpen func(string) error
}

func (hooks judgeBodyPathHooks) withDefaults() judgeBodyPathHooks {
	if hooks.chmodFile == nil {
		hooks.chmodFile = func(file *os.File, mode os.FileMode) error { return file.Chmod(mode) }
	}
	if hooks.chmodPath == nil {
		hooks.chmodPath = os.Chmod
	}
	return hooks
}

type preparedJudgeBodyPath struct {
	path        string
	pinned      *os.File
	securedMode os.FileMode
	hooks       judgeBodyPathHooks
}

func (prepared *preparedJudgeBodyPath) close() {
	if prepared != nil && prepared.pinned != nil {
		_ = prepared.pinned.Close()
		prepared.pinned = nil
	}
}

func prepareJudgeBodyDatabasePath(path string, hooks judgeBodyPathHooks) (*preparedJudgeBodyPath, error) {
	// openSQLite appends its pragma query to the filename. Reject a filename
	// that already contains the DSN delimiter so the validated filesystem path
	// cannot differ from the file SQLite actually opens.
	if strings.ContainsRune(path, '?') {
		return nil, errors.New("judge_body: database path contains an unsupported DSN delimiter")
	}
	absolute, err := filepath.Abs(filepath.Clean(path))
	if err != nil {
		return nil, errors.New("judge_body: normalize database path")
	}
	if err := ensureTrustedJudgeBodyParents(filepath.Dir(absolute), hooks, true); err != nil {
		return nil, err
	}

	pinned, created, err := openPinnedJudgeBodyLeaf(absolute)
	if err != nil {
		return nil, err
	}
	prepared := &preparedJudgeBodyPath{path: absolute, pinned: pinned, hooks: hooks}
	fail := func(err error) (*preparedJudgeBodyPath, error) {
		prepared.close()
		return nil, err
	}
	if created {
		if err := secureJudgeBodyPlatformPath(absolute, false); err != nil {
			return fail(err)
		}
	}

	info, err := pinned.Stat()
	if err != nil {
		return fail(fmt.Errorf("judge_body: inspect database file: %w", err))
	}
	if err := validateJudgeBodyLeaf(absolute, info); err != nil {
		return fail(err)
	}

	currentMode := info.Mode().Perm()
	targetMode := tightenedJudgeBodyFileMode(currentMode)
	if created {
		targetMode = 0o600
	}
	// A newly created file must be exactly 0600 even under an unusually
	// restrictive umask. Existing files are only tightened: intersecting with
	// 0600 can remove permissions but can never add one.
	if created || targetMode != currentMode {
		if err := hooks.chmodFile(pinned, targetMode); err != nil {
			return fail(fmt.Errorf("judge_body: secure database file permissions: %w", err))
		}
	}
	if err := validatePinnedJudgeBodyLeaf(absolute, pinned); err != nil {
		return fail(err)
	}
	tightenedInfo, err := pinned.Stat()
	if err != nil {
		return fail(fmt.Errorf("judge_body: inspect secured database file: %w", err))
	}
	if !judgeBodyModeMatches(tightenedInfo, targetMode) {
		return fail(errors.New("judge_body: database file permissions could not be secured"))
	}
	if err := secureJudgeBodySQLiteSidecars(absolute, hooks); err != nil {
		return fail(err)
	}
	prepared.securedMode = targetMode
	return prepared, nil
}

var judgeBodySQLiteSidecarSuffixes = [...]string{"-wal", "-shm", "-journal"}

// secureJudgeBodySQLiteSidecars closes the upgrade/crash gap left by older
// constructors that tightened only the main database file. WAL and journal
// files contain raw database pages and therefore require the same trust and
// confidentiality boundary before SQLite can reuse them.
func secureJudgeBodySQLiteSidecars(databasePath string, hooks judgeBodyPathHooks) error {
	hooks = hooks.withDefaults()
	for _, suffix := range judgeBodySQLiteSidecarSuffixes {
		path := databasePath + suffix
		before, err := os.Lstat(path)
		if os.IsNotExist(err) {
			continue
		}
		if err != nil {
			return fmt.Errorf("judge_body: inspect SQLite sidecar %s: %w", suffix, err)
		}
		if err := validateJudgeBodyLeaf(path, before); err != nil {
			return fmt.Errorf("judge_body: unsafe SQLite sidecar %s: %w", suffix, err)
		}
		targetMode := tightenedJudgeBodyFileMode(before.Mode().Perm())
		if targetMode != before.Mode().Perm() {
			if err := hooks.chmodPath(path, targetMode); err != nil {
				return fmt.Errorf("judge_body: secure SQLite sidecar %s permissions: %w", suffix, err)
			}
		}
		if err := secureJudgeBodyPlatformPath(path, false); err != nil {
			return fmt.Errorf("judge_body: secure SQLite sidecar %s platform ACL: %w", suffix, err)
		}
		after, err := os.Lstat(path)
		if err != nil {
			return fmt.Errorf("judge_body: re-inspect SQLite sidecar %s: %w", suffix, err)
		}
		if !os.SameFile(before, after) {
			return fmt.Errorf("judge_body: SQLite sidecar %s changed during secure open", suffix)
		}
		if err := validateJudgeBodyLeaf(path, after); err != nil {
			return fmt.Errorf("judge_body: unsafe SQLite sidecar %s after securing: %w", suffix, err)
		}
		if !judgeBodyModeMatches(after, targetMode) {
			return fmt.Errorf("judge_body: SQLite sidecar %s permissions could not be secured", suffix)
		}
	}
	return nil
}

func openPinnedJudgeBodyLeaf(path string) (*os.File, bool, error) {
	info, err := os.Lstat(path)
	if err == nil {
		if err := validateJudgeBodyLeaf(path, info); err != nil {
			return nil, false, err
		}
		file, openErr := openJudgeBodyFileNoFollow(path, false)
		if openErr != nil {
			return nil, false, fmt.Errorf("judge_body: open existing database file safely: %w", openErr)
		}
		return file, false, nil
	}
	if !os.IsNotExist(err) {
		return nil, false, fmt.Errorf("judge_body: inspect database file: %w", err)
	}

	file, err := openJudgeBodyFileNoFollow(path, true)
	if err == nil {
		return file, true, nil
	}
	// If another creator won the race, re-run the full leaf validation and
	// open without following links. Every other error is terminal.
	if !os.IsExist(err) {
		return nil, false, fmt.Errorf("judge_body: create database file safely: %w", err)
	}
	info, statErr := os.Lstat(path)
	if statErr != nil {
		return nil, false, fmt.Errorf("judge_body: inspect raced database file: %w", statErr)
	}
	if err := validateJudgeBodyLeaf(path, info); err != nil {
		return nil, false, err
	}
	file, err = openJudgeBodyFileNoFollow(path, false)
	if err != nil {
		return nil, false, fmt.Errorf("judge_body: open raced database file safely: %w", err)
	}
	return file, false, nil
}

func ensureTrustedJudgeBodyParents(parent string, hooks judgeBodyPathHooks, allowCreate bool) error {
	parent = filepath.Clean(parent)
	chain := make([]string, 0, 8)
	for current := parent; ; current = filepath.Dir(current) {
		chain = append(chain, current)
		next := filepath.Dir(current)
		if next == current {
			break
		}
	}
	for left, right := 0, len(chain)-1; left < right; left, right = left+1, right-1 {
		chain[left], chain[right] = chain[right], chain[left]
	}

	for _, directory := range chain {
		info, err := os.Lstat(directory)
		created := false
		if os.IsNotExist(err) {
			if !allowCreate {
				return errors.New("judge_body: database directory changed during secure open")
			}
			mkdirErr := os.Mkdir(directory, 0o700)
			if mkdirErr != nil && !os.IsExist(mkdirErr) {
				return fmt.Errorf("judge_body: create database directory: %w", mkdirErr)
			}
			created = mkdirErr == nil
			info, err = os.Lstat(directory)
		}
		if err != nil {
			return fmt.Errorf("judge_body: inspect database directory: %w", err)
		}
		if created {
			if err := secureJudgeBodyPlatformPath(directory, true); err != nil {
				return err
			}
			info, err = os.Lstat(directory)
			if err != nil {
				return fmt.Errorf("judge_body: re-inspect database directory: %w", err)
			}
		}
		if err := validateJudgeBodyDirectory(directory, info, directory != parent); err != nil {
			return err
		}
		if created {
			if err := hooks.chmodPath(directory, 0o700); err != nil {
				return fmt.Errorf("judge_body: secure database directory permissions: %w", err)
			}
			info, err = os.Lstat(directory)
			if err != nil {
				return fmt.Errorf("judge_body: re-inspect database directory: %w", err)
			}
			if !judgeBodyModeMatches(info, 0o700) {
				return errors.New("judge_body: new database directory permissions are not 0700")
			}
		}
	}
	return nil
}

func validateJudgeBodyDirectory(path string, info os.FileInfo, allowStickyWritableAncestor bool) error {
	if info.Mode()&os.ModeSymlink != 0 {
		if trustedJudgeBodySystemDirectoryAlias(path, info) {
			resolved, err := filepath.EvalSymlinks(path)
			if err != nil {
				return fmt.Errorf("judge_body: resolve trusted system directory alias: %w", err)
			}
			target, err := os.Stat(resolved)
			if err != nil {
				return fmt.Errorf("judge_body: inspect trusted system directory alias: %w", err)
			}
			return validateJudgeBodyDirectory(resolved, target, allowStickyWritableAncestor)
		}
		return errors.New("judge_body: database path contains a symbolic link")
	}
	if !info.IsDir() {
		return errors.New("judge_body: database parent is not a directory")
	}
	if err := validateJudgeBodyPlatformTrust(path, info, true, !allowStickyWritableAncestor); err != nil {
		return err
	}
	// Root-owned sticky directories are acceptable only above the immediate
	// database parent. SQLite creates WAL/SHM/journal siblings by name, so a
	// world-writable final parent would let another local user pre-create or
	// observe those files even though the main database leaf is pinned.
	if !allowStickyWritableAncestor && !judgeBodyImmediateDirectoryModeTrusted(info) {
		return errors.New("judge_body: immediate database directory is group- or other-writable")
	}
	return nil
}

func validateJudgeBodyLeaf(path string, info os.FileInfo) error {
	if info.Mode()&os.ModeSymlink != 0 {
		return errors.New("judge_body: database file must not be a symbolic link")
	}
	if !info.Mode().IsRegular() {
		return errors.New("judge_body: database file must be regular")
	}
	if err := validateJudgeBodyPlatformTrust(path, info, false, true); err != nil {
		return err
	}
	return nil
}

func validatePinnedJudgeBodyLeaf(path string, pinned *os.File) error {
	pinnedInfo, err := pinned.Stat()
	if err != nil {
		return fmt.Errorf("judge_body: inspect pinned database file: %w", err)
	}
	if err := validateJudgeBodyLeaf(path, pinnedInfo); err != nil {
		return err
	}
	pathInfo, err := os.Lstat(path)
	if err != nil {
		return fmt.Errorf("judge_body: re-inspect database file: %w", err)
	}
	if err := validateJudgeBodyLeaf(path, pathInfo); err != nil {
		return err
	}
	if !os.SameFile(pinnedInfo, pathInfo) {
		return errors.New("judge_body: database file changed during secure open")
	}
	return nil
}

func (prepared *preparedJudgeBodyPath) validateAfterOpen() error {
	if prepared == nil || prepared.pinned == nil {
		return errors.New("judge_body: secure database path handle is unavailable")
	}
	if err := ensureTrustedJudgeBodyParents(filepath.Dir(prepared.path), judgeBodyPathHooks{}.withDefaults(), false); err != nil {
		return err
	}
	if err := validatePinnedJudgeBodyLeaf(prepared.path, prepared.pinned); err != nil {
		return err
	}
	info, err := prepared.pinned.Stat()
	if err != nil {
		return fmt.Errorf("judge_body: inspect database file after open: %w", err)
	}
	if !judgeBodyModeMatches(info, prepared.securedMode) {
		return errors.New("judge_body: database file permissions changed during secure open")
	}
	if err := secureJudgeBodySQLiteSidecars(prepared.path, prepared.hooks); err != nil {
		return err
	}
	return nil
}

func tightenedJudgeBodyFileMode(mode os.FileMode) os.FileMode {
	return mode.Perm() & 0o600
}

// sameJudgeBodyDatabaseFile compares both normalized names and existing file
// identity. Cutover uses this to reject hard-link aliases between audit.db and
// judge_bodies.db, not merely identical configured strings.
func sameJudgeBodyDatabaseFile(left, right string) bool {
	if strings.TrimSpace(left) == "" || strings.TrimSpace(right) == "" {
		return false
	}
	absLeft, leftErr := filepath.Abs(filepath.Clean(left))
	absRight, rightErr := filepath.Abs(filepath.Clean(right))
	if leftErr == nil && rightErr == nil {
		if absLeft == absRight || runtime.GOOS == "windows" && strings.EqualFold(absLeft, absRight) {
			return true
		}
	}
	leftInfo, leftErr := os.Stat(left)
	rightInfo, rightErr := os.Stat(right)
	return leftErr == nil && rightErr == nil && os.SameFile(leftInfo, rightInfo)
}

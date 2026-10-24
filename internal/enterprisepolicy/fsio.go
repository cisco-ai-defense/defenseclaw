// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// SPDX-License-Identifier: Apache-2.0

package enterprisepolicy

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
)

// policyFileLimit bounds every vendor policy read. Real files are a few KiB.
const policyFileLimit = 4 << 20

func sha256Hex(data []byte) string {
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

// readBounded reads an already-opened regular file with a hard size cap.
func readBounded(file *os.File, limit int64) ([]byte, error) {
	data, err := io.ReadAll(io.LimitReader(file, limit+1))
	if err != nil {
		return nil, err
	}
	if int64(len(data)) > limit {
		return nil, &readLimitError{path: file.Name(), limit: limit}
	}
	return data, nil
}

// readLimitError reports a file larger than the limit its reader allows.
type readLimitError struct {
	path  string
	limit int64
}

func (e *readLimitError) Error() string { return fmt.Sprintf("%s exceeds %d bytes", e.path, e.limit) }

// untrustedPolicyFileError reports an existing policy file that fails the
// administrator-ownership rules.
type untrustedPolicyFileError struct {
	path string
	err  error
}

func (e *untrustedPolicyFileError) Error() string { return e.err.Error() }

func (e *untrustedPolicyFileError) Unwrap() error { return e.err }

// policyTakeBack is what reclaimPolicyDirs did to a policy path's vendor
// directories.
type policyTakeBack struct {
	// reclaimed directories now carry DefenseClaw's owner and protected DACL.
	reclaimed []string
	// created directories replace an object an unprivileged user planted.
	created []string
	// notes describe the planted objects removed or moved aside.
	notes []string
}

// takeBackPolicyPath reclaims the vendor directories of path that an
// unprivileged user created or occupied ahead of DefenseClaw (Windows
// ProgramData), and clears a planted non-regular object at path itself,
// before a target reads or writes its policy. It records what it did and
// returns the directories it created.
func takeBackPolicyPath(opts Options, path string, state *State) ([]string, error) {
	if opts.SkipTrustChecks {
		return nil, nil
	}
	result, err := reclaimPolicyDirs(opts, platformPath(opts, dirFor(opts, path)))
	for _, dir := range result.reclaimed {
		state.detail("took back %s: an unprivileged user created it before DefenseClaw; it now has DefenseClaw's owner and protected DACL", dir)
	}
	for _, note := range result.notes {
		state.detail("%s", note)
	}
	if err != nil {
		return result.created, err
	}
	note, err := clearPolicyFileName(opts, platformPath(opts, path))
	if note != "" {
		state.detail("%s", note)
	}
	return result.created, err
}

// TakeBackVendorPolicyFolder takes back dir, a vendor folder under
// ProgramData that holds DefenseClaw machine state (the Codex requirements
// folder and the hooks' runtime selectors), when a standard user created it
// or one of its ancestors below ProgramData before DefenseClaw: each gets
// DefenseClaw's owner and protected DACL, an object planted at a part of
// the path is cleared, and what such a user put inside is moved aside to a
// hidden name for an administrator to review, as for the Copilot and
// OpenCode folders (machine-policy.mdx, Windows differences). It returns
// what it did. Elsewhere, and for a missing folder, it does nothing.
func TakeBackVendorPolicyFolder(opts Options, dir string) ([]string, error) {
	if opts.SkipTrustChecks || opts.WindowsProgramData == "" {
		return nil, nil
	}
	var state State
	if _, err := takeBackPolicyPath(opts, filepath.Join(dir, ".defenseclaw-takeback"), &state); err != nil {
		return state.Details, err
	}
	displaceUntrustedEntries(opts, platformPath(opts, dir), &state)
	return state.Details, nil
}

// readPolicyFile returns (data, exists). The file must be a regular,
// non-symlink file whose ancestors an unprivileged user cannot replace.
func readPolicyFile(opts Options, path string) ([]byte, bool, error) {
	return readPolicyFileWith(opts, path, validateTrustedPolicyFile)
}

// readPolicyFileWith is readPolicyFile with the trust rule for the file
// itself supplied by the caller (the managed OpenCode plugin has its own).
func readPolicyFileWith(opts Options, path string, validate func(Options, string) error) ([]byte, bool, error) {
	path = platformPath(opts, path)
	info, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		if !opts.SkipTrustChecks {
			if err := validateTrustedAncestors(opts, path); err != nil {
				return nil, false, err
			}
		}
		return nil, false, nil
	}
	if err != nil {
		return nil, false, err
	}
	if !info.Mode().IsRegular() {
		return nil, false, fmt.Errorf("%s is not a regular file", path)
	}
	if !opts.SkipTrustChecks {
		if err := validate(opts, path); err != nil {
			return nil, false, &untrustedPolicyFileError{path: path, err: err}
		}
	}
	file, err := openNoFollow(path)
	if err != nil {
		return nil, false, err
	}
	defer file.Close()
	stat, err := file.Stat()
	if err != nil {
		return nil, false, err
	}
	if !os.SameFile(info, stat) {
		return nil, false, fmt.Errorf("%s changed while it was opened", path)
	}
	data, err := readBounded(file, policyFileLimit)
	if err != nil {
		return nil, false, err
	}
	return data, true, nil
}

// writePolicyFile atomically replaces path with data, creating missing
// parent directories administrator-owned. The file stays readable by every
// local user (agents must read machine policy) and writable only by
// administrators. It returns the directories it created, deepest last.
func writePolicyFile(opts Options, path string, data []byte) ([]string, error) {
	return writePolicyFileWith(opts, path, func(path string) error {
		return atomicWrite(opts, path, data, true)
	})
}

// writePolicyFileWith is writePolicyFile with the final atomic write
// supplied by the caller (the managed OpenCode plugin has its own
// descriptor).
func writePolicyFileWith(opts Options, path string, write func(path string) error) ([]string, error) {
	path = platformPath(opts, path)
	created, err := ensurePolicyDir(opts, dirFor(opts, path))
	if err != nil {
		return created, err
	}
	if info, err := os.Lstat(path); err == nil && !info.Mode().IsRegular() {
		return created, fmt.Errorf("%s exists and is not a regular file", path)
	}
	return created, write(path)
}

// removePolicyFile deletes path if it is a regular file.
func removePolicyFile(opts Options, path string) error {
	path = platformPath(opts, path)
	info, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	if !info.Mode().IsRegular() {
		return fmt.Errorf("refusing to remove non-regular %s", path)
	}
	return os.Remove(path)
}

// removeDirIfEmpty removes a directory DefenseClaw created, only when it
// is empty, so shared vendor parents with other content survive.
func removeDirIfEmpty(opts Options, dir string) error {
	dir = platformPath(opts, dir)
	entries, err := os.ReadDir(dir)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	if len(entries) != 0 {
		return nil
	}
	return os.Remove(dir)
}

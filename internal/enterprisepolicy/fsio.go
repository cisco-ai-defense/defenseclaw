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

	"github.com/defenseclaw/defenseclaw/internal/pathidentity"
	"github.com/defenseclaw/defenseclaw/internal/safefile"
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
	// left says which vendor folders a standalone install did not take
	// over: DefenseClaw did not create them, they hold a file DefenseClaw
	// recorded, and no standard user can delete or replace that file there
	// (Windows, g582 review 6 M2, case c).
	left []string
	// unprotected is a case c folder that does not protect the recorded file,
	// found by a removal walk (policyFolderUse.removal), which does not fail
	// closed on it: the walk stops there and takes nothing over.
	unprotected []unprotectedVendorFolder
	// reprotected are case c folders that did not protect the recorded file
	// and that the safe transaction put back to DefenseClaw's protected form.
	reprotected []ReprotectedFolder
}

// ReprotectedFolder is a vendor folder DefenseClaw did not create, holding a
// file DefenseClaw recorded, that a reconcile put back to DefenseClaw's
// protected form after proving nothing else held or changed it (E3 case c,
// GAP-0756). Before and After are the owner and access list as SDDL; the
// caller writes one HIGH connector-hook-repaired audit row from it.
type ReprotectedFolder struct {
	Connector string `json:"connector"`
	Dir       string `json:"dir"`
	File      string `json:"file"`
	// Why says what was wrong with the folder.
	Why    string `json:"why"`
	Before string `json:"before"`
	After  string `json:"after"`
}

// policyFolderUse is how the vendor uses the folder that holds a policy
// file, and what the walk is for.
type policyFolderUse struct {
	// siblings says what else the vendor loads from that folder besides the
	// policy file itself, for example "GitHub Copilot loads every *.json file
	// in it", or "" when the vendor reads only that one file name. In case c
	// such a folder fails closed when standard users may add files to it: a
	// file they add would apply beside or instead of DefenseClaw's (g582
	// review 7 M1).
	siblings string
	// removal is an uninstall walk: a case c folder that does not protect the
	// recorded file is reported in policyTakeBack.unprotected instead of
	// failing, so the removal goes on without taking the folder over (g582
	// review 7 S1).
	removal bool
}

// Folder uses of the Go-owned Windows targets whose vendor loads more than
// DefenseClaw's file from its folder.
var (
	copilotFolderUse  = policyFolderUse{siblings: "GitHub Copilot loads every *.json file in it for every user"}
	opencodeFolderUse = policyFolderUse{siblings: "OpenCode loads opencode.json and opencode.jsonc from it for every user, and prefers opencode.jsonc"}
)

// unprotectedVendorFolder is a vendor folder DefenseClaw did not create that
// holds a file DefenseClaw recorded and does not protect that file (case c).
type unprotectedVendorFolder struct {
	// dir is the folder, reason why it does not protect the file, and fix
	// the administrator's commands, in order.
	dir, reason, fix string
}

// takeBackPolicyPath reclaims the vendor directories of path that an
// unprivileged user created or occupied ahead of DefenseClaw (Windows
// ProgramData), and clears a planted non-regular object at path itself,
// before a target reads or writes its policy. It records what it did and
// returns the directories it created.
func takeBackPolicyPath(opts Options, path string, state *State) ([]string, error) {
	created, _, err := takeBackPolicyPathFor(opts, path, policyFolderUse{}, state)
	return created, err
}

// takeBackPolicyPathFor is takeBackPolicyPath for a folder the vendor uses
// as use says. It also returns the case c folders a removal walk found
// unprotected; the path itself is then left alone.
func takeBackPolicyPathFor(opts Options, path string, use policyFolderUse, state *State) ([]string, []unprotectedVendorFolder, error) {
	if opts.SkipTrustChecks {
		return nil, nil, nil
	}
	result, err := reclaimPolicyDirsFor(opts, platformPath(opts, dirFor(opts, path)), use)
	for _, dir := range result.reclaimed {
		state.detail("took back %s: an unprivileged user created it before DefenseClaw; it now has DefenseClaw's owner and protected DACL", dir)
	}
	for _, note := range result.notes {
		state.detail("%s", note)
	}
	for _, note := range result.left {
		state.detail("%s", note)
	}
	for _, folder := range result.reprotected {
		folder.Connector = state.Connector
		state.detail("re-protected %s: %s; nothing held it open, DefenseClaw's recorded files in it were as DefenseClaw wrote them and it held "+
			"nothing else DefenseClaw did not account for, so it now has DefenseClaw's owner and protected access list", folder.Dir, folder.Why)
		state.Reprotected = append(state.Reprotected, folder)
		state.Changed = true
	}
	if err != nil || len(result.unprotected) != 0 {
		return result.created, result.unprotected, err
	}
	note, err := clearPolicyFileName(opts, platformPath(opts, path))
	if note != "" {
		state.detail("%s", note)
	}
	return result.created, nil, err
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
	var data []byte
	var seen bool
	read := func() error {
		var err error
		data, err = readPolicyFileOnce(opts, path, validate, &seen)
		return err
	}
	var err error
	if opts.goos() == "windows" {
		err = safefile.RetryTransientRead(read)
		if seen && safefile.IsTransientReadError(err) {
			err = safefile.RetryPublishedRead(read)
		}
	} else {
		err = read()
	}
	var untrusted *untrustedPolicyFileError
	if errors.As(err, &untrusted) {
		return nil, false, err
	}
	// A checked policy that disappears before open is an uncertain read,
	// not evidence that no policy was installed.
	if errors.Is(err, os.ErrNotExist) && !seen {
		forgetPolicyFileRead(path)
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
	return data, true, nil
}

// Each attempt rechecks the file's name, protection, and opened identity.
// A publication change is returned to the caller for a whole-read retry.
func readPolicyFileOnce(opts Options, path string, validate func(Options, string) error, seen *bool) ([]byte, error) {
	info, err := pathidentity.LstatPinned(path)
	if err != nil {
		return nil, err
	}
	*seen = true
	if !info.Mode().IsRegular() {
		return nil, fmt.Errorf("%s is not a regular file", path)
	}
	if !opts.SkipTrustChecks {
		if err := validate(opts, path); err != nil {
			return nil, &untrustedPolicyFileError{path: path, err: err}
		}
	}
	file, err := openNoFollow(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	stat, err := file.Stat()
	if err != nil {
		return nil, err
	}
	if !os.SameFile(info, stat) {
		return nil, fmt.Errorf("%s changed while it was opened: %w", path, safefile.ErrReadIdentityChanged)
	}
	data, err := readBounded(file, policyFileLimit)
	if err != nil {
		return nil, err
	}
	if opts.goos() == "windows" {
		final, err := pathidentity.LstatPinned(path)
		if err != nil {
			return nil, err
		}
		if !final.Mode().IsRegular() {
			return nil, fmt.Errorf("%s is not a regular file", path)
		}
		if !os.SameFile(stat, final) || final.Size() != int64(len(data)) {
			return nil, fmt.Errorf("%s changed while it was read: %w", path, safefile.ErrReadIdentityChanged)
		}
	}
	notePolicyFileRead(path, file, data)
	return data, nil
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

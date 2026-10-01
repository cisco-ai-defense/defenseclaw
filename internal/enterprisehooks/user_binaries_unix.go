// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package enterprisehooks

import (
	"bufio"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
)

// The per-user install (scripts/install.sh) puts these in ~/.local/bin.
var (
	// userBinaryFiles are the Go binaries it copies there. The names are
	// DefenseClaw's own, so a regular file of the account's goes.
	userBinaryFiles = []string{"defenseclaw-gateway", "defenseclaw-acp"}
	// userBinaryLinks are the launchers it links to the per-user venv in
	// ~/.defenseclaw/.venv (plus the console scripts a source install linked
	// the same way). Only a link into the purged data directory goes: a
	// pip-installed skill-scanner or litellm of the account's own stays.
	userBinaryLinks = []string{
		"defenseclaw",
		"skill-scanner",
		"skill-scanner-api",
		"skill-scanner-pre-commit",
		"mcp-scanner",
		"mcp-scanner-api",
		"litellm",
	}
	// userBinaryBookkeeping are the installer's marker and custody files.
	userBinaryBookkeeping = []string{".defenseclaw-source-root", ".defenseclaw-install-custody"}
	// userUVNames are the uv files the installer may have put there; the
	// record lists each one's digest, and only an unchanged one goes.
	userUVNames = map[string]bool{"uv": true, "uvx": true}
)

const (
	userUVRecord         = "defenseclaw-uv.sha256"
	userUVRecordMaxBytes = 4096
)

// RemoveUserBinaries removes what the per-user install put in
// <home>/.local/bin for the account uid: the defenseclaw-gateway and
// defenseclaw-acp binaries, the launcher links into dataDir (which the purge
// of dataDir leaves dangling), the uv files that still match the installer's
// record, the record itself, and the installer's bookkeeping. It also removes
// the custody folder pre-1.0 installers left in the home. Only entries the
// account owns go; ~/.local/bin itself stays, since other tools use it. The
// install edits no shell profile, so no PATH entry is left to remove. It
// returns the paths it removed. Run it as the account.
func RemoveUserBinaries(home, dataDir string, uid int) ([]string, error) {
	binDir := filepath.Join(home, ".local", "bin")
	var removed []string
	var errs []error
	remove := func(path string) {
		if err := os.RemoveAll(path); err != nil {
			errs = append(errs, err)
			return
		}
		removed = append(removed, path)
	}
	owned := func(path string) bool {
		ok, _ := fileOwnerMatches(path, uid)
		return ok
	}

	if info, err := os.Stat(binDir); err == nil && info.IsDir() && owned(binDir) {
		for _, name := range userBinaryFiles {
			path := filepath.Join(binDir, name)
			info, err := os.Lstat(path)
			if err != nil || !owned(path) {
				continue
			}
			if info.Mode().IsRegular() || (info.Mode()&os.ModeSymlink != 0 && linkPointsInto(path, dataDir)) {
				remove(path)
			}
		}
		for _, name := range userBinaryLinks {
			path := filepath.Join(binDir, name)
			info, err := os.Lstat(path)
			if err != nil || info.Mode()&os.ModeSymlink == 0 || !owned(path) {
				continue
			}
			if linkPointsInto(path, dataDir) {
				remove(path)
			}
		}
		for _, path := range installerUVFiles(binDir, uid) {
			remove(path)
		}
		for _, name := range userBinaryBookkeeping {
			path := filepath.Join(binDir, name)
			if _, err := os.Lstat(path); err == nil && owned(path) {
				remove(path)
			}
		}
	} else if err != nil && !errors.Is(err, os.ErrNotExist) {
		errs = append(errs, err)
	}

	custody := filepath.Join(home, ".defenseclaw-install-custody")
	if _, err := os.Lstat(custody); err == nil && owned(custody) {
		remove(custody)
	}
	if len(errs) > 0 {
		return removed, fmt.Errorf("enterprise hooks: remove the per-user binaries: %w", errors.Join(errs...))
	}
	return removed, nil
}

// linkPointsInto reports whether the link at path names a path inside dir,
// read without following it (the target may be gone).
func linkPointsInto(path, dir string) bool {
	target, err := os.Readlink(path)
	if err != nil {
		return false
	}
	if !filepath.IsAbs(target) {
		target = filepath.Join(filepath.Dir(path), target)
	}
	rel, err := filepath.Rel(filepath.Clean(dir), filepath.Clean(target))
	return err == nil && rel != "." && rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator))
}

// installerUVFiles returns the uv files in binDir that still match the
// digest the installer recorded, then the record itself. A uv updated or
// replaced since then belongs to the account and stays.
func installerUVFiles(binDir string, uid int) []string {
	record := filepath.Join(binDir, userUVRecord)
	info, err := os.Lstat(record)
	if err != nil || !info.Mode().IsRegular() || info.Size() > userUVRecordMaxBytes {
		return nil
	}
	if ok, _ := fileOwnerMatches(record, uid); !ok {
		return nil
	}
	file, err := os.Open(record)
	if err != nil {
		return nil
	}
	defer file.Close()
	var paths []string
	scanner := bufio.NewScanner(io.LimitReader(file, userUVRecordMaxBytes))
	for scanner.Scan() {
		digest, name, ok := strings.Cut(strings.TrimSpace(scanner.Text()), "  ")
		if !ok || !userUVNames[name] {
			continue
		}
		path := filepath.Join(binDir, name)
		if info, err := os.Lstat(path); err != nil || !info.Mode().IsRegular() {
			continue
		}
		if owned, _ := fileOwnerMatches(path, uid); !owned {
			continue
		}
		if sum, err := sha256File(path); err == nil && strings.EqualFold(sum, digest) {
			paths = append(paths, path)
		}
	}
	return append(paths, record)
}

func sha256File(path string) (string, error) {
	file, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer file.Close()
	digest := sha256.New()
	if _, err := io.Copy(digest, file); err != nil {
		return "", err
	}
	return hex.EncodeToString(digest.Sum(nil)), nil
}

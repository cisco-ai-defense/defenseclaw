// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// SPDX-License-Identifier: Apache-2.0

package winpath

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"strings"
	"sync"
	"time"
)

// Versioned managed hook images (GAP-0751). A standalone managed Windows
// install keeps two kinds of hook image under <InstallRoot>\bin:
//
//   - bin\defenseclaw-hook.exe (and bin\defenseclaw-hook-guard.exe), the
//     transition image. Setup replaces it in place during an upgrade, before
//     it stops the services (the GAP-0993 closed guard), exactly as 1.0.9
//     did. Agent hook configs written by 1.0.9 and earlier name it.
//   - bin\hooks\<d16>\defenseclaw-hook.exe (and the guard beside it), the
//     launch image every hook config names from 1.0.10 on. d16 is the first
//     16 lowercase hex digits of the hook image's SHA-256. Setup stages a new
//     folder for a new release, starts the image once, and the configs switch
//     to it afterwards; nothing ever replaces the image an agent starts.
//
// The base names never change, so checks that look only at the file name
// (the hookexec wrapper detection, the Authenticode pin by name) are the same
// for both kinds. These helpers are pure string code on Windows paths so they
// run in every platform's tests.
const (
	EnterpriseHookImageName      = "defenseclaw-hook.exe"
	EnterpriseHookGuardImageName = "defenseclaw-hook-guard.exe"
	EnterpriseHookImagesDirName  = "hooks"
	enterpriseHookImageDigestLen = 16
)

// EnterpriseHookImageLocation is a parsed managed hook image path.
type EnterpriseHookImageLocation struct {
	// Bin is <InstallRoot>\bin.
	Bin string
	// Name is EnterpriseHookImageName or EnterpriseHookGuardImageName, as
	// spelled in bin (the comparison is case-insensitive).
	Name string
	// Digest is the launch folder name in lowercase (16 hex digits), empty
	// for the transition image.
	Digest string
}

// Versioned reports a launch image under bin\hooks.
func (l EnterpriseHookImageLocation) Versioned() bool { return l.Digest != "" }

// cleanWindowsPath trims, turns forward slashes into backslashes, collapses
// repeated separators and drops a trailing one (but keeps "C:\").
func cleanWindowsPath(value string) string {
	value = strings.ReplaceAll(strings.TrimSpace(value), "/", `\`)
	for strings.Contains(value, `\\`) {
		value = strings.ReplaceAll(value, `\\`, `\`)
	}
	if len(value) > 3 {
		value = strings.TrimRight(value, `\`)
	}
	return value
}

func splitWindowsParent(value string) (string, string) {
	index := strings.LastIndex(value, `\`)
	if index < 0 {
		return "", value
	}
	parent := value[:index]
	if len(parent) == 2 && parent[1] == ':' {
		parent += `\`
	}
	return parent, value[index+1:]
}

func joinWindowsPath(parent string, names ...string) string {
	out := strings.TrimRight(cleanWindowsPath(parent), `\`)
	for _, name := range names {
		out += `\` + name
	}
	return out
}

// IsEnterpriseHookImageDirName reports a launch folder name: exactly 16 hex
// digits. Setup creates it in lowercase; Windows names are case-insensitive,
// so a path that spells it in another case names the same folder.
func IsEnterpriseHookImageDirName(name string) bool {
	if len(name) != enterpriseHookImageDigestLen {
		return false
	}
	for _, r := range name {
		if !(r >= '0' && r <= '9') && !(r >= 'a' && r <= 'f') && !(r >= 'A' && r <= 'F') {
			return false
		}
	}
	return true
}

// EnterpriseHookImageDigest is the launch folder name of an image whose
// SHA-256 is sha256Hex (64 hex digits, any case).
func EnterpriseHookImageDigest(sha256Hex string) (string, error) {
	sha256Hex = strings.ToLower(strings.TrimSpace(sha256Hex))
	if len(sha256Hex) != 64 {
		return "", fmt.Errorf("hook image digest is not a SHA-256: %q", sha256Hex)
	}
	if _, err := hex.DecodeString(sha256Hex); err != nil {
		return "", fmt.Errorf("hook image digest is not a SHA-256: %q", sha256Hex)
	}
	return sha256Hex[:enterpriseHookImageDigestLen], nil
}

// EnterpriseHookImagesRoot is <bin>\hooks.
func EnterpriseHookImagesRoot(bin string) string {
	return joinWindowsPath(bin, EnterpriseHookImagesDirName)
}

// EnterpriseHookImageDir is <bin>\hooks\<d16> for an image SHA-256.
func EnterpriseHookImageDir(bin, sha256Hex string) (string, error) {
	digest, err := EnterpriseHookImageDigest(sha256Hex)
	if err != nil {
		return "", err
	}
	return joinWindowsPath(bin, EnterpriseHookImagesDirName, digest), nil
}

// ParseEnterpriseHookImagePath parses an absolute drive path of the form
// <bin>\<name> or <bin>\hooks\<16 hex>\<name>, name being the hook or the hook
// guard image. It does not look at the file system and does not check that
// bin belongs to a managed install root: callers keep their own root check.
func ParseEnterpriseHookImagePath(path string) (EnterpriseHookImageLocation, bool) {
	path = cleanWindowsPath(path)
	if !windowsAbsoluteDrivePath(path) {
		return EnterpriseHookImageLocation{}, false
	}
	dir, name := splitWindowsParent(path)
	if !strings.EqualFold(name, EnterpriseHookImageName) && !strings.EqualFold(name, EnterpriseHookGuardImageName) {
		return EnterpriseHookImageLocation{}, false
	}
	if strings.EqualFold(lastWindowsName(dir), "bin") && !isDriveRoot(dir) {
		return EnterpriseHookImageLocation{Bin: dir, Name: name}, true
	}
	hooks, digest := splitWindowsParent(dir)
	if !IsEnterpriseHookImageDirName(digest) || !strings.EqualFold(lastWindowsName(hooks), EnterpriseHookImagesDirName) {
		return EnterpriseHookImageLocation{}, false
	}
	bin, _ := splitWindowsParent(hooks)
	if !strings.EqualFold(lastWindowsName(bin), "bin") || isDriveRoot(bin) {
		return EnterpriseHookImageLocation{}, false
	}
	return EnterpriseHookImageLocation{Bin: bin, Name: name, Digest: strings.ToLower(digest)}, true
}

func lastWindowsName(value string) string {
	_, name := splitWindowsParent(value)
	return name
}

func isDriveRoot(value string) bool {
	return len(value) <= 3 && len(value) >= 2 && value[1] == ':'
}

// SameEnterpriseHookImageFamily reports two paths that are the same image
// kind (hook or guard) of the same bin directory, transition or launch image
// in either order. A hook process started from an earlier launch image (an
// agent session that read its hook command before an upgrade) is the same
// managed hook as the current one; only its bytes are older.
func SameEnterpriseHookImageFamily(a, b string) bool {
	left, ok := ParseEnterpriseHookImagePath(a)
	if !ok {
		return false
	}
	right, ok := ParseEnterpriseHookImagePath(b)
	if !ok {
		return false
	}
	return strings.EqualFold(left.Name, right.Name) && strings.EqualFold(left.Bin, right.Bin)
}

// EnterpriseHookImageBin returns <bin> for a managed hook or guard image
// path (transition or launch image), "" otherwise. Code that finds a sibling
// of the hook (the gateway, the CLI) must look in this bin, not in the
// hook's own folder.
func EnterpriseHookImageBin(path string) string {
	location, ok := ParseEnterpriseHookImagePath(path)
	if !ok {
		return ""
	}
	return location.Bin
}

// EnterpriseHookImageState says which hook image ResolveEnterpriseHookImage
// chose and why.
type EnterpriseHookImageState string

const (
	// EnterpriseHookImageStaged: bin\hooks holds the exact launch set of the
	// transition image's digest; agent configs name it.
	EnterpriseHookImageStaged EnterpriseHookImageState = "staged"
	// EnterpriseHookImageLegacyLayout: there is no bin\hooks (a 1.0.9
	// layout before its first 1.0.10 upgrade, Secure Client, a development
	// tree); the transition image is the launch image.
	EnterpriseHookImageLegacyLayout EnterpriseHookImageState = "legacy_layout"
	// EnterpriseHookImageNotStaged: bin\hooks exists but has no exact launch
	// set for the transition image's digest. The transition image is
	// returned, which is this release's own bytes and always starts, and
	// verify reports the state (hook_image_not_staged).
	EnterpriseHookImageNotStaged EnterpriseHookImageState = "not_staged"
)

// EnterpriseHookImage is the resolved launch set of a managed bin.
type EnterpriseHookImage struct {
	Bin string
	// Hook is the path agent hook configs name.
	Hook string
	// Guard is the hook guard beside Hook, or "" when the layout has no
	// transition guard (Secure Client).
	Guard string
	// SHA256 is the transition image's digest ("" when it cannot be read).
	SHA256 string
	State  EnterpriseHookImageState
	// Problem says why State is not_staged.
	Problem string
}

// EnterpriseHookImageFS is the file access ResolveEnterpriseHookImageWith
// needs. Lstat must not follow a final link. FileSHA256 returns the
// lowercase SHA-256 of a regular file.
type EnterpriseHookImageFS interface {
	Lstat(name string) (fs.FileInfo, error)
	FileSHA256(name string) (string, error)
}

// ResolveEnterpriseHookImage resolves bin's launch set on the real file
// system (digests memoized per file object; see hookImageDigestMemo).
func ResolveEnterpriseHookImage(bin string) EnterpriseHookImage {
	return ResolveEnterpriseHookImageWith(osHookImageFS{}, bin)
}

// ResolveEnterpriseHookImageWith returns the hook image agent configs must
// name for bin. It never fails: when the launch set is not staged and exact
// it returns the transition image (Setup installed it and the guardian keeps
// it at the recorded digest), so a writer always names an image that starts.
// Setup fails closed before that can matter: it refuses an upgrade whose new
// launch image does not start (hook_image_start_failed), and every config
// keeps the old image.
func ResolveEnterpriseHookImageWith(fsys EnterpriseHookImageFS, bin string) EnterpriseHookImage {
	bin = cleanWindowsPath(bin)
	transitionHook := joinWindowsPath(bin, EnterpriseHookImageName)
	transitionGuard := joinWindowsPath(bin, EnterpriseHookGuardImageName)
	out := EnterpriseHookImage{Bin: bin, Hook: transitionHook, State: EnterpriseHookImageLegacyLayout}
	guardExists := false
	if info, err := fsys.Lstat(transitionGuard); err == nil && info.Mode().IsRegular() {
		guardExists = true
		out.Guard = transitionGuard
	}
	notStaged := func(format string, args ...any) EnterpriseHookImage {
		out.State = EnterpriseHookImageNotStaged
		out.Problem = fmt.Sprintf(format, args...)
		return out
	}
	root := EnterpriseHookImagesRoot(bin)
	info, err := fsys.Lstat(root)
	if errors.Is(err, fs.ErrNotExist) {
		if digest, hashErr := fsys.FileSHA256(transitionHook); hashErr == nil {
			out.SHA256 = digest
		}
		return out
	}
	if err != nil {
		return notStaged("inspect %s: %v", root, err)
	}
	if !info.IsDir() || info.Mode()&fs.ModeSymlink != 0 || info.Mode()&fs.ModeIrregular != 0 {
		return notStaged("%s is not a plain folder", root)
	}
	digest, err := fsys.FileSHA256(transitionHook)
	if err != nil {
		return notStaged("read the transition hook %s: %v", transitionHook, err)
	}
	out.SHA256 = digest
	dir, err := EnterpriseHookImageDir(bin, digest)
	if err != nil {
		return notStaged("%v", err)
	}
	if info, err := fsys.Lstat(dir); err != nil || !info.IsDir() || info.Mode()&(fs.ModeSymlink|fs.ModeIrregular) != 0 {
		return notStaged("no launch folder %s for the installed hook", dir)
	}
	hook := joinWindowsPath(dir, EnterpriseHookImageName)
	if problem := exactHookImage(fsys, hook, digest); problem != "" {
		return notStaged("%s", problem)
	}
	guard := ""
	if guardExists {
		guardDigest, err := fsys.FileSHA256(transitionGuard)
		if err != nil {
			return notStaged("read the transition hook guard %s: %v", transitionGuard, err)
		}
		guard = joinWindowsPath(dir, EnterpriseHookGuardImageName)
		if problem := exactHookImage(fsys, guard, guardDigest); problem != "" {
			return notStaged("%s", problem)
		}
	}
	out.Hook = hook
	out.Guard = guard
	out.State = EnterpriseHookImageStaged
	return out
}

func exactHookImage(fsys EnterpriseHookImageFS, path, want string) string {
	info, err := fsys.Lstat(path)
	if err != nil {
		return fmt.Sprintf("launch image %s: %v", path, err)
	}
	if !info.Mode().IsRegular() || info.Size() == 0 {
		return fmt.Sprintf("launch image %s is not a regular file", path)
	}
	have, err := fsys.FileSHA256(path)
	if err != nil {
		return fmt.Sprintf("read launch image %s: %v", path, err)
	}
	if !strings.EqualFold(have, want) {
		return fmt.Sprintf("launch image %s has sha256 %s, not the installed %s", path, have, want)
	}
	return ""
}

type osHookImageFS struct{}

func (osHookImageFS) Lstat(name string) (fs.FileInfo, error) { return os.Lstat(name) }

func (osHookImageFS) FileSHA256(name string) (string, error) {
	return defaultHookImageDigestMemo.sha256(name, os.Lstat, OpenReadShared)
}

// hookImageDigestMemo keeps the last digest of each image path while the
// same file object (os.SameFile), size and modification time are there.
// The guardian resolves the launch set for every target of every reconcile,
// and an image is about 130 MB; a new object, a resize or a write that moves
// the modification time is hashed again. The guardian checks the bytes of the
// current images against the recorded digest on its own schedule.
type hookImageDigestMemo struct {
	mu      sync.Mutex
	entries map[string]hookImageDigestEntry
}

type hookImageDigestEntry struct {
	info    fs.FileInfo
	size    int64
	modTime time.Time
	digest  string
}

var defaultHookImageDigestMemo = &hookImageDigestMemo{}

func (m *hookImageDigestMemo) sha256(
	name string,
	lstat func(string) (fs.FileInfo, error),
	open func(string) (*os.File, error),
) (string, error) {
	before, err := lstat(name)
	if err != nil {
		return "", err
	}
	if !before.Mode().IsRegular() {
		return "", fmt.Errorf("%s is not a regular file", name)
	}
	key := strings.ToLower(cleanWindowsPath(name))
	m.mu.Lock()
	entry, ok := m.entries[key]
	m.mu.Unlock()
	if ok && entry.size == before.Size() && entry.modTime.Equal(before.ModTime()) && os.SameFile(entry.info, before) {
		return entry.digest, nil
	}
	file, err := open(name)
	if err != nil {
		return "", err
	}
	hash := sha256.New()
	_, copyErr := io.Copy(hash, file)
	closeErr := file.Close()
	if copyErr != nil {
		return "", copyErr
	}
	if closeErr != nil {
		return "", closeErr
	}
	digest := hex.EncodeToString(hash.Sum(nil))
	after, err := lstat(name)
	if err != nil {
		return "", err
	}
	if after.Size() != before.Size() || !after.ModTime().Equal(before.ModTime()) || !os.SameFile(before, after) {
		return "", fmt.Errorf("%s changed while it was read", name)
	}
	m.mu.Lock()
	if m.entries == nil {
		m.entries = make(map[string]hookImageDigestEntry)
	}
	m.entries[key] = hookImageDigestEntry{info: after, size: after.Size(), modTime: after.ModTime(), digest: digest}
	m.mu.Unlock()
	return digest, nil
}

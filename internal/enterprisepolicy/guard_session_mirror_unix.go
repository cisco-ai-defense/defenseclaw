// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package enterprisepolicy

import (
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"
)

// foreignHookCleanMirrorTrustTop is the highest ancestor of the root whose
// owner and mode are checked ("" checks every ancestor up to /); tests set
// it to their temporary folder.
var foreignHookCleanMirrorTrustTop = ""

// WriteForeignHookCleanMirrors publishes the entries of key for the account
// identity under root (the gateway, holding the account's exchange lock,
// after an allow). A missing root, an identity that is not a uid, and any
// write failure publish nothing: the caller removes what may be left.
func WriteForeignHookCleanMirrors(root, identity string, key SessionKey, state string, now time.Time) error {
	uid, ok := posixAccountUID(identity)
	if !ok || !key.valid() || !filepath.IsAbs(root) {
		return errors.New("no clean-session entry for this caller")
	}
	if err := cleanMirrorOwnDir(root, false); err != nil {
		return err
	}
	dir := filepath.Join(root, uid)
	if err := cleanMirrorOwnDir(dir, true); err != nil {
		return err
	}
	keys := foreignHookCleanMirrorKeys(key)
	fresh := true
	for _, kindID := range keys {
		info, err := os.Lstat(foreignHookCleanMirrorPath(root, uid, key.Connector, kindID[0], kindID[1]))
		if err != nil || !info.Mode().IsRegular() || now.Sub(info.ModTime()) > foreignHookCleanMirrorRefresh || info.ModTime().After(now) {
			fresh = false
		}
	}
	if fresh {
		// Written moments ago for this key: an entry's content changes only
		// in its times.
		return nil
	}
	if err := pruneCleanMirrorDir(dir, now, len(keys)); err != nil {
		return err
	}
	for _, kindID := range keys {
		data, err := encodeForeignHookCleanMirror(uid, key, kindID[0], kindID[1], state, now)
		if err != nil {
			return err
		}
		if err := writeCleanMirrorFile(dir, foreignHookCleanMirrorPath(root, uid, key.Connector, kindID[0], kindID[1]), data); err != nil {
			return err
		}
	}
	return nil
}

// foreignHookCleanMirrorRefresh is how old an entry may be before an allow
// writes it again, and foreignHookCleanMirrorDirLimit how many entries one
// account keeps.
const (
	foreignHookCleanMirrorRefresh  = 5 * time.Minute
	foreignHookCleanMirrorDirLimit = 512
)

// pruneCleanMirrorDir removes the account's expired entries and leftover
// temporary files when the folder is near its limit, and refuses a write
// that would take it past the limit (the call then gets no entry).
func pruneCleanMirrorDir(dir string, now time.Time, adding int) error {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return err
	}
	if len(entries)+adding <= foreignHookCleanMirrorDirLimit {
		return nil
	}
	kept := 0
	for _, entry := range entries {
		info, err := entry.Info()
		if err == nil && now.Sub(info.ModTime()) <= ForeignHookCleanMirrorTTL && !strings.HasPrefix(entry.Name(), ".clean-") {
			kept++
			continue
		}
		if err := os.Remove(filepath.Join(dir, entry.Name())); err != nil && !errors.Is(err, fs.ErrNotExist) {
			kept++
		}
	}
	if kept+adding > foreignHookCleanMirrorDirLimit {
		return errors.New("the account has too many clean-session entries")
	}
	return nil
}

// cleanMirrorOwnDir checks that path is a real folder this process (or
// root) owns, not writable by others; with create it makes a missing one
// 0711 and resets its mode.
func cleanMirrorOwnDir(path string, create bool) error {
	info, err := os.Lstat(path)
	if create && errors.Is(err, fs.ErrNotExist) {
		if err := os.Mkdir(path, 0o711); err != nil && !errors.Is(err, fs.ErrExist) {
			return err
		}
		info, err = os.Lstat(path)
	}
	if err != nil {
		return err
	}
	if !info.IsDir() || info.Mode()&fs.ModeSymlink != 0 {
		return fmt.Errorf("%s is not a folder", path)
	}
	owner, ok := cleanMirrorOwner(info)
	if !ok || (owner != 0 && owner != os.Geteuid()) {
		return fmt.Errorf("%s is not owned by this service", path)
	}
	if create && info.Mode().Perm() != 0o711 {
		if err := os.Chmod(path, 0o711); err != nil {
			return err
		}
	} else if info.Mode().Perm()&0o022 != 0 {
		return fmt.Errorf("%s is writable by other accounts", path)
	}
	return nil
}

func writeCleanMirrorFile(dir, path string, data []byte) error {
	temp, err := os.CreateTemp(dir, ".clean-*")
	if err != nil {
		return err
	}
	name := temp.Name()
	done := false
	defer func() {
		if !done {
			_ = temp.Close()
			_ = os.Remove(name)
		}
	}()
	if err := temp.Chmod(0o644); err != nil {
		return err
	}
	// No fsync: an entry is of use only until the agent process ends, and
	// every process ends at a reboot.
	if _, err := temp.Write(data); err != nil {
		return err
	}
	if err := temp.Close(); err != nil {
		return err
	}
	if err := os.Rename(name, path); err != nil {
		return err
	}
	done = true
	return nil
}

// DropForeignHookCleanMirrors removes the entries of key for the account
// identity (the gateway, before a denial of either key).
func DropForeignHookCleanMirrors(root, identity string, key SessionKey) error {
	uid, ok := posixAccountUID(identity)
	if !ok || !filepath.IsAbs(root) {
		return nil
	}
	var errs []error
	for _, kindID := range foreignHookCleanMirrorKeys(key) {
		if err := os.Remove(foreignHookCleanMirrorPath(root, uid, key.Connector, kindID[0], kindID[1])); err != nil && !errors.Is(err, fs.ErrNotExist) {
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
}

// DropForeignHookCleanMirrorsForAccount removes every entry of the account
// identity, or of every account when identity is not a uid (the hook
// guardian, before it records a removal). A missing root has none.
func DropForeignHookCleanMirrorsForAccount(root, identity string) error {
	if !filepath.IsAbs(root) {
		return nil
	}
	if _, err := os.Lstat(root); errors.Is(err, fs.ErrNotExist) {
		return nil
	} else if err != nil {
		return err
	}
	if uid, ok := posixAccountUID(identity); ok {
		return os.RemoveAll(filepath.Join(root, uid))
	}
	entries, err := os.ReadDir(root)
	if err != nil {
		return err
	}
	var errs []error
	for _, entry := range entries {
		if err := os.RemoveAll(filepath.Join(root, entry.Name())); err != nil {
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
}

// ForeignHookCleanServiceUID returns the owner of the standalone data
// directory, the gateway's service account.
func ForeignHookCleanServiceUID(dataDir string) (int, error) {
	info, err := os.Lstat(dataDir)
	if err != nil {
		return -1, err
	}
	if !info.IsDir() || info.Mode()&fs.ModeSymlink != 0 {
		return -1, errors.New("the data directory is not a folder")
	}
	owner, ok := cleanMirrorOwner(info)
	if !ok {
		return -1, errors.New("the data directory has no owner")
	}
	return owner, nil
}

// CheckForeignHookCleanMirror returns nil only when the entry of the agent
// process check.Key.Process, and the entry of its session check.Key.Session
// when the call names one, are present and trusted: each entry, its account
// folder and the root are owned by root or the service account and not
// writable by other accounts, no path element is a symbolic link, every
// ancestor of the root is owned by root and not writable by other accounts,
// the account folder is the caller's uid, and the entry decodes strictly,
// names this key, account and agent process, and has not expired.
func CheckForeignHookCleanMirror(check ForeignHookCleanMirrorCheck) error {
	root := filepath.Clean(check.Root)
	if !filepath.IsAbs(check.Root) || check.Key.Process == "" || !check.Key.valid() || check.CallerUID < 0 {
		return errors.New("no clean-session entry for this call")
	}
	trusted := func(owner int) bool { return owner == 0 || (check.ServiceUID >= 0 && owner == check.ServiceUID) }
	for dir := filepath.Dir(root); ; dir = filepath.Dir(dir) {
		if foreignHookCleanMirrorTrustTop != "" && dir == filepath.Clean(foreignHookCleanMirrorTrustTop) {
			break
		}
		if err := cleanMirrorTrustedDir(dir, func(owner int) bool { return owner == 0 }); err != nil {
			return err
		}
		if dir == filepath.Dir(dir) {
			break
		}
	}
	uid := strconv.Itoa(check.CallerUID)
	for _, dir := range []string{root, filepath.Join(root, uid)} {
		if err := cleanMirrorTrustedDir(dir, trusted); err != nil {
			return err
		}
	}
	// The process entry says the agent process is clean; the session entry
	// that this process's session is (a clean process that resumes a blocked
	// session stays denied by the gateway).
	for _, kindID := range foreignHookCleanMirrorKeys(check.Key) {
		path := foreignHookCleanMirrorPath(root, uid, check.Key.Connector, kindID[0], kindID[1])
		if err := checkCleanMirrorFile(path, kindID[0], trusted, check); err != nil {
			return err
		}
	}
	return nil
}

func checkCleanMirrorFile(path, kind string, trusted func(int) bool, check ForeignHookCleanMirrorCheck) error {
	before, err := os.Lstat(path)
	if err != nil {
		return err
	}
	file, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	if err != nil {
		return err
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil {
		return err
	}
	owner, ok := cleanMirrorOwner(info)
	switch {
	case !info.Mode().IsRegular() || !os.SameFile(before, info):
		return errors.New("clean-session entry is not a regular file")
	case !ok || !trusted(owner):
		return errors.New("clean-session entry is not owned by the service")
	case info.Mode().Perm()&0o022 != 0:
		return errors.New("clean-session entry is writable by other accounts")
	case cleanMirrorLinks(info) != 1:
		return errors.New("clean-session entry has other links")
	case info.Size() > foreignHookCleanMirrorLimit:
		return errors.New("clean-session entry too large")
	}
	data, err := io.ReadAll(io.LimitReader(file, foreignHookCleanMirrorLimit+1))
	if err != nil {
		return err
	}
	return decodeForeignHookCleanMirror(data, kind, check)
}

func cleanMirrorTrustedDir(path string, trusted func(int) bool) error {
	info, err := os.Lstat(path)
	if err != nil {
		return err
	}
	owner, ok := cleanMirrorOwner(info)
	switch {
	case !info.IsDir() || info.Mode()&fs.ModeSymlink != 0:
		return fmt.Errorf("%s is not a folder", path)
	case !ok || !trusted(owner):
		return fmt.Errorf("%s is not owned by a trusted account", path)
	case info.Mode().Perm()&0o022 != 0:
		return fmt.Errorf("%s is writable by other accounts", path)
	}
	return nil
}

func cleanMirrorOwner(info fs.FileInfo) (int, bool) {
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return -1, false
	}
	return int(stat.Uid), true
}

func cleanMirrorLinks(info fs.FileInfo) uint64 {
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return 0
	}
	return uint64(stat.Nlink)
}

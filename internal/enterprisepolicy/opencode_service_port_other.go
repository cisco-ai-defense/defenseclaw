//go:build !windows

// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package enterprisepolicy

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"syscall"

	"github.com/defenseclaw/defenseclaw/internal/gateway/connector"
)

// openCodeMaxLinks bounds the links the path walk follows.
const openCodeMaxLinks = 40

// openCodeOwnerPrivateGroup is the private-group proof (tests replace it).
var openCodeOwnerPrivateGroup = connector.OwnerPrivateGroup

func writeOpenCodeServiceConfig(_ string, path string, data []byte) error {
	return writePrivateUserFile(path, data)
}

// checkOpenCodeServiceConfigFolders walks the whole path to service.json, link
// by link, and refuses it when another account could replace what the walk
// passes through (REVIEW-2 MF1b). It runs before a port that already matches is
// accepted and before a write, so a matching file is no safer than a differing
// one. Every folder the walk stands in (the folders on the way, the folder
// holding each link, the folders a link leads through) must be owned by this
// account or root and closed to other accounts: no other-write bit, and no
// group-write bit unless the group is the private group of the account
// (GAP-0657, the rule the CLI preflight applies). A sticky folder passes on
// those bits because each entry in it is owner-checked as the walk reaches it.
// Every entry on the way (folder, link, file) must be owned by this account or
// root. The stow layout, a link to the dotfiles of the account, passes; the
// file mode is openCodeServiceFileShared to judge.
//
// A group record cannot show who holds a group: a directory service, a primary
// group in another account's record or a credential granted outside every
// database all reach a folder the group can write (REVIEW-4 MF1). So the
// private-group proof only decides whether to try, and a folder the group can
// write is made sticky by its owner (openCodeSealSharedFolder) before the walk
// goes on: from then on nobody but the owner of an entry can rename or remove
// it, whoever holds the group. The folders it sealed are returned. A folder
// that cannot be made sticky is refused. A missing tail is created by the write
// at 0700 and needs no check.
func checkOpenCodeServiceConfigFolders(_, path string) (sealed []string, err error) {
	pending := strings.Split(filepath.Clean(path), string(filepath.Separator))
	cur := string(filepath.Separator)
	links := 0
	for len(pending) > 0 {
		name := pending[0]
		pending = pending[1:]
		switch name {
		case "", ".":
			continue
		case "..":
			cur = filepath.Dir(cur)
			continue
		}
		dir, err := os.Lstat(cur)
		if err != nil {
			return sealed, err
		}
		if openCodeFolderOpenToOthers(cur, dir) {
			return sealed, fmt.Errorf("%s is owned by or writable to another account", cur)
		}
		done, err := openCodeSealSharedFolder(cur, dir)
		if err != nil {
			return sealed, fmt.Errorf("%s is writable to its group and could not be made sticky: %w", cur, err)
		}
		if done {
			sealed = append(sealed, cur)
		}
		next := filepath.Join(cur, name)
		entry, err := os.Lstat(next)
		if os.IsNotExist(err) {
			return sealed, nil
		}
		if err != nil {
			return sealed, err
		}
		if !openCodeTrustedOwner(entry) {
			return sealed, fmt.Errorf("%s is owned by another account", next)
		}
		if entry.Mode()&os.ModeSymlink == 0 {
			cur = next
			continue
		}
		if links++; links > openCodeMaxLinks {
			return sealed, fmt.Errorf("%s: too many links", path)
		}
		target, err := os.Readlink(next)
		if err != nil {
			return sealed, err
		}
		if filepath.IsAbs(target) {
			cur = string(filepath.Separator)
		}
		pending = append(strings.Split(target, string(filepath.Separator)), pending...)
	}
	return sealed, nil
}

// openCodeSealSharedFolder adds the sticky bit to a folder the group can write
// and reports that it did. The folder is opened without following a link and
// must still be the one the walk looked at; only its owner can change it, so a
// folder of another account fails here and is refused. The bit is read back:
// a file system that ignores it is not a seal.
func openCodeSealSharedFolder(path string, info os.FileInfo) (bool, error) {
	if info.Mode()&os.ModeSticky != 0 || info.Mode().Perm()&0o020 == 0 {
		return false, nil
	}
	folder, err := os.OpenFile(path, os.O_RDONLY|syscall.O_DIRECTORY|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return false, err
	}
	defer folder.Close()
	now, err := folder.Stat()
	if err != nil || !os.SameFile(info, now) {
		return false, fmt.Errorf("%s changed while it was checked", path)
	}
	if err := folder.Chmod(now.Mode()&(os.ModePerm|os.ModeSetuid|os.ModeSetgid) | os.ModeSticky); err != nil {
		return false, err
	}
	if after, err := folder.Stat(); err != nil || after.Mode()&os.ModeSticky == 0 {
		return false, fmt.Errorf("%s ignores the sticky bit", path)
	}
	return true, nil
}

// openCodeTrustedOwner reports an entry this account or root owns; either one
// can change it anyway.
func openCodeTrustedOwner(info os.FileInfo) bool {
	stat, ok := info.Sys().(*syscall.Stat_t)
	return ok && (int(stat.Uid) == os.Geteuid() || stat.Uid == 0)
}

// openCodeFolderOpenToOthers reports a folder whose owner is another account
// or whose mode lets another account add, remove or rename entries in it.
func openCodeFolderOpenToOthers(path string, info os.FileInfo) bool {
	if !openCodeTrustedOwner(info) {
		return true
	}
	if info.Mode()&os.ModeSticky != 0 {
		return false
	}
	perm := info.Mode().Perm()
	return perm&0o002 != 0 || (perm&0o020 != 0 && !openCodeOwnerPrivateGroup(path, info))
}

// openCodeServiceFileShared reports a service.json another account can write
// (a group or other write bit). The write replaces it with a 0600 copy, or
// refuses a link. Where the file lives is the folder check to judge.
func openCodeServiceFileShared(path string) bool {
	info, err := os.Lstat(path)
	return err != nil || info.Mode().Perm()&0o022 != 0
}

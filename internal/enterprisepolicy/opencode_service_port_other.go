//go:build !windows

// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package enterprisepolicy

import (
	"fmt"
	"os"
	"os/user"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"

	"github.com/defenseclaw/defenseclaw/internal/gateway/connector"
	"github.com/defenseclaw/defenseclaw/internal/managed"
)

// openCodeMaxLinks bounds the links the path walk follows.
const openCodeMaxLinks = 40

// openCodeOwnerPrivateGroup is the private-group proof (tests replace it).
var openCodeOwnerPrivateGroup = connector.OwnerPrivateGroup

// openCodePathACLOpen reports a path whose access control list lets another
// principal write it. macOS grants write and append through an ACL entry
// without changing the mode bits, so every mode check below asks this too
// (GAP-0053 REVIEW-6 MF1). The folders and files here belong to this account,
// so an entry for root, an administrator group or the account itself adds no
// authority and is not judged (REVIEW-7 MF1); an entry for any other principal
// is. A list that cannot be read counts as open. Tests replace it.
var openCodePathACLOpen = func(path string) bool {
	return managed.ValidatePathACLForAccount(path, os.Geteuid(), openCodeAccountName()) != nil
}

// openCodeAccountName is the short name of the account the process runs as,
// "" when the name service cannot say (then only root and the administrator
// groups are accepted in an ACL).
func openCodeAccountName() string {
	account, err := user.LookupId(strconv.Itoa(os.Geteuid()))
	if err != nil {
		return ""
	}
	return account.Username
}

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
// The walk follows links for the read and the write alike, so the follow
// argument (Windows: read only) is not used here.
func checkOpenCodeServiceConfigFolders(_, path string, _ bool) (sealed []string, err error) {
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
	// A link has no mode of its own to judge (macOS reports 0755 where Linux
	// reports 0777), so it is refused before the mode is read.
	if info.Mode()&os.ModeSymlink != 0 {
		return false, fmt.Errorf("%s is a link; it is not sealed", path)
	}
	if info.Mode()&os.ModeSticky != 0 || openCodePerm(path, info)&0o020 == 0 {
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

// openCodePerm is the permission bits of an entry as they apply to other
// accounts: where Linux reports a POSIX ACL mask as the group bits, the group
// object entry decides, not the mask a root or owner entry raised. Named
// entries are openCodePathACLOpen to judge.
func openCodePerm(path string, info os.FileInfo) os.FileMode {
	return managed.ModeWithoutACLMask(path, info.Mode().Perm())
}

// openCodeTrustedOwner reports an entry this account or root owns; either one
// can change it anyway.
func openCodeTrustedOwner(info os.FileInfo) bool {
	stat, ok := info.Sys().(*syscall.Stat_t)
	return ok && (int(stat.Uid) == os.Geteuid() || stat.Uid == 0)
}

// openCodeFolderOpenToOthers reports a folder whose owner is another account
// or whose mode or ACL lets another account add, remove or rename entries in
// it. An ACL entry decides whatever the mode bits and the sticky bit say.
func openCodeFolderOpenToOthers(path string, info os.FileInfo) bool {
	if !openCodeTrustedOwner(info) || openCodePathACLOpen(path) {
		return true
	}
	if info.Mode()&os.ModeSticky != 0 {
		return false
	}
	perm := openCodePerm(path, info)
	return perm&0o002 != 0 || (perm&0o020 != 0 && !openCodeOwnerPrivateGroup(path, info))
}

// openCodeServiceFileShared reports a service.json another account can write
// (a group or other write bit, or an ACL entry). The write replaces it with a
// 0600 copy, or refuses a link. Where the file lives is the folder check to
// judge.
func openCodeServiceFileShared(path string) bool {
	info, err := os.Lstat(path)
	return err != nil || openCodePerm(path, info)&0o022 != 0 || openCodePathACLOpen(path)
}

// openCodeImportFileTrusted reports that the open service.json is owned by
// this account or root and that no group or other account can write it, by
// mode or by ACL. The mode is read from the open file; the ACL is read from the
// path the open file resolves to, once that path is shown to be the same file,
// so what is read is what was checked.
func openCodeImportFileTrusted(path string, file *os.File) bool {
	info, err := file.Stat()
	if err != nil || !openCodeTrustedOwner(info) {
		return false
	}
	resolved, err := filepath.EvalSymlinks(path)
	if err != nil {
		return false
	}
	at, err := os.Lstat(resolved)
	if err != nil || !os.SameFile(info, at) || openCodePerm(resolved, info)&0o022 != 0 {
		return false
	}
	return !openCodePathACLOpen(resolved)
}

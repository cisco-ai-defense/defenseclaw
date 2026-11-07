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
// by link, without creating anything, and refuses it when another account
// could replace what the walk passes through (REVIEW-2 MF1b). It runs before a
// port that already matches is accepted and before a write, so a matching file
// is no safer than a differing one. Every folder the walk stands in (the
// folders on the way, the folder holding each link, the folders a link leads
// through) must be owned by this account or root and closed to other accounts:
// no other-write bit, and no group-write bit unless the group is the private
// group of the account (GAP-0657, the rule the CLI preflight applies). A sticky
// folder passes on those bits because each entry in it is owner-checked as the
// walk reaches it. Every entry on the way (folder, link, file) must be owned by
// this account or root. The stow layout, a link to the dotfiles of the account,
// passes; the file mode is openCodeServiceFileShared to judge. A missing tail
// is created by the write at 0700 and needs no check.
func checkOpenCodeServiceConfigFolders(_, path string) error {
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
			return err
		}
		if openCodeFolderOpenToOthers(cur, dir) {
			return fmt.Errorf("%s is owned by or writable to another account", cur)
		}
		next := filepath.Join(cur, name)
		entry, err := os.Lstat(next)
		if os.IsNotExist(err) {
			return nil
		}
		if err != nil {
			return err
		}
		if !openCodeTrustedOwner(entry) {
			return fmt.Errorf("%s is owned by another account", next)
		}
		if entry.Mode()&os.ModeSymlink == 0 {
			cur = next
			continue
		}
		if links++; links > openCodeMaxLinks {
			return fmt.Errorf("%s: too many links", path)
		}
		target, err := os.Readlink(next)
		if err != nil {
			return err
		}
		if filepath.IsAbs(target) {
			cur = string(filepath.Separator)
		}
		pending = append(strings.Split(target, string(filepath.Separator)), pending...)
	}
	return nil
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

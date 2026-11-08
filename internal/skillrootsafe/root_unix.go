//go:build !windows

// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package skillrootsafe

import (
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"syscall"

	"github.com/defenseclaw/defenseclaw/internal/gateway/connector"
)

const maxRootLinks = 32

// ownerPrivateGroup is the private-group proof (tests replace it). It holds
// only on a host whose accounts and groups are all local files: an account a
// directory service gives the group as its primary group can write the folder,
// and the name service cannot list those.
var ownerPrivateGroup = connector.OwnerPrivateGroupLocalSources

// pamGroupLoaded says whether a PAM stack file loads pam_group (tests replace
// it). Where it does, a private group is not a proof that nobody else can
// write the folder.
var pamGroupLoaded = connector.PAMGroupLoaded

func fileUID(info os.FileInfo) (uint32, bool) {
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return 0, false
	}
	return stat.Uid, true
}

// otherAccountWrite judges the write bits of a folder of a linked route
// (GAP-0905). refuse is true when an account other than the owner can write
// it: other write always, and group write unless the group is the own private
// group of the owner, the scheme Ubuntu, Debian and RHEL use with a umask of
// 002, which has no other member. privateGroup is true when only that
// exception let the folder pass.
func otherAccountWrite(path string, info os.FileInfo) (refuse, privateGroup bool) {
	perm := info.Mode().Perm()
	if perm&0o002 != 0 {
		return true, false
	}
	if perm&0o020 == 0 {
		return false, false
	}
	if ownerPrivateGroup(path, info) {
		return false, true
	}
	return true, false
}

func writableAncestor(root, ancestor string, info os.FileInfo) error {
	return fmt.Errorf("linked or unavailable skill root: %s: %w", root,
		&WritableAncestorError{Ancestor: ancestor, Mode: info.Mode()})
}

func pathParts(path string) []string {
	return strings.FieldsFunc(path, func(r rune) bool { return r == filepath.Separator })
}

// acceptLinkedRoot returns the resolved root when every link on the route is
// controlled by the account or root.
func acceptLinkedRoot(path, resolved string) (string, []string, error) {
	privateGroupFolders, err := validateLinkedPath(path, resolved)
	if err != nil {
		return "", nil, err
	}
	return resolved, privateGroupFolders, nil
}

// validateLinkedPath checks the route. It returns the folders the route passes
// only because their group is the private group of the owner, when pam_group is
// loaded.
func validateLinkedPath(path, want string) ([]string, error) {
	// The first link is inside the account's own tree. Its plain parent gives
	// the account UID even when a managed gateway itself runs as root.
	current := string(filepath.Separator)
	var accountUID uint32
	found := false
	for _, part := range pathParts(path) {
		next := filepath.Join(current, part)
		info, err := os.Lstat(next)
		if err != nil {
			return nil, unsafeRoot(path)
		}
		if info.Mode()&os.ModeSymlink != 0 {
			parent, err := os.Lstat(current)
			if err != nil {
				return nil, unsafeRoot(path)
			}
			accountUID, found = fileUID(parent)
			break
		}
		current = next
	}
	if !found {
		return nil, unsafeRoot(path)
	}

	current = string(filepath.Separator)
	remaining := pathParts(path)
	var privateGroupFolders []string
	links := 0
	for len(remaining) > 0 {
		next := filepath.Join(current, remaining[0])
		remaining = remaining[1:]
		info, err := os.Lstat(next)
		if err != nil {
			return nil, unsafeRoot(path)
		}
		uid, ok := fileUID(info)
		if !ok || (uid != accountUID && uid != 0) {
			return nil, unsafeRoot(path)
		}
		if info.Mode()&os.ModeSymlink != 0 {
			links++
			if links > maxRootLinks {
				return nil, unsafeRoot(path)
			}
			target, err := os.Readlink(next)
			if err != nil {
				return nil, unsafeRoot(path)
			}
			if !filepath.IsAbs(target) {
				target = filepath.Join(current, target)
			}
			remaining = append(pathParts(filepath.Clean(target)), remaining...)
			current = string(filepath.Separator)
			continue
		}
		if !info.IsDir() || info.Mode()&os.ModeIrregular != 0 {
			return nil, unsafeRoot(path)
		}
		// A root-owned sticky system temp folder protects entries by owner;
		// any other writable ancestor could replace a validated link target.
		if info.Mode().Perm()&0o022 != 0 && (uid != 0 || info.Mode()&os.ModeSticky == 0) {
			refuse, privateGroup := otherAccountWrite(next, info)
			if refuse {
				return nil, writableAncestor(path, next, info)
			}
			if privateGroup {
				privateGroupFolders = append(privateGroupFolders, next)
			}
		}
		current = next
	}
	if !samePath(current, want) {
		return nil, fmt.Errorf("skill root changed while resolving: %s", path)
	}
	final, err := os.Lstat(current)
	if err != nil {
		return nil, unsafeRoot(path)
	}
	uid, ok := fileUID(final)
	if !ok || uid != accountUID {
		return nil, unsafeRoot(path)
	}
	if final.Mode().Perm()&0o022 != 0 {
		refuse, privateGroup := otherAccountWrite(current, final)
		if refuse {
			return nil, writableAncestor(path, current, final)
		}
		if privateGroup && !slices.Contains(privateGroupFolders, current) {
			privateGroupFolders = append(privateGroupFolders, current)
		}
	}
	return privateGroupFolders, nil
}

// groupWritableWarnings keeps the private-group folders of a route only where
// pam_group is loaded: the module can add an account to a group at login by
// rules this check does not read, so there a private group does not prove that
// nobody else writes the folder.
func groupWritableWarnings(privateGroupFolders []string) []string {
	if len(privateGroupFolders) == 0 || !pamGroupLoaded() {
		return nil
	}
	return privateGroupFolders
}

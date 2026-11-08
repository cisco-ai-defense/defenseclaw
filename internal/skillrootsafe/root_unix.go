//go:build !windows

// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package skillrootsafe

import (
	"fmt"
	"os"
	"path/filepath"
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

func fileUID(info os.FileInfo) (uint32, bool) {
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return 0, false
	}
	return stat.Uid, true
}

// writableByOtherAccount reports whether an account other than the owner can
// write the folder info describes (GAP-0905). Other write always counts. Group
// write counts unless the group is the owner's own private group, the scheme
// Ubuntu, Debian and RHEL use with a umask of 002: that group has no other
// member, so it lets nobody else in. Any other group keeps the refusal.
func writableByOtherAccount(path string, info os.FileInfo) bool {
	perm := info.Mode().Perm()
	if perm&0o002 != 0 {
		return true
	}
	return perm&0o020 != 0 && !ownerPrivateGroup(path, info)
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
func acceptLinkedRoot(path, resolved string) (string, error) {
	if err := validateLinkedPath(path, resolved); err != nil {
		return "", err
	}
	return resolved, nil
}

func validateLinkedPath(path, want string) error {
	// The first link is inside the account's own tree. Its plain parent gives
	// the account UID even when a managed gateway itself runs as root.
	current := string(filepath.Separator)
	var accountUID uint32
	found := false
	for _, part := range pathParts(path) {
		next := filepath.Join(current, part)
		info, err := os.Lstat(next)
		if err != nil {
			return unsafeRoot(path)
		}
		if info.Mode()&os.ModeSymlink != 0 {
			parent, err := os.Lstat(current)
			if err != nil {
				return unsafeRoot(path)
			}
			accountUID, found = fileUID(parent)
			break
		}
		current = next
	}
	if !found {
		return unsafeRoot(path)
	}

	current = string(filepath.Separator)
	remaining := pathParts(path)
	links := 0
	for len(remaining) > 0 {
		next := filepath.Join(current, remaining[0])
		remaining = remaining[1:]
		info, err := os.Lstat(next)
		if err != nil {
			return unsafeRoot(path)
		}
		uid, ok := fileUID(info)
		if !ok || (uid != accountUID && uid != 0) {
			return unsafeRoot(path)
		}
		if info.Mode()&os.ModeSymlink != 0 {
			links++
			if links > maxRootLinks {
				return unsafeRoot(path)
			}
			target, err := os.Readlink(next)
			if err != nil {
				return unsafeRoot(path)
			}
			if !filepath.IsAbs(target) {
				target = filepath.Join(current, target)
			}
			remaining = append(pathParts(filepath.Clean(target)), remaining...)
			current = string(filepath.Separator)
			continue
		}
		if !info.IsDir() || info.Mode()&os.ModeIrregular != 0 {
			return unsafeRoot(path)
		}
		// A root-owned sticky system temp folder protects entries by owner;
		// any other writable ancestor could replace a validated link target.
		if info.Mode().Perm()&0o022 != 0 && (uid != 0 || info.Mode()&os.ModeSticky == 0) &&
			writableByOtherAccount(next, info) {
			return writableAncestor(path, next, info)
		}
		current = next
	}
	if !samePath(current, want) {
		return fmt.Errorf("skill root changed while resolving: %s", path)
	}
	final, err := os.Lstat(current)
	if err != nil {
		return unsafeRoot(path)
	}
	uid, ok := fileUID(final)
	if !ok || uid != accountUID {
		return unsafeRoot(path)
	}
	if final.Mode().Perm()&0o022 != 0 && writableByOtherAccount(current, final) {
		return writableAncestor(path, current, final)
	}
	return nil
}

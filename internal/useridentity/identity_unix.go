// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package useridentity

import (
	"os"
	"os/user"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
)

// currentIdentity reports the effective uid, which is the join key that
// survives setuid hook impersonation, plus the account name when it resolves.
//
// Geteuid is preferred over user.Current because user.Current consults HOME
// and the passwd database, and a hardened hook deliberately rewrites HOME.
func currentIdentity() Identity {
	out := Identity{
		ID:     strconv.Itoa(os.Geteuid()),
		IDKind: KindPOSIXUID,
	}
	if current, err := user.Current(); err == nil && current != nil {
		out.Name = strings.TrimSpace(current.Username)
	}
	if out.Name == "" {
		if resolved, err := user.LookupId(out.ID); err == nil && resolved != nil {
			out.Name = strings.TrimSpace(resolved.Username)
		}
	}
	return out
}

// homeForID reads the passwd home directory for a uid.
//
// A relative path is refused: the passwd database is administrator-owned, but
// a relative home would resolve against the gateway's working directory and
// silently read files from somewhere other than a user profile.
func homeForID(id string) string {
	resolved, err := user.LookupId(id)
	if err != nil || resolved == nil {
		return ""
	}
	home := strings.TrimSpace(resolved.HomeDir)
	if home == "" || !filepath.IsAbs(home) {
		return ""
	}
	return home
}

// identityForHome reports the owner of a profile directory from its inode.
//
// The directory owner is used rather than a passwd scan for a home path match,
// because a passwd entry can point at a directory the account no longer owns,
// and because this needs no elevated access: the sidecar can stat a profile
// root it is allowed to traverse without reading the account database.
func identityForHome(home string) Identity {
	info, err := os.Stat(home)
	if err != nil || !info.IsDir() {
		return Identity{}
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return Identity{}
	}
	out := Identity{
		ID:     strconv.FormatUint(uint64(stat.Uid), 10),
		IDKind: KindPOSIXUID,
	}
	if resolved, err := user.LookupId(out.ID); err == nil && resolved != nil {
		out.Name = strings.TrimSpace(resolved.Username)
	}
	return out
}

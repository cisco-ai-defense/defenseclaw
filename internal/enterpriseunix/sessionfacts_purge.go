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

package enterpriseunix

import (
	"encoding/json"
	"errors"
	"fmt"
	"path/filepath"
	"strings"

	"golang.org/x/sys/unix"

	"github.com/defenseclaw/defenseclaw/internal/enterprisehooks"
	"github.com/defenseclaw/defenseclaw/internal/useridentity"
)

// sessionFactsAccount is an enrolled account whose session-facts cache an
// uninstall --purge removes.
type sessionFactsAccount struct {
	user string
	uid  int
	home string
}

// sessionFactsAccounts are the enrolled accounts of the enumerator's
// eligible-accounts record, read before the uninstall removes it.
func (env *Env) sessionFactsAccounts() []sessionFactsAccount {
	data, err := readBounded(env.P(enterprisehooks.UnixEligibleAccountsPath(env.Layout.ManifestPath)), maxInputBytes)
	if err != nil {
		return nil
	}
	var record struct {
		Accounts []struct {
			User string `json:"user"`
			UID  int    `json:"uid"`
			Home string `json:"home"`
		} `json:"accounts"`
	}
	if json.Unmarshal(data, &record) != nil {
		return nil
	}
	var accounts []sessionFactsAccount
	for _, account := range record.Accounts {
		home := filepath.Clean(strings.TrimSpace(account.Home))
		if account.UID <= 0 || !filepath.IsAbs(home) || home == "/" || strings.TrimSpace(account.User) == "" {
			continue
		}
		accounts = append(accounts, sessionFactsAccount{user: account.User, uid: account.UID, home: home})
	}
	return accounts
}

// purgeSessionFactsCaches removes, on uninstall --purge, the session-facts
// cache the managed hook keeps in each enrolled account's home
// (~/.defenseclaw/session-facts.json, internal/useridentity), and the
// ~/.defenseclaw it leaves empty. An account enrolled only for
// machine-policy connectors (Claude Code, Codex) has no manifest row, and the
// per-user purge, which deletes the whole ~/.defenseclaw only of the
// accounts the manifest enrolls, left the cache there (GAP-1186).
func (l *lifecycle) purgeSessionFactsCaches(accounts []sessionFactsAccount) {
	cache := "~/.defenseclaw/" + useridentity.SessionFactsCacheFileName
	for _, account := range accounts {
		removed, err := removeSessionFactsCache(l.env.P(account.home), account.uid)
		switch {
		case err != nil:
			l.result.AddWarning(codePerUserState, fmt.Sprintf("the DefenseClaw session cache of user %s (%s) was not removed: %v; delete it by hand", account.user, cache, err))
		case removed:
			l.result.Changes = append(l.result.Changes, fmt.Sprintf("removed the DefenseClaw session cache of user %s (%s)", account.user, cache))
		}
	}
}

// removeSessionFactsCache removes home/.defenseclaw/session-facts.json and,
// when the cache was all it held, the folder, which the hook created for it.
// It runs as root in a home the account controls, so each folder is opened
// without following a symlink and must be owned by uid, the cache must be a
// regular file the account owns, and the deletes go through the opened
// folders: a symlink or a folder swapped in meanwhile cannot redirect them.
// removed reports whether the cache was there.
func removeSessionFactsCache(home string, uid int) (removed bool, err error) {
	homeFD, err := openOwnedDir(unix.AT_FDCWD, home, uid)
	if err != nil || homeFD < 0 {
		return false, err
	}
	defer unix.Close(homeFD)
	dataFD, err := openOwnedDir(homeFD, ".defenseclaw", uid)
	if err != nil || dataFD < 0 {
		return false, err
	}
	defer unix.Close(dataFD)
	name := useridentity.SessionFactsCacheFileName
	var st unix.Stat_t
	if err := unix.Fstatat(dataFD, name, &st, unix.AT_SYMLINK_NOFOLLOW); err != nil {
		if errors.Is(err, unix.ENOENT) {
			return false, nil
		}
		return false, err
	}
	if st.Mode&unix.S_IFMT != unix.S_IFREG || int(st.Uid) != uid {
		return false, fmt.Errorf("%s is not a regular file the account owns", name)
	}
	if err := unix.Unlinkat(dataFD, name, 0); err != nil && !errors.Is(err, unix.ENOENT) {
		return false, err
	}
	// A folder with anything else in it (a per-user install's data) stays.
	err = unix.Unlinkat(homeFD, ".defenseclaw", unix.AT_REMOVEDIR)
	if err != nil && !errors.Is(err, unix.ENOTEMPTY) && !errors.Is(err, unix.EEXIST) && !errors.Is(err, unix.ENOENT) {
		return true, fmt.Errorf("remove the empty ~/.defenseclaw: %w", err)
	}
	return true, nil
}

// openOwnedDir opens name below dirFD as a folder without following a
// symlink and checks that uid owns it. It returns -1 and no error when the
// folder does not exist.
func openOwnedDir(dirFD int, name string, uid int) (int, error) {
	fd, err := unix.Openat(dirFD, name, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	switch {
	case errors.Is(err, unix.ENOENT):
		return -1, nil
	case errors.Is(err, unix.ELOOP) || errors.Is(err, unix.ENOTDIR):
		return -1, fmt.Errorf("%s is not a folder (a symlink is not followed)", name)
	case err != nil:
		return -1, err
	}
	var st unix.Stat_t
	if err := unix.Fstat(fd, &st); err != nil {
		_ = unix.Close(fd)
		return -1, err
	}
	if int(st.Uid) != uid {
		_ = unix.Close(fd)
		return -1, fmt.Errorf("%s is owned by uid %d, not the account's uid %d", name, st.Uid, uid)
	}
	return fd, nil
}

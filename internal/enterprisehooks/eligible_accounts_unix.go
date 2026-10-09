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
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"strings"
	"syscall"
)

// UnixEligibleAccountsFileName is the root-only record the enumerator
// writes next to the manifest.
const UnixEligibleAccountsFileName = "eligible-accounts.json"

const unixEligibleAccountsMaxBytes = 4 << 20

type unixEligibleAccountsFile struct {
	Version  int                   `json:"version"`
	Accounts []UnixEligibleAccount `json:"accounts"`
	// IdentityOnly are accounts that pass every enrollment filter but whose
	// home is not enrolled (it is group/other writable, a symlink or owned
	// by another account). The guardian keeps their identity record, so a
	// user cannot drop the profile assigned to him by loosening his own home
	// (GAP-0714); nothing is written in their homes.
	IdentityOnly []UnixEligibleAccount `json:"identity_only,omitempty"`
}

// UnixEligibleAccountsPath is the eligible-accounts record for manifestPath.
func UnixEligibleAccountsPath(manifestPath string) string {
	return filepath.Join(filepath.Dir(filepath.Clean(manifestPath)), UnixEligibleAccountsFileName)
}

// UnixCopilotVSCodeAccountsFileName is the guardian's root-only record of
// the accounts it wrote DefenseClaw's VS Code Local hook file or Copilot
// plugin for, in the eligible-accounts format. An account that stops being
// eligible keeps those files until the guardian or remove-all takes them out
// through this record.
const UnixCopilotVSCodeAccountsFileName = "copilot-vscode-accounts.json"

// UnixCopilotVSCodeAccountsPath is the VS Code Local accounts record for
// manifestPath.
func UnixCopilotVSCodeAccountsPath(manifestPath string) string {
	return filepath.Join(filepath.Dir(filepath.Clean(manifestPath)), UnixCopilotVSCodeAccountsFileName)
}

// WriteUnixEligibleAccounts publishes accounts at path: root-owned 0600
// below a root-owned directory chain, written through a same-directory temp
// file and rename. The guardian only trusts a record written this way.
func WriteUnixEligibleAccounts(path string, accounts []UnixEligibleAccount) error {
	return WriteUnixEnumeratorAccounts(path, accounts, nil)
}

// WriteUnixEnumeratorAccounts publishes the eligible accounts and the
// identity-only accounts (unixEligibleAccountsFile.IdentityOnly) at path.
func WriteUnixEnumeratorAccounts(path string, accounts, identityOnly []UnixEligibleAccount) error {
	path = filepath.Clean(strings.TrimSpace(path))
	if !filepath.IsAbs(path) {
		return fmt.Errorf("enterprise hooks: eligible accounts path must be absolute: %s", path)
	}
	sortAccounts := func(accounts []UnixEligibleAccount) []UnixEligibleAccount {
		sorted := append([]UnixEligibleAccount{}, accounts...)
		sort.Slice(sorted, func(i, j int) bool { return sorted[i].User < sorted[j].User })
		return sorted
	}
	sorted := sortAccounts(accounts)
	record := unixEligibleAccountsFile{Version: 1, Accounts: sorted}
	if len(identityOnly) > 0 {
		record.IdentityOnly = sortAccounts(identityOnly)
	}
	data, err := json.MarshalIndent(record, "", "  ")
	if err != nil {
		return err
	}
	return writeUnixRootOnlyRecord(path, append(data, '\n'), ".defenseclaw-eligible-*.new", unixEligibleAccountsMaxBytes)
}

// WriteUnixUnprotectedAgents publishes the enumerator's unprotected-agents
// record at path with the same root-only contract as the eligible accounts.
func WriteUnixUnprotectedAgents(path string, agents []UnprotectedAgent) error {
	path = filepath.Clean(strings.TrimSpace(path))
	if !filepath.IsAbs(path) {
		return fmt.Errorf("enterprise hooks: unprotected agents path must be absolute: %s", path)
	}
	data, err := MarshalUnprotectedAgents(agents)
	if err != nil {
		return err
	}
	return writeUnixRootOnlyRecord(path, data, ".defenseclaw-unprotected-*.new", UnprotectedAgentsMaxBytes)
}

// writeUnixRootOnlyRecord writes data at path: root-owned 0600 below a
// root-owned directory chain, through a same-directory temp file and
// rename. An identical record is left untouched.
func writeUnixRootOnlyRecord(path string, data []byte, tempPattern string, limit int64) error {
	dir := filepath.Dir(path)
	if err := validateRootOwnedDirChain(dir); err != nil {
		return err
	}
	if current, readErr := readBoundedFile(path, limit); readErr == nil && string(current) == string(data) {
		return nil
	}
	tmp, err := os.CreateTemp(dir, tempPattern)
	if err != nil {
		return err
	}
	tmpPath := tmp.Name()
	defer func() { _ = os.Remove(tmpPath) }()
	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Chmod(0o600); err != nil {
		_ = tmp.Close()
		return err
	}
	if os.Geteuid() == 0 {
		if err := tmp.Chown(0, 0); err != nil {
			_ = tmp.Close()
			return err
		}
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmpPath, path)
}

// LoadUnixEligibleAccounts reads the record the enumerator published. A
// missing record is an empty list; a record that is not a root-owned 0600
// regular file below a root-owned directory chain is refused.
func LoadUnixEligibleAccounts(path string) ([]UnixEligibleAccount, error) {
	record, err := loadUnixEligibleAccountsFile(path)
	return record.Accounts, err
}

// LoadUnixIdentityAccounts returns every account whose identity record the
// guardian keeps: the eligible accounts and the identity-only ones.
func LoadUnixIdentityAccounts(path string) ([]UnixEligibleAccount, error) {
	record, err := loadUnixEligibleAccountsFile(path)
	return append(record.Accounts, record.IdentityOnly...), err
}

func loadUnixEligibleAccountsFile(path string) (unixEligibleAccountsFile, error) {
	var none unixEligibleAccountsFile
	path = filepath.Clean(strings.TrimSpace(path))
	if err := validateRootOwnedDirChain(filepath.Dir(path)); err != nil {
		return none, err
	}
	info, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		return none, nil
	}
	if err != nil {
		return none, err
	}
	if !info.Mode().IsRegular() || info.Mode().Perm()&0o077 != 0 {
		return none, fmt.Errorf("enterprise hooks: eligible accounts record %s must be a 0600 regular file", path)
	}
	if st, ok := info.Sys().(*syscall.Stat_t); !ok || (st.Uid != 0 && !unixManifestTestOwnerAllowed(st.Uid)) || st.Nlink != 1 {
		return none, fmt.Errorf("enterprise hooks: eligible accounts record %s is not a root-owned single-link file", path)
	}
	data, err := readBoundedFile(path, unixEligibleAccountsMaxBytes)
	if err != nil {
		return none, err
	}
	var record unixEligibleAccountsFile
	if err := json.Unmarshal(data, &record); err != nil {
		return none, fmt.Errorf("enterprise hooks: parse eligible accounts record: %w", err)
	}
	if record.Version != 1 {
		return none, fmt.Errorf("enterprise hooks: eligible accounts record version %d is not supported", record.Version)
	}
	valid := func(accounts []UnixEligibleAccount) []UnixEligibleAccount {
		out := make([]UnixEligibleAccount, 0, len(accounts))
		for _, account := range accounts {
			home := filepath.Clean(strings.TrimSpace(account.Home))
			if account.UID <= 0 || account.GID < 0 || !filepath.IsAbs(home) || home == "/" || strings.TrimSpace(account.User) == "" {
				continue
			}
			account.Home = home
			account.CreatedDirs = UnixCreatedDirsBelow(home, account.CreatedDirs)
			out = append(out, account)
		}
		return out
	}
	return unixEligibleAccountsFile{Version: 1, Accounts: valid(record.Accounts), IdentityOnly: valid(record.IdentityOnly)}, nil
}

// unixCreatedDirsLimit bounds the folders one account's record entry lists.
const unixCreatedDirsLimit = 64

// ManifestEnrolledAccounts keeps the accounts a target of manifest enrolls:
// the target of the account uid or, for a target that names no uid, of its
// user name. Under manifest enrollment the enumerator is idle, so the
// eligible-accounts record is what its last auto pass published: an account
// the administrator has since left out of the manifest stayed eligible, and
// the guardian kept scanning its home and publishing its identity record
// (GAP-0761).
func ManifestEnrolledAccounts(accounts []UnixEligibleAccount, manifest Manifest) []UnixEligibleAccount {
	uids, users := map[int]bool{}, map[string]bool{}
	for _, target := range manifest.Targets {
		if target.UID != nil {
			uids[*target.UID] = true
		} else if user := strings.TrimSpace(target.User); user != "" {
			users[user] = true
		}
	}
	out := make([]UnixEligibleAccount, 0, len(accounts))
	for _, account := range accounts {
		if uids[account.UID] || users[strings.TrimSpace(account.User)] {
			out = append(out, account)
		}
	}
	return out
}

// UnixCreatedDirsBelow keeps the absolute folders strictly below home, cleaned,
// without duplicates.
func UnixCreatedDirsBelow(home string, dirs []string) []string {
	var out []string
	for _, dir := range dirs {
		dir = filepath.Clean(strings.TrimSpace(dir))
		relative, err := filepath.Rel(home, dir)
		if !filepath.IsAbs(dir) || err != nil || relative == "." || relative == ".." ||
			strings.HasPrefix(relative, ".."+string(filepath.Separator)) {
			continue
		}
		if !slices.Contains(out, dir) && len(out) < unixCreatedDirsLimit {
			out = append(out, dir)
		}
	}
	sort.Strings(out)
	return out
}

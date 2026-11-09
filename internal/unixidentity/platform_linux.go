//go:build linux

// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// SPDX-License-Identifier: Apache-2.0

package unixidentity

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/useridentity"
)

// DirectoryFactsFunc returns a uid's verified directory facts through NSS,
// for LookupAccountSpelling, or nil without a trusted getent.
func DirectoryFactsFunc(ctx context.Context) func(uid int) (useridentity.DirectoryFacts, bool) {
	nss, err := NewNSSResolver(ctx)
	if err != nil {
		return nil
	}
	return func(uid int) (useridentity.DirectoryFacts, bool) {
		facts, err := nss.DirectoryFactsWithoutGroupsForUID(uid, time.Now().UTC())
		return facts, err == nil
	}
}

// platformLoginShell has nothing to add on Linux: getent, nslcd and
// /etc/passwd give every account its shell.
func platformLoginShell(context.Context, commandRunner, string) string { return "" }

// platformMobileAccounts finds none on Linux, whose directory accounts are
// never copied into /etc/passwd.
func platformMobileAccounts(context.Context) (map[string]string, error) {
	return map[string]string{}, nil
}

// platformSSOLinkedAccounts finds none on Linux, which has no Platform SSO.
func platformSSOLinkedAccounts(context.Context) (map[string]bool, error) {
	return map[string]bool{}, nil
}

// platformOpenDirectoryNodeStates has no Open Directory to read on Linux.
func platformOpenDirectoryNodeStates(context.Context) (string, error) {
	return "", errors.New("unixidentity: no Open Directory on this platform")
}

const loginDefsPath = "/etc/login.defs"

var (
	localPasswdPath = "/etc/passwd"
	localGroupPath  = "/etc/group"
	nsswitchPath    = "/etc/nsswitch.conf"
	sambaConfPath   = "/etc/samba/smb.conf"
)

// platformLocalAccounts reads /etc/passwd, the files backend itself.
func platformLocalAccounts(context.Context) (map[string]int, error) {
	data, err := readSmallFile(localPasswdPath, 16<<20)
	if err != nil {
		return nil, err
	}
	return parseLocalPasswd(string(data)), nil
}

// platformLocalDatabaseAccounts adds the systemd-userdb drop-in records and
// the nss-altfiles passwd files to /etc/passwd. A fresh account created as a
// userdb record is in no /etc/passwd line, so the guardian's warm-up never
// spooled its identity record and its first managed Codex turn was refused
// "the account holder is unconfirmed" (GAP-0026, the userdb leg of GAP-0677).
func platformLocalDatabaseAccounts(ctx context.Context) (map[string]int, error) {
	out, err := platformLocalAccounts(ctx)
	if err != nil {
		return nil, err
	}
	add := func(name string, uid int) {
		if _, dup := out[name]; !dup && validName(name) == nil && uid >= 0 {
			out[name] = uid
		}
	}
	for _, dir := range UserdbRecordDirs {
		entries, err := os.ReadDir(dir)
		if err != nil {
			continue
		}
		for _, entry := range entries {
			if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".user") {
				continue
			}
			data, err := readSmallFile(filepath.Join(dir, entry.Name()), 1<<20)
			if err != nil {
				continue
			}
			var record struct {
				UserName string `json:"userName"`
				UID      *int   `json:"uid"`
			}
			if json.Unmarshal(data, &record) != nil || record.UID == nil {
				continue
			}
			add(record.UserName, *record.UID)
		}
	}
	for _, path := range AltfilesPasswdFiles {
		data, err := readSmallFile(path, 16<<20)
		if err != nil {
			continue
		}
		for name, uid := range parseLocalPasswd(string(data)) {
			add(name, uid)
		}
	}
	return out, nil
}

// platformLocalDatabaseUIDs reads the sources of platformLocalDatabaseAccounts
// as uids. /etc/passwd, a userdb drop-in record or an nss-altfiles file that
// exists and cannot be read or parsed is an error; a directory or file that
// is absent is a source the host does not have.
func platformLocalDatabaseUIDs(context.Context) ([]int, error) {
	data, err := readSmallFile(localPasswdPath, 16<<20)
	if err != nil {
		return nil, fmt.Errorf("unixidentity: read %s: %w", localPasswdPath, err)
	}
	uids := parseLocalPasswdUIDs(string(data))
	for _, dir := range UserdbRecordDirs {
		entries, err := os.ReadDir(dir)
		if errors.Is(err, os.ErrNotExist) {
			continue
		}
		if err != nil {
			return nil, fmt.Errorf("unixidentity: read %s: %w", dir, err)
		}
		for _, entry := range entries {
			if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".user") {
				continue
			}
			path := filepath.Join(dir, entry.Name())
			data, err := readSmallFile(path, 1<<20)
			if err != nil {
				return nil, fmt.Errorf("unixidentity: read %s: %w", path, err)
			}
			var record struct {
				UID *int `json:"uid"`
			}
			if err := json.Unmarshal(data, &record); err != nil {
				return nil, fmt.Errorf("unixidentity: parse %s: %w", path, err)
			}
			if record.UID != nil && *record.UID >= 0 {
				uids = append(uids, *record.UID)
			}
		}
	}
	for _, path := range AltfilesPasswdFiles {
		data, err := readSmallFile(path, 16<<20)
		if errors.Is(err, os.ErrNotExist) {
			continue
		}
		if err != nil {
			return nil, fmt.Errorf("unixidentity: read %s: %w", path, err)
		}
		uids = append(uids, parseLocalPasswdUIDs(string(data))...)
	}
	return uids, nil
}

// parseLocalPasswdUIDs returns the uid of every entry of a passwd(5) file, in
// file order, duplicates included. NIS compat markers (+/-) and malformed
// lines are skipped.
func parseLocalPasswdUIDs(content string) []int {
	var out []int
	for _, line := range strings.Split(content, "\n") {
		line = strings.TrimRight(line, "\r")
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, "+") || strings.HasPrefix(line, "-") {
			continue
		}
		if account, err := ParsePasswdLine(line); err == nil {
			out = append(out, account.UID)
		}
	}
	return out
}

// platformDirectoryShowsUIDUnused asks every passwd service of nsswitch.conf
// but files (read by LocalDatabaseUIDs) for uid by itself, getent -s
// <service>: the combined lookup stops at the first miss when an NSS action
// such as [NOTFOUND=return] says so, and then never asks the services after
// it. A service that holds the uid is ErrUIDHeld. One that does not must also
// show it answers (passwdAbsent: SSSD and winbind online, nslcd completing the
// search). A service name DefenseClaw cannot check, or that is not a valid
// service name, is no proof.
func platformDirectoryShowsUIDUnused(ctx context.Context, uid int) error {
	services, err := passwdProviders()
	if err != nil {
		return err
	}
	var resolver *NSSResolver
	return servicesShowUIDUnused(services, uid, func() (*NSSResolver, error) {
		if resolver == nil {
			var err error
			if resolver, err = NewNSSResolver(ctx); err != nil {
				return nil, err
			}
		}
		return resolver, nil
	})
}

// servicesShowUIDUnused is platformDirectoryShowsUIDUnused for a list of
// services and the resolver it gets lazily, so a host with only files never
// needs getent.
func servicesShowUIDUnused(services []string, uid int, resolverFor func() (*NSSResolver, error)) error {
	for _, service := range services {
		if service == "files" {
			continue
		}
		if !validServiceName(service) {
			return fmt.Errorf("unixidentity: NSS passwd service %q cannot be checked", service)
		}
		resolver, err := resolverFor()
		if err != nil {
			return err
		}
		switch _, err := resolver.LookupUIDInService(service, uid); {
		case err == nil:
			return fmt.Errorf("%w: NSS service %s holds uid %d", ErrUIDHeld, service, uid)
		case !errors.Is(err, ErrNotFound):
			return fmt.Errorf("unixidentity: NSS service %s cannot show that uid %d has no account: %w", service, uid, err)
		}
		if err := resolver.passwdAbsent(service, strconv.Itoa(uid), true); err != nil {
			return fmt.Errorf("unixidentity: NSS service %s cannot show that uid %d has no account: %w", service, uid, err)
		}
	}
	return nil
}

func platformLocalAccountRecords(context.Context) (map[string]LocalAccountRecord, error) {
	return nil, errors.New("unixidentity: local account records are listed only on macOS")
}

func platformLocalAccountRecord(context.Context, string) (LocalAccountRecord, bool, error) {
	return LocalAccountRecord{}, false, errors.New("unixidentity: local account records are listed only on macOS")
}

func platformAccountsAtHome(context.Context, string) ([]HomeAccount, error) {
	return nil, errors.New("unixidentity: home folders are searched only on macOS")
}

// platformAccountRecordGone is false: these lookups already run in a
// fresh process (getent) or read the files backend, so a found account is
// current.
func platformAccountRecordGone(context.Context, string) bool { return false }

// platformAccountUIDGone is false for the same reason.
func platformAccountUIDGone(context.Context, string, int) bool { return false }

// platformLocalGroups reads /etc/group, the files backend itself.
func platformLocalGroups(context.Context) (map[string]int, error) {
	data, err := readSmallFile(localGroupPath, 16<<20)
	if err != nil {
		return nil, err
	}
	return parseLocalGroups(string(data)), nil
}

// platformDirectoryConfigured reads the passwd sources of nsswitch.conf. A
// missing file is glibc's default (files only); an unreadable one is
// treated as a directory host.
func platformDirectoryConfigured() bool {
	data, err := readSmallFile(nsswitchPath, 1<<20)
	if err != nil {
		return !errors.Is(err, os.ErrNotExist)
	}
	return ParseNSSwitchDirectoryConfigured(string(data))
}

func readSmallFile(path string, limit int64) ([]byte, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	data, err := io.ReadAll(io.LimitReader(file, limit+1))
	if err != nil {
		return nil, err
	}
	if int64(len(data)) > limit {
		return nil, fmt.Errorf("unixidentity: %s exceeds %d bytes", path, limit)
	}
	return data, nil
}

// ProcessLookupsOutliveDeletion is false on Linux: NSS answers each lookup
// from the account databases (nscd and SSSD caches are invalidated on a
// change), so a found answer means the account exists.
const ProcessLookupsOutliveDeletion = false

// DefaultUIDRange reads UID_MIN/UID_MAX from /etc/login.defs, falling back
// to the shadow-utils defaults.
func DefaultUIDRange() (int, int) {
	file, err := os.Open(loginDefsPath)
	if err != nil {
		return 1000, 60000
	}
	defer file.Close()
	data, err := io.ReadAll(io.LimitReader(file, 256<<10))
	if err != nil {
		return 1000, 60000
	}
	return ParseLoginDefsUIDRange(string(data), 1000, 60000)
}

// Default returns the NSS resolver when a trusted getent exists, otherwise
// os/user, which sees only /etc/passwd and /etc/group.
func Default(ctx context.Context) Resolver {
	if nss, err := NewNSSResolver(ctx); err == nil {
		return NewCachingResolver(nss)
	}
	return NewCachingResolver(NewOSUserResolver(ctx))
}

// platformLocalUserLister has nothing better than NSS on Linux; the
// files-only fallback does not enumerate.
func platformLocalUserLister(context.Context, commandRunner) ([]Account, error) {
	return nil, nil
}

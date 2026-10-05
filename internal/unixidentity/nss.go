//go:build !windows

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
	"fmt"
	"sort"
	"strconv"
	"strings"
)

// getent exit codes (glibc, musl and systemd agree on these).
const (
	getentExitOK           = 0
	getentExitNotFound     = 2
	getentExitNoEnumerate  = 3
	getentExitMissingArgs  = 1
	defaultGetentPrimary   = "/usr/bin/getent"
	defaultGetentSecondary = "/bin/getent"
)

// NSSResolver resolves accounts through NSS by running getent, so every
// configured backend (files, sss, ldap, winbind, systemd) answers.
type NSSResolver struct {
	path   string
	runner commandRunner
	ctx    context.Context
}

// NewNSSResolver returns an NSS resolver backed by the first trusted getent
// binary. It fails when no root-owned getent exists.
func NewNSSResolver(ctx context.Context) (*NSSResolver, error) {
	path, err := firstTrustedTool(defaultGetentPrimary, defaultGetentSecondary)
	if err != nil {
		return nil, fmt.Errorf("unixidentity: no trusted getent binary: %w", err)
	}
	return &NSSResolver{path: path, runner: runTrustedCommand, ctx: ctx}, nil
}

func (r *NSSResolver) query(database string, keys ...string) (commandResult, error) {
	for _, key := range keys {
		if key == "" || strings.HasPrefix(key, "-") || strings.ContainsAny(key, "\x00\r\n") {
			return commandResult{}, fmt.Errorf("unixidentity: invalid %s lookup key %q", database, key)
		}
	}
	args := append([]string{database}, keys...)
	return r.runner(r.context(), r.path, args)
}

func (r *NSSResolver) context() context.Context {
	if r.ctx == nil {
		return context.Background()
	}
	return r.ctx
}

// LookupUIDInService asks one NSS service, and only that one, for uid
// (getent -s <service> passwd <uid>). It answers ErrNotFound when that
// service does not own the account, which is how the backend of a directory
// account is found: sss, winbind or ldap answer for their own users only.
func (r *NSSResolver) LookupUIDInService(service string, uid int) (Account, error) {
	if !validServiceName(service) || uid < 0 {
		return Account{}, fmt.Errorf("unixidentity: invalid service lookup %q %d", service, uid)
	}
	result, err := r.runner(r.context(), r.path, []string{"-s", service, "passwd", strconv.Itoa(uid)})
	if err != nil {
		return Account{}, err
	}
	switch result.exitCode {
	case getentExitOK:
	case getentExitNotFound:
		return Account{}, ErrNotFound
	default:
		return Account{}, fmt.Errorf("unixidentity: getent -s %s passwd %d exited %d", service, uid, result.exitCode)
	}
	lines := nonEmptyLines(string(result.stdout))
	if len(lines) != 1 {
		return Account{}, ErrNotFound
	}
	account, err := ParsePasswdLine(lines[0])
	if err != nil {
		return Account{}, err
	}
	if account.UID != uid {
		return Account{}, fmt.Errorf("unixidentity: getent -s %s passwd %d answered for uid %d", service, uid, account.UID)
	}
	return account, nil
}

func validServiceName(name string) bool {
	if name == "" || len(name) > 32 {
		return false
	}
	for _, r := range name {
		if !(r >= 'a' && r <= 'z' || r >= '0' && r <= '9' || r == '_') {
			return false
		}
	}
	return true
}

func (r *NSSResolver) lookupPasswd(key string) (Account, error) {
	result, err := r.query("passwd", key)
	if err != nil {
		return Account{}, err
	}
	switch result.exitCode {
	case getentExitOK:
	case getentExitNotFound:
		return Account{}, ErrNotFound
	default:
		return Account{}, fmt.Errorf("unixidentity: getent passwd %s exited %d", key, result.exitCode)
	}
	lines := nonEmptyLines(string(result.stdout))
	if len(lines) != 1 {
		return Account{}, fmt.Errorf("unixidentity: getent passwd %s returned %d entries", key, len(lines))
	}
	return ParsePasswdLine(lines[0])
}

// LookupUser resolves an account by name.
func (r *NSSResolver) LookupUser(name string) (Account, error) {
	if err := validName(name); err != nil {
		return Account{}, err
	}
	account, err := r.lookupPasswd(name)
	if err != nil {
		return Account{}, err
	}
	if account.Name != name {
		return Account{}, fmt.Errorf("unixidentity: getent passwd %s answered for %q", name, account.Name)
	}
	return account, nil
}

// LookupUID resolves an account by uid.
func (r *NSSResolver) LookupUID(uid int) (Account, error) {
	if uid < 0 {
		return Account{}, fmt.Errorf("unixidentity: invalid uid %d", uid)
	}
	account, err := r.lookupPasswd(strconv.Itoa(uid))
	if err != nil {
		return Account{}, err
	}
	if account.UID != uid {
		return Account{}, fmt.Errorf("unixidentity: getent passwd %d answered for uid %d", uid, account.UID)
	}
	return account, nil
}

func (r *NSSResolver) lookupGroupKey(key string) (Group, error) {
	result, err := r.query("group", key)
	if err != nil {
		return Group{}, err
	}
	switch result.exitCode {
	case getentExitOK:
	case getentExitNotFound:
		return Group{}, ErrNotFound
	default:
		return Group{}, fmt.Errorf("unixidentity: getent group %s exited %d", key, result.exitCode)
	}
	lines := nonEmptyLines(string(result.stdout))
	if len(lines) != 1 {
		return Group{}, fmt.Errorf("unixidentity: getent group %s returned %d entries", key, len(lines))
	}
	return ParseGroupLine(lines[0])
}

// LookupGroup resolves a group by name.
func (r *NSSResolver) LookupGroup(name string) (Group, error) {
	if err := validName(name); err != nil {
		return Group{}, err
	}
	group, err := r.lookupGroupKey(name)
	if err != nil {
		return Group{}, err
	}
	if group.Name != name {
		return Group{}, fmt.Errorf("unixidentity: getent group %s answered for %q", name, group.Name)
	}
	return group, nil
}

// LookupGroupID resolves a group by gid.
func (r *NSSResolver) LookupGroupID(gid int) (Group, error) {
	if gid < 0 {
		return Group{}, fmt.Errorf("unixidentity: invalid gid %d", gid)
	}
	group, err := r.lookupGroupKey(strconv.Itoa(gid))
	if err != nil {
		return Group{}, err
	}
	if group.GID != gid {
		return Group{}, fmt.Errorf("unixidentity: getent group %d answered for gid %d", gid, group.GID)
	}
	return group, nil
}

// GroupIDs resolves primary and supplementary groups with getent initgroups.
func (r *NSSResolver) GroupIDs(account Account) ([]int, error) {
	if err := validName(account.Name); err != nil {
		return nil, err
	}
	result, err := r.query("initgroups", account.Name)
	if err != nil {
		return nil, err
	}
	switch result.exitCode {
	case getentExitOK:
	case getentExitNotFound:
		return nil, ErrNotFound
	default:
		return nil, fmt.Errorf("unixidentity: getent initgroups %s exited %d", account.Name, result.exitCode)
	}
	ids, err := ParseInitgroups(string(result.stdout), account.Name)
	if err != nil {
		return nil, err
	}
	return withPrimary(ids, account.GID), nil
}

// ListUsers enumerates NSS passwd. Directory backends that refuse
// enumeration (SSSD enumerate=false) contribute nothing, so complete is
// always false: callers must merge other candidate sources.
func (r *NSSResolver) ListUsers() ([]Account, bool, error) {
	result, err := r.query("passwd")
	if err != nil {
		return nil, false, err
	}
	switch result.exitCode {
	case getentExitOK:
	case getentExitNoEnumerate:
		return nil, false, nil
	default:
		return nil, false, fmt.Errorf("unixidentity: getent passwd exited %d", result.exitCode)
	}
	var accounts []Account
	seen := map[string]bool{}
	for _, line := range nonEmptyLines(string(result.stdout)) {
		account, err := ParsePasswdLine(line)
		if err != nil {
			// One malformed backend row must not hide every other account.
			continue
		}
		if seen[account.Name] {
			continue
		}
		seen[account.Name] = true
		accounts = append(accounts, account)
	}
	sort.Slice(accounts, func(i, j int) bool { return accounts[i].UID < accounts[j].UID })
	return accounts, false, nil
}

func nonEmptyLines(text string) []string {
	var lines []string
	for _, line := range strings.Split(text, "\n") {
		if strings.TrimSpace(line) != "" {
			lines = append(lines, strings.TrimRight(line, "\r"))
		}
	}
	return lines
}

func withPrimary(ids []int, primary int) []int {
	for _, id := range ids {
		if id == primary {
			return ids
		}
	}
	out := append([]int{primary}, ids...)
	sort.Ints(out)
	return out
}

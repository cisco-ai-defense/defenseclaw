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
	"errors"
	"fmt"
	"os/user"
	"sort"
	"strconv"
	"strings"
)

// OSUserResolver resolves through os/user. On macOS that reaches Open
// Directory through libSystem, so local, mobile and directory-bound
// accounts resolve. On Linux (CGO_ENABLED=0) it sees only /etc/passwd and
// /etc/group and is used only when no trusted getent exists.
type OSUserResolver struct {
	ctx    context.Context
	runner commandRunner
	// lister enumerates local accounts; nil means "cannot enumerate".
	lister func(ctx context.Context, runner commandRunner) ([]Account, error)
}

// NewOSUserResolver returns an os/user resolver with the platform lister.
func NewOSUserResolver(ctx context.Context) *OSUserResolver {
	return &OSUserResolver{ctx: ctx, runner: runTrustedCommand, lister: platformLocalUserLister}
}

func translateUserErr(err error) error {
	var unknownUser user.UnknownUserError
	var unknownUID user.UnknownUserIdError
	var unknownGroup user.UnknownGroupError
	var unknownGID user.UnknownGroupIdError
	if errors.As(err, &unknownUser) || errors.As(err, &unknownUID) ||
		errors.As(err, &unknownGroup) || errors.As(err, &unknownGID) {
		return ErrNotFound
	}
	return err
}

func accountFromUser(u *user.User) (Account, error) {
	uid, err := parseID(u.Uid, "uid")
	if err != nil {
		return Account{}, err
	}
	gid, err := parseID(u.Gid, "gid")
	if err != nil {
		return Account{}, err
	}
	if err := validName(u.Username); err != nil {
		return Account{}, err
	}
	return Account{Name: u.Username, UID: uid, GID: gid, Gecos: u.Name, Home: u.HomeDir}, nil
}

// LookupUser resolves by name.
func (r *OSUserResolver) LookupUser(name string) (Account, error) {
	if err := validName(name); err != nil {
		return Account{}, err
	}
	u, err := user.Lookup(name)
	if err != nil {
		return Account{}, translateUserErr(err)
	}
	return accountFromUser(u)
}

// LookupUID resolves by uid.
func (r *OSUserResolver) LookupUID(uid int) (Account, error) {
	if uid < 0 {
		return Account{}, fmt.Errorf("unixidentity: invalid uid %d", uid)
	}
	u, err := user.LookupId(strconv.Itoa(uid))
	if err != nil {
		return Account{}, translateUserErr(err)
	}
	return accountFromUser(u)
}

// LookupGroup resolves by name.
func (r *OSUserResolver) LookupGroup(name string) (Group, error) {
	if err := validGroupName(name); err != nil {
		return Group{}, err
	}
	g, err := user.LookupGroup(name)
	if err != nil {
		return Group{}, translateUserErr(err)
	}
	gid, err := parseID(g.Gid, "gid")
	if err != nil {
		return Group{}, err
	}
	return Group{Name: g.Name, GID: gid}, nil
}

// LookupGroupID resolves by gid.
func (r *OSUserResolver) LookupGroupID(gid int) (Group, error) {
	if gid < 0 {
		return Group{}, fmt.Errorf("unixidentity: invalid gid %d", gid)
	}
	g, err := user.LookupGroupId(strconv.Itoa(gid))
	if err != nil {
		return Group{}, translateUserErr(err)
	}
	return Group{Name: g.Name, GID: gid}, nil
}

// GroupIDs returns primary and supplementary gids.
func (r *OSUserResolver) GroupIDs(account Account) ([]int, error) {
	u, err := user.LookupId(strconv.Itoa(account.UID))
	if err != nil {
		return nil, translateUserErr(err)
	}
	raw, err := AccountGroupIDs(r.ctx, u)
	if err != nil {
		return nil, err
	}
	seen := map[int]bool{}
	var ids []int
	for _, value := range raw {
		gid, err := parseID(strings.TrimSpace(value), "gid")
		if err != nil {
			return nil, err
		}
		if !seen[gid] {
			seen[gid] = true
			ids = append(ids, gid)
		}
	}
	sort.Ints(ids)
	return withPrimary(ids, account.GID), nil
}

// AccountGroupIDs lists the gids of an OS account, its primary group
// included, as decimal strings: os/user's GroupIds, checked by the platform
// where os/user cannot be trusted with a long membership. On macOS os/user
// lists into a buffer of 256 groups and getgrouplist does not report how many
// it holds, so an account in more fails (a mobile Active Directory account) or
// comes back cut at 256 (a local one) without an error (GAP-0201).
func AccountGroupIDs(ctx context.Context, account *user.User) ([]string, error) {
	ids, err := account.GroupIds()
	return platformAccountGroupIDs(ctx, runTrustedCommand, account, ids, err)
}

// ListUsers enumerates local accounts; directory accounts are not listed.
func (r *OSUserResolver) ListUsers() ([]Account, bool, error) {
	if r.lister == nil {
		return nil, false, nil
	}
	ctx := r.ctx
	if ctx == nil {
		ctx = context.Background()
	}
	accounts, err := r.lister(ctx, r.runner)
	return accounts, false, err
}

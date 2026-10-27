//go:build darwin

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
	"slices"
	"strconv"
	"strings"
	"time"

	"golang.org/x/sync/errgroup"
)

const (
	darwinID           = "/usr/bin/id"
	darwinDSMemberUtil = "/usr/bin/dsmemberutil"
	// osUserGroupBuffer is the number of groups os/user lists into on macOS. A
	// list that fills it may be cut short.
	osUserGroupBuffer = 256
)

// platformAccountGroupIDs gets candidate gids from os/user, or id when its
// fixed buffer is full, adds the gids of the named groups (the groups profile
// assignments select by), then confirms every supplementary membership
// against the account's uid. Both candidate providers calculate groups by
// name and leave out nested memberships; Open Directory's uid membership
// check binds each group to the account and answers nested ones (GAP-0528).
func platformAccountGroupIDs(ctx context.Context, runner commandRunner, account *user.User, ids []string, listErr error, named []string) ([]string, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	if listErr != nil || len(ids) >= osUserGroupBuffer {
		if err := validName(account.Username); err != nil {
			return nil, errors.Join(listErr, err)
		}
		if err := validateTrustedTool(darwinID); err != nil {
			return nil, errors.Join(listErr, err)
		}
		result, err := runner(ctx, darwinID, []string{"-G", "--", account.Username})
		if err != nil {
			return nil, errors.Join(listErr, err)
		}
		if result.exitCode != 0 {
			return nil, errors.Join(listErr, fmt.Errorf("unixidentity: id exited %d", result.exitCode))
		}
		ids, err = parseIDGroupList(string(result.stdout))
		if err != nil {
			return nil, errors.Join(listErr, err)
		}
	}
	extra, err := namedGroupIDs(ctx, named, lookupNamedGroupGID)
	if err != nil {
		return nil, err
	}
	return uidVerifiedGroupIDs(ctx, runner, account, ids, extra)
}

// lookupNamedGroupGID resolves a group name through Open Directory; ok is
// false when no group has the name. Tests replace it.
var lookupNamedGroupGID = func(ctx context.Context, name string) (gid int, ok bool, err error) {
	// os/user uses Open Directory on macOS and has no context parameter.
	// A bounded worker owns this call; the caller stops waiting at its
	// deadline and fails closed even if Open Directory remains blocked.
	type answer struct {
		gid int
		ok  bool
		err error
	}
	result := make(chan answer, 1)
	go func() {
		group, err := user.LookupGroup(name)
		if err != nil {
			if err = translateUserErr(err); errors.Is(err, ErrNotFound) {
				result <- answer{}
				return
			}
			result <- answer{err: err}
			return
		}
		gid, err := parseID(group.Gid, "gid")
		result <- answer{gid: gid, ok: err == nil, err: err}
	}()
	select {
	case <-ctx.Done():
		return 0, false, ctx.Err()
	case out := <-result:
		return out.gid, out.ok, out.err
	}
}

// uidVerifiedGroupIDs checks candidates, then the extra gids of named groups,
// through the Open Directory membership API, once each. The account's
// primary gid is held by its uid record.
func uidVerifiedGroupIDs(ctx context.Context, runner commandRunner, account *user.User, candidates []string, extra []int) ([]string, error) {
	uid, err := parseID(account.Uid, "uid")
	if err != nil {
		return nil, err
	}
	primary, err := parseID(account.Gid, "gid")
	if err != nil {
		return nil, err
	}
	if err := validateTrustedTool(darwinDSMemberUtil); err != nil {
		return nil, err
	}
	ids := []int{primary}
	listed := map[int]bool{primary: true}
	for _, value := range candidates {
		gid, err := parseID(value, "gid")
		if err != nil {
			return nil, err
		}
		if !listed[gid] {
			listed[gid] = true
			ids = append(ids, gid)
		}
	}
	for _, gid := range extra {
		if gid >= 0 && !listed[gid] {
			listed[gid] = true
			ids = append(ids, gid)
		}
	}
	if len(ids) > maxDirectoryGroups {
		return nil, fmt.Errorf("in %d groups, more than the %d DefenseClaw names", len(ids), maxDirectoryGroups)
	}
	verified := make([]bool, len(ids))
	verified[0] = true
	g, groupCtx := errgroup.WithContext(ctx)
	g.SetLimit(16)
	for i := 1; i < len(ids); i++ {
		i, gid := i, ids[i]
		g.Go(func() error {
			result, err := runner(groupCtx, darwinDSMemberUtil, []string{"checkmembership", "-u", strconv.Itoa(uid), "-g", strconv.Itoa(gid)})
			if err != nil {
				return err
			}
			if result.exitCode != 0 {
				return fmt.Errorf("unixidentity: dsmemberutil exited %d", result.exitCode)
			}
			switch strings.TrimSpace(string(result.stdout)) {
			case "user is a member of the group":
				verified[i] = true
			case "user is not a member of the group":
			default:
				return fmt.Errorf("unixidentity: dsmemberutil returned no membership answer")
			}
			return nil
		})
	}
	if err := g.Wait(); err != nil {
		return nil, err
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	var out []string
	for i, gid := range ids {
		if verified[i] {
			out = append(out, strconv.Itoa(gid))
		}
	}
	return out, nil
}

// parseIDGroupList parses the space-separated gids `id -G` prints, once each.
// An account in more than maxDirectoryGroups groups is an error, as on Linux:
// part of a membership must not select a profile.
func parseIDGroupList(output string) ([]string, error) {
	fields := strings.Fields(output)
	if len(fields) > maxDirectoryGroups {
		return nil, fmt.Errorf("in %d groups, more than the %d DefenseClaw names", len(fields), maxDirectoryGroups)
	}
	seen := map[int]bool{}
	var ids []string
	for _, field := range fields {
		gid, err := parseID(field, "gid")
		if err != nil {
			return nil, err
		}
		if !seen[gid] {
			seen[gid] = true
			ids = append(ids, strconv.Itoa(gid))
		}
	}
	if len(ids) == 0 {
		return nil, errors.New("unixidentity: id listed no groups")
	}
	return ids, nil
}

// accountInGroup is AccountInGroup with the candidate list and the runner
// given: it confirms gid alone, so one dsmemberutil run answers it, as the
// full list would (a candidate Open Directory confirms by uid, or the
// primary group). A list os/user could not give, or one that may be cut at
// its buffer, takes the full path.
func accountInGroup(ctx context.Context, runner commandRunner, account *user.User, ids []string, listErr error, gid int) (bool, error) {
	want := strconv.Itoa(gid)
	if account.Gid == want {
		return true, nil
	}
	if listErr == nil && len(ids) < osUserGroupBuffer {
		if !slices.Contains(ids, want) {
			return false, nil
		}
		ids = []string{want}
	}
	verified, err := platformAccountGroupIDs(ctx, runner, account, ids, listErr, nil)
	if err != nil {
		return false, err
	}
	return slices.Contains(verified, want), nil
}

func platformAccountInGroup(ctx context.Context, account *user.User, gid int) (bool, error) {
	ids, err := account.GroupIds()
	return accountInGroup(ctx, runTrustedCommand, account, ids, err, gid)
}

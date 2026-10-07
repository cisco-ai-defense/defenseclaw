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
	"strconv"
	"strings"
)

const (
	darwinID = "/usr/bin/id"
	// osUserGroupBuffer is the number of groups os/user lists into on macOS. A
	// list that fills it may be cut short.
	osUserGroupBuffer = 256
)

// platformAccountGroupIDs returns os/user's listing (ids, listErr) when it is
// complete, and lists the groups with `id -G` when it failed or filled
// os/user's buffer. id grows its buffer until getgrouplist fits, so an account
// in more than 256 groups lists whole. A listing that cannot be confirmed is
// an error, never a cut-short list: part of a membership must not select a
// profile. The name is passed after "--", so no name is read as an option.
func platformAccountGroupIDs(ctx context.Context, runner commandRunner, account *user.User, ids []string, listErr error) ([]string, error) {
	if listErr == nil && len(ids) < osUserGroupBuffer {
		return ids, nil
	}
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
	full, err := parseIDGroupList(string(result.stdout))
	if err != nil {
		return nil, errors.Join(listErr, err)
	}
	return full, nil
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

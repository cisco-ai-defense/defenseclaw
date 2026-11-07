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
	"strings"
)

// HomeAccount is a live account found at a home folder: its name and uid.
type HomeAccount struct {
	Name string
	UID  int
}

// homeAccountsLimit bounds the accounts read for one home.
const homeAccountsLimit = 32

// AccountsAtHome lists the accounts a fresh read across the whole directory
// search policy (local and bound directory nodes) finds with home as their
// home folder, in a fresh process. It is how a caller learns who holds the
// home of an account that has gone: a replacement may be a local account or a
// directory account, and its name and uid are its own. No account is an empty
// list and no error; a directory that does not answer, an unclear answer and
// every platform other than macOS are an error, so a caller never takes them
// for a free home.
func AccountsAtHome(ctx context.Context, home string) ([]HomeAccount, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	if strings.TrimSpace(home) == "" || strings.ContainsAny(home, "\n\x00") {
		return nil, errors.New("unixidentity: invalid home")
	}
	return platformAccountsAtHome(ctx, home)
}

// dsclHomeAccounts decides AccountsAtHome from dscl answers: search runs
// `dscl /Search -search /Users NFSHomeDirectory <home>` and read runs
// `dscl /Search -read /Users/<name> UniqueID`. It is shared so it can be
// tested on every platform.
func dsclHomeAccounts(search func() (commandResult, error), read func(name string) (commandResult, error)) ([]HomeAccount, error) {
	found, err := search()
	if err != nil {
		return nil, err
	}
	if found.exitCode != 0 {
		return nil, fmt.Errorf("unixidentity: dscl exited %d", found.exitCode)
	}
	var accounts []HomeAccount
	for _, name := range dsclSearchRecordNames(string(found.stdout)) {
		if len(accounts) >= homeAccountsLimit {
			return nil, errors.New("unixidentity: too many accounts at one home")
		}
		if validName(name) != nil {
			return nil, fmt.Errorf("unixidentity: unclear account name in the search answer")
		}
		result, err := read(name)
		if dsclRecordNotFound(result, err) {
			// Gone between the two reads: it holds nothing.
			continue
		}
		if err != nil {
			return nil, err
		}
		if result.exitCode != 0 {
			return nil, fmt.Errorf("unixidentity: dscl exited %d", result.exitCode)
		}
		uid, ok := dsclReadUniqueID(string(result.stdout))
		if !ok {
			return nil, errors.New("unixidentity: unclear uid in the directory answer")
		}
		accounts = append(accounts, HomeAccount{Name: name, UID: uid})
	}
	return accounts, nil
}

// dsclSearchRecordNames are the record names of a `dscl -search` answer: the
// text before the first tab of each line that starts in column zero ("name
// <tab><tab>Attribute = (" is followed by indented value lines).
func dsclSearchRecordNames(output string) []string {
	var names []string
	for _, line := range strings.Split(output, "\n") {
		if line == "" || line[0] == ' ' || line[0] == '\t' || line[0] == ')' {
			continue
		}
		name, _, ok := strings.Cut(line, "\t")
		if !ok {
			continue
		}
		if name = strings.TrimSpace(name); name != "" {
			names = append(names, name)
		}
	}
	return names
}

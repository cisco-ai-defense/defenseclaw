//go:build !windows && !linux && !darwin

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

	"github.com/defenseclaw/defenseclaw/internal/useridentity"
)

// ProcessLookupsOutliveDeletion: no such cache is known here.
const ProcessLookupsOutliveDeletion = false

// DefaultUIDRange is a conservative default for other Unix systems.
func DefaultUIDRange() (int, int) { return 1000, 60000 }

// Default returns the os/user resolver.
func Default(ctx context.Context) Resolver {
	return NewCachingResolver(NewOSUserResolver(ctx))
}

// DirectoryFactsFunc has no directory facts to offer here.
func DirectoryFactsFunc(context.Context) func(uid int) (useridentity.DirectoryFacts, bool) {
	return nil
}

func platformLocalUserLister(context.Context, commandRunner) ([]Account, error) {
	return nil, nil
}

func platformLocalAccounts(context.Context) (map[string]int, error) {
	return nil, errors.New("unixidentity: no local account reader on this platform")
}

// platformLocalDatabaseAccounts has no other local account database here.
func platformLocalDatabaseAccounts(ctx context.Context) (map[string]int, error) {
	return platformLocalAccounts(ctx)
}

func platformLocalAccountRecords(context.Context) (map[string]LocalAccountRecord, error) {
	return nil, errors.New("unixidentity: local account records are listed only on macOS")
}

func platformLocalAccountRecord(context.Context, string) (LocalAccountRecord, bool, error) {
	return LocalAccountRecord{}, false, errors.New("unixidentity: local account records are listed only on macOS")
}

// platformAccountRecordGone is false: these lookups already run in a
// fresh process (getent) or read the files backend, so a found account is
// current.
func platformAccountRecordGone(context.Context, string) bool { return false }

// platformAccountUIDGone is false for the same reason.
func platformAccountUIDGone(context.Context, string, int) bool { return false }

func platformLocalGroups(context.Context) (map[string]int, error) {
	return nil, errors.New("unixidentity: no local group reader on this platform")
}

func platformDirectoryConfigured() bool { return true }

func platformOpenDirectoryNodeStates(context.Context) (string, error) {
	return "", errors.New("unixidentity: no Open Directory on this platform")
}

func platformMobileAccounts(context.Context) (map[string]string, error) {
	return nil, errors.New("unixidentity: no local directory node on this platform")
}

func platformSSOLinkedAccounts(context.Context) (map[string]bool, error) {
	return nil, errors.New("unixidentity: no local directory node on this platform")
}

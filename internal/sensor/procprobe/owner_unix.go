// Copyright 2026 Cisco Systems, Inc. and its affiliates
// Copyright (c) 2026 Mike Storm. All rights reserved.
//
// Derived from ShadowClaw -- Universal Shadow AI Detector, by Mike Storm,
// Distinguished Engineer, CCIE Security 13847. Reimplemented in Go and
// absorbed into the DefenseClaw gateway; see NOTICE for the modifications.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
// SPDX-License-Identifier: Apache-2.0

//go:build unix

package procprobe

import (
	"context"
	"os"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/unixidentity"
)

// userCache avoids one account lookup per process per poll. A busy host has
// hundreds of processes owned by a handful of users, and the lookup can touch
// a directory service.
var userCache sync.Map // uid string -> cachedOwner

// cachedOwner is the name of a uid's account; retryAt is set when the lookup
// failed for a reason other than "no such account" (a directory service that
// does not answer), so the uid is asked again after it.
type cachedOwner struct {
	name    string
	retryAt time.Time
}

const (
	// ownerLookupTimeout bounds one account lookup.
	ownerLookupTimeout = 2 * time.Second
	// ownerRetryAfter is how long a failed lookup is kept.
	ownerRetryAfter = time.Minute
)

// ownerAccounts is the account database the owner of a process is named
// from: NSS through the root-owned getent on Linux (unixidentity.Default), as
// the hook guardian's identity records and the discovery --user filter
// resolve a uid. The release binaries are built with CGO_ENABLED=0, so os/user
// read only /etc/passwd on Linux: a directory account's process (SSSD, LDAP or
// winbind; an AD account on a joined host) had no owner, and its runtime
// finding was unattributed and listed under no --user (rel-1-0-6 GAP-0184).
// On macOS unixidentity.Default is os/user, which asks Open Directory. A
// variable for tests.
var ownerAccounts = func(ctx context.Context) unixidentity.Resolver { return unixidentity.Default(ctx) }

// ownerOf resolves the owning username of a /proc entry or process directory.
// It returns "" rather than a uid string when the name cannot be resolved,
// because a bare number is not what an operator reads in a finding.
func ownerOf(path string) string {
	info, err := os.Stat(path)
	if err != nil {
		return ""
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return ""
	}
	return ownerName(int(stat.Uid), time.Now())
}

// ownerName is the name of the account that holds uid, "" when there is
// none or the account database does not answer.
func ownerName(uid int, now time.Time) string {
	key := strconv.Itoa(uid)
	if cached, ok := userCache.Load(key); ok {
		entry := cached.(cachedOwner)
		if entry.retryAt.IsZero() || now.Before(entry.retryAt) {
			return entry.name
		}
	}
	ctx, cancel := context.WithTimeout(context.Background(), ownerLookupTimeout)
	defer cancel()
	entry := cachedOwner{}
	account, err := ownerAccounts(ctx).LookupUID(uid)
	switch {
	case err == nil:
		entry.name = strings.TrimSpace(account.Name)
	case !unixidentity.IsNotFound(err):
		entry.retryAt = now.Add(ownerRetryAfter)
	}
	userCache.Store(key, entry)
	return entry.name
}

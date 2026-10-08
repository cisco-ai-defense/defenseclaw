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

package cli

import (
	"context"
	"fmt"
	"io"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/enterprisehooks"
	"github.com/defenseclaw/defenseclaw/internal/managed"
)

// Identity spool (standalone profile, Linux and macOS). After a reconcile
// the guardian resolves the privileged directory facts of every enrolled
// account (enterprisehooks.WriteIdentitySpool) in the background, when the
// enrolled accounts changed or the refresh interval elapsed, so the gateway
// can report a verified UPN its sandbox cannot read itself.

// Successful passes refresh before the gateway's identity cache expires.
// Failed passes retry on the guardian's next one-minute reconcile tick.
const enterpriseHookIdentitySpoolInterval = 15 * time.Minute
const enterpriseHookIdentitySpoolRetryInterval = time.Minute

// enterpriseHookLoadIdentityAccounts is replaceable in tests (the record is
// root-only).
var enterpriseHookLoadIdentityAccounts = enterprisehooks.LoadUnixIdentityAccounts

var enterpriseHookIdentitySpoolState struct {
	sync.Mutex
	running     bool
	last        time.Time
	fingerprint string
	failed      bool
}

func startEnterpriseHookIdentitySpool(ctx context.Context, stderr io.Writer, run enterpriseHookReconcileRun) {
	if cfg == nil || !cfg.StandaloneEnterprise() {
		return
	}
	dir := enterprisehooks.IdentitySpoolDir(managed.HookGuardianAuthorizationDir(cfg.DataDir))
	if dir == "" {
		return
	}
	accounts := []enterprisehooks.IdentitySpoolAccount{}
	keys := []string{}
	seen := map[int]bool{}
	for _, row := range run.Rows {
		if row.UID <= 0 || row.Pending || seen[row.UID] {
			continue
		}
		seen[row.UID] = true
		accounts = append(accounts, enterprisehooks.IdentitySpoolAccount{UID: row.UID, User: row.User})
		keys = append(keys, strconv.Itoa(row.UID)+":"+row.User)
	}
	// Eligible accounts without rows, and accounts whose home is untrusted,
	// keep their identity record too: a standard user who makes his home
	// group-writable must not drop the profile assigned to his UPN to the
	// default (GAP-0714).
	if strings.TrimSpace(run.Manifest) != "" {
		extra, err := enterpriseHookLoadIdentityAccounts(enterprisehooks.UnixEligibleAccountsPath(run.Manifest))
		if err != nil {
			fmt.Fprintf(stderr, "[hook-guardian] identity spool: eligible accounts: %v\n", err)
		}
		for _, account := range extra {
			if account.UID <= 0 || seen[account.UID] {
				continue
			}
			seen[account.UID] = true
			accounts = append(accounts, enterprisehooks.IdentitySpoolAccount{UID: account.UID, User: account.User})
			keys = append(keys, strconv.Itoa(account.UID)+":"+account.User)
		}
	}
	sort.Strings(keys)
	fingerprint := strings.Join(keys, ";")
	now := time.Now()
	state := &enterpriseHookIdentitySpoolState
	state.Lock()
	interval := enterpriseHookIdentitySpoolInterval
	if state.failed {
		interval = enterpriseHookIdentitySpoolRetryInterval
	}
	// The interval runs on the monotonic clock, but the gateway trusts a
	// record by its wall-clock age: after a clock step the records are
	// rewritten at the next one-minute tick (GAP-0921).
	_, stepped := enterprisehooks.IdentitySpoolStale(dir, now, enterpriseHookIdentitySpoolInterval+2*enterpriseHookIdentitySpoolRetryInterval)
	due := !state.running && (fingerprint != state.fingerprint || now.Sub(state.last) >= interval || stepped)
	if due {
		state.running = true
	}
	state.Unlock()
	if !due {
		return
	}
	go func() {
		var passErr error
		defer func() {
			state.Lock()
			state.running = false
			state.last = time.Now()
			state.fingerprint = fingerprint
			state.failed = passErr != nil
			state.Unlock()
		}()
		if err := ensureEnterpriseHookStandaloneAuthDir(managed.HookGuardianAuthorizationDir(cfg.DataDir)); err != nil {
			passErr = err
			fmt.Fprintf(stderr, "[hook-guardian] identity spool: %v\n", err)
			return
		}
		logf := func(format string, args ...any) { fmt.Fprintf(stderr, format+"\n", args...) }
		passErr = enterprisehooks.WriteIdentitySpool(ctx, dir, accounts, enterpriseHookAuthorizationOwnershipSetter, logf)
		if passErr != nil {
			fmt.Fprintf(stderr, "[hook-guardian] identity spool: %v\n", passErr)
		}
	}()
}

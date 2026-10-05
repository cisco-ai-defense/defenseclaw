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

// enterpriseHookIdentitySpoolInterval matches the gateway's identity cache
// lifetime, so the gateway's refresh always finds a current record.
const enterpriseHookIdentitySpoolInterval = 15 * time.Minute

var enterpriseHookIdentitySpoolState struct {
	sync.Mutex
	running     bool
	last        time.Time
	fingerprint string
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
	sort.Strings(keys)
	fingerprint := strings.Join(keys, ";")
	now := time.Now()
	state := &enterpriseHookIdentitySpoolState
	state.Lock()
	due := !state.running && (fingerprint != state.fingerprint || now.Sub(state.last) >= enterpriseHookIdentitySpoolInterval)
	if due {
		state.running, state.last, state.fingerprint = true, now, fingerprint
	}
	state.Unlock()
	if !due {
		return
	}
	go func() {
		defer func() {
			state.Lock()
			state.running = false
			state.Unlock()
		}()
		if err := ensureEnterpriseHookStandaloneAuthDir(managed.HookGuardianAuthorizationDir(cfg.DataDir)); err != nil {
			fmt.Fprintf(stderr, "[hook-guardian] identity spool: %v\n", err)
			return
		}
		logf := func(format string, args ...any) { fmt.Fprintf(stderr, format+"\n", args...) }
		if err := enterprisehooks.WriteIdentitySpool(ctx, dir, accounts, enterpriseHookAuthorizationOwnershipSetter, logf); err != nil {
			fmt.Fprintf(stderr, "[hook-guardian] identity spool: %v\n", err)
		}
	}()
}

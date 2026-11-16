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
	"errors"
	"fmt"
	"os"
	"os/user"
	"strconv"
	"sync"
	"syscall"
	"time"
)

// setEnterpriseHookAuthorizationOwnership keeps the root-written guardian
// authorization record readable by the unprivileged defenseclaw gateway while
// excluding unrelated local users. Non-root development/test invocations keep
// their existing ownership and are still protected by the 0750/0640 modes.
//
// On installs where the daemon runs as root (managed_enterprise on macOS
// since the CMID switch — the shipped plist omits UserName/GroupName so
// launchd defaults to uid 0), there is no defenseclaw service user. The
// authorization file is already root-owned 0640, which root can read; the
// service-user chgrp is a leftover from the pre-root era and must not fail
// the whole reconcile when the user is absent.
func setEnterpriseHookAuthorizationOwnership(path string) error {
	if os.Geteuid() != 0 {
		return nil
	}
	serviceUserName := "defenseclaw"
	if enterpriseHooksStandaloneUnixActive() {
		serviceUserName = enterpriseHookStandaloneServiceUser()
	}
	gid, err := enterpriseHookServiceGroup(serviceUserName)
	if err != nil {
		// No service user on this host — the daemon runs as root and
		// reads the 0640 file via its owner bit. Nothing to align. The
		// standalone gateway never runs as root, so its account must
		// exist.
		var unknown user.UnknownUserError
		if errors.As(err, &unknown) && !enterpriseHooksStandaloneUnixActive() {
			return nil
		}
		return err
	}
	if err := os.Chown(path, 0, gid); err != nil {
		return err
	}
	return verifyEnterpriseHookRecordOwnership(path, gid)
}

// verifyEnterpriseHookRecordOwnership checks that path is root's and in
// group gid, the service account's group the gateway reads it through.
func verifyEnterpriseHookRecordOwnership(path string, gid int) error {
	info, err := os.Stat(path)
	if err != nil {
		return err
	}
	st, ok := info.Sys().(*syscall.Stat_t)
	if !ok || st.Uid != 0 || int64(st.Gid) != int64(gid) {
		return fmt.Errorf("%s is not owned by root and group %d", path, gid)
	}
	return nil
}

// enterpriseHookServiceGroupLookupTimeout bounds the service account lookup
// of a guardian record write. NSS and Directory Services take no context,
// and a removal ledger write runs under the account's removal lock, which
// must not wait on them without end.
var enterpriseHookServiceGroupLookupTimeout = 15 * time.Second

// enterpriseHookServiceUserLookup is user.Lookup. Replaceable in tests.
var enterpriseHookServiceUserLookup = user.Lookup

// enterpriseHookServiceGroups holds the group of each service account found,
// for the life of the guardian process: once a write has published a
// record, the writes after it make no directory call.
var (
	enterpriseHookServiceGroupsMu sync.Mutex
	enterpriseHookServiceGroups   = map[string]int{}
)

type enterpriseHookServiceGroupAnswer struct {
	gid int
	err error
}

// enterpriseHookServiceGroup returns the primary group of service account
// name, within enterpriseHookServiceGroupLookupTimeout, one lookup at a time
// per account. A lookup error is returned as it is.
func enterpriseHookServiceGroup(name string) (int, error) {
	enterpriseHookServiceGroupsMu.Lock()
	gid, ok := enterpriseHookServiceGroups[name]
	enterpriseHookServiceGroupsMu.Unlock()
	if ok {
		return gid, nil
	}
	lookupUser := enterpriseHookServiceUserLookup
	lookup := startEnterpriseHookLookup("service-group\x00"+name, func() any {
		serviceUser, err := lookupUser(name)
		if err != nil {
			return enterpriseHookServiceGroupAnswer{err: err}
		}
		gid, err := strconv.Atoi(serviceUser.Gid)
		return enterpriseHookServiceGroupAnswer{gid: gid, err: err}
	})
	timer := time.NewTimer(enterpriseHookServiceGroupLookupTimeout)
	defer timer.Stop()
	select {
	case <-lookup.done:
	case <-timer.C:
		return 0, fmt.Errorf("the service account %s did not resolve within %s", name, enterpriseHookServiceGroupLookupTimeout)
	}
	answer, _ := lookup.value.(enterpriseHookServiceGroupAnswer)
	if answer.err != nil {
		return 0, answer.err
	}
	enterpriseHookServiceGroupsMu.Lock()
	enterpriseHookServiceGroups[name] = answer.gid
	enterpriseHookServiceGroupsMu.Unlock()
	return answer.gid, nil
}

// enterpriseHookLookup is one running lookup that takes no context; value
// is set before done is closed.
type enterpriseHookLookup struct {
	done  chan struct{}
	value any
}

// enterpriseHookLookups are the lookups still running, by key, so a
// stalled directory holds one lookup per key, not one per caller.
var (
	enterpriseHookLookupsMu sync.Mutex
	enterpriseHookLookups   = map[string]*enterpriseHookLookup{}
)

// startEnterpriseHookLookup runs fn for key, or joins the run for key that
// has not ended. The caller bounds how long it waits for done.
func startEnterpriseHookLookup(key string, fn func() any) *enterpriseHookLookup {
	enterpriseHookLookupsMu.Lock()
	defer enterpriseHookLookupsMu.Unlock()
	if lookup := enterpriseHookLookups[key]; lookup != nil {
		return lookup
	}
	lookup := &enterpriseHookLookup{done: make(chan struct{})}
	enterpriseHookLookups[key] = lookup
	go func() {
		defer func() {
			enterpriseHookLookupsMu.Lock()
			delete(enterpriseHookLookups, key)
			enterpriseHookLookupsMu.Unlock()
			close(lookup.done)
		}()
		lookup.value = fn()
	}()
	return lookup
}

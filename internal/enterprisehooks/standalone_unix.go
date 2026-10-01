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

package enterprisehooks

import (
	"context"
	"fmt"
	"os"
	"sync"
	"sync/atomic"

	"github.com/defenseclaw/defenseclaw/internal/unixidentity"
)

// standaloneUnixMode switches this process to the standalone managed
// profile's Unix rules: directory-backed accounts resolve through NSS,
// Unix manifests may carry deferred rows, and user homes are never mutated
// from a root process (the per-user apply-target worker does it with the
// user's own credentials). It is off by default, so the Secure Client
// macOS guardian keeps its exact behavior.
var standaloneUnixMode atomic.Bool

var (
	standaloneResolverMu sync.Mutex
	standaloneResolverV  unixidentity.Resolver
)

// SetStandaloneUnix enables or disables the standalone Unix rules for the
// current process. Callers set it once from the resolved enterprise
// profile, before any manifest load or target resolution.
func SetStandaloneUnix(enabled bool) {
	standaloneUnixMode.Store(enabled)
}

// StandaloneUnix reports whether the standalone Unix rules are active.
func StandaloneUnix() bool {
	return standaloneUnixMode.Load()
}

// standaloneProfileProcess reports whether this process serves the
// standalone profile: the standalone guardian, enumerator and per-user
// worker set the mode; the Secure Client macOS guardian never does.
func standaloneProfileProcess() bool {
	return StandaloneUnix()
}

// SetStandaloneResolver replaces the NSS/Directory Services resolver used
// by the standalone rules. Tests and the CLI use it to share one cached
// resolver per cycle.
func SetStandaloneResolver(resolver unixidentity.Resolver) {
	standaloneResolverMu.Lock()
	defer standaloneResolverMu.Unlock()
	standaloneResolverV = resolver
}

// StandaloneResolver returns the standalone resolver, creating the
// platform default on first use.
func StandaloneResolver() unixidentity.Resolver {
	standaloneResolverMu.Lock()
	defer standaloneResolverMu.Unlock()
	if standaloneResolverV == nil {
		standaloneResolverV = unixidentity.Default(context.Background())
	}
	return standaloneResolverV
}

// refuseStandaloneRootInProcess keeps a root standalone guardian from
// touching a user home in-process. Every user-path Lstat/remove/chmod must
// run with the user's kernel permissions in the apply-target worker, which
// removes the check-then-act races of a root caller and the process-wide
// Seteuid drop that LockOSThread cannot confine.
func refuseStandaloneRootInProcess(operation string) error {
	if StandaloneUnix() && os.Geteuid() == 0 {
		return fmt.Errorf("enterprise hooks: standalone guardians %s user hooks only through the per-user apply-target worker, never in a root process", operation)
	}
	return nil
}

// standaloneLookupPrimaryGID resolves a uid's primary gid through NSS or
// Directory Services for the standalone profile.
func standaloneLookupPrimaryGID(uid int) (int, error) {
	account, err := StandaloneResolver().LookupUID(uid)
	if err != nil {
		return 0, err
	}
	return account.GID, nil
}

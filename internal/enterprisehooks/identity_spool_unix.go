// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package enterprisehooks

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"time"
)

// IdentitySpoolAccount is one enrolled account the guardian resolves.
type IdentitySpoolAccount struct {
	UID  int
	User string
}

// identitySpoolLookupTimeout bounds the privileged lookups for one account,
// so one unreachable directory cannot stall the guardian's pass.
const identitySpoolLookupTimeout = 10 * time.Second

// WriteIdentitySpool resolves every account's privileged directory facts
// and replaces dir's records with them: a record per account, and none for
// an account no longer enrolled. setOwnership gives each new file (and the
// directory) the guardian authorization ownership, root:<gateway group>,
// before it is renamed into place, so the gateway never reads a partial or
// unreadable record. A failed privileged lookup keeps a previous verified
// record; a newly enrolled account gets its basic facts until retry succeeds.
//
// The record of an account missing from accounts is removed only once it is
// older than IdentitySpoolMaxAge, when the gateway ignores it anyway. A pass
// that could not decide an account (the enumerator drops AD accounts whose
// home owner does not resolve while the domain controller is unreachable)
// would otherwise delete the UPN and directory facts of every such account,
// and the gateway would report them without those until the next pass
// (GAP-0145).
func WriteIdentitySpool(ctx context.Context, dir string, accounts []IdentitySpoolAccount, setOwnership func(string) error, logf func(string, ...any)) error {
	if dir == "" {
		return nil
	}
	if err := os.MkdirAll(dir, 0o750); err != nil {
		return fmt.Errorf("create identity spool: %w", err)
	}
	if err := os.Chmod(dir, 0o750); err != nil {
		return fmt.Errorf("harden identity spool: %w", err)
	}
	if setOwnership != nil {
		if err := setOwnership(dir); err != nil {
			return fmt.Errorf("set identity spool ownership: %w", err)
		}
	}
	keep := map[string]bool{}
	var passErr error
	for _, account := range accounts {
		if account.UID <= 0 || keep[strconv.Itoa(account.UID)+".json"] {
			continue
		}
		name := strconv.Itoa(account.UID) + ".json"
		keep[name] = true
		lookupCtx, cancel := context.WithTimeout(ctx, identitySpoolLookupTimeout)
		record, err := collectIdentitySpoolRecord(lookupCtx, account, time.Now().UTC())
		cancel()
		if err == nil {
			err = writeIdentitySpoolFile(dir, name, record, setOwnership)
		} else if record.Key != "" {
			// Keep a previous verified UPN through a transient lookup
			// failure. For a newly enrolled account, still provide its
			// basic NSS facts while the privileged lookup is retried.
			if _, statErr := os.Stat(filepath.Join(dir, name)); errors.Is(statErr, os.ErrNotExist) {
				err = errors.Join(err, writeIdentitySpoolFile(dir, name, record, setOwnership))
			} else if statErr != nil {
				err = errors.Join(err, statErr)
			}
		}
		if err != nil {
			passErr = errors.Join(passErr, fmt.Errorf("uid %d: %w", account.UID, err))
			if logf != nil {
				logf("[hook-guardian] identity facts for uid %d: %v", account.UID, err)
			}
		}
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		return errors.Join(passErr, fmt.Errorf("read identity spool: %w", err))
	}
	for _, entry := range entries {
		if keep[entry.Name()] {
			continue
		}
		if info, err := entry.Info(); err == nil && time.Since(info.ModTime()) < IdentitySpoolMaxAge {
			continue
		}
		_ = os.RemoveAll(filepath.Join(dir, entry.Name()))
	}
	return passErr
}

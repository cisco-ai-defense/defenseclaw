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
	"strings"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/useridentity"
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
// record only while it still names the same account (the gateway checks the
// name again); a newly enrolled or reassigned account gets its basic facts
// until a retry succeeds.
//
// The record of an account missing from accounts goes after a pass in which
// every listed account resolved: the account left the enrollment (excluded,
// out of the manifest) or was deleted, nothing refreshes its record again,
// and status and verify warned identity_records_stale about it 30 minutes
// later (GAP-1113, GAP-1103). A directory account's record stays until it is
// older than IdentitySpoolMaxAge, when the gateway ignores it anyway, unless
// the pass also resolved a directory account: while the domain controller is
// unreachable the enumerator drops the AD accounts whose home owner does not
// resolve, and deleting their records would take their UPN and directory
// facts until the next pass (GAP-0145). A failed pass removes nothing young.
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
	directoryAnswered := false
	for _, account := range accounts {
		if account.UID <= 0 || keep[strconv.Itoa(account.UID)+".json"] {
			continue
		}
		name := strconv.Itoa(account.UID) + ".json"
		if account.User != "" {
			if previous, err := ReadIdentitySpoolRecord(dir, strconv.Itoa(account.UID), nil); err == nil &&
				previous.User != "" && !strings.EqualFold(previous.User, account.User) {
				// A UID assigned to a different account must not retain its
				// previous owner's privileged facts if this lookup fails.
				if err := os.Remove(filepath.Join(dir, name)); err != nil {
					return fmt.Errorf("remove reassigned identity spool record: %w", err)
				}
			}
		}
		keep[name] = true
		lookupCtx, cancel := context.WithTimeout(ctx, identitySpoolLookupTimeout)
		record, err := collectIdentitySpoolRecord(lookupCtx, account, time.Now().UTC())
		cancel()
		if err == nil {
			err = writeIdentitySpoolFile(dir, name, record, setOwnership)
			directoryAnswered = directoryAnswered || err == nil && identitySpoolDirectoryRecord(record)
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
		if info, err := entry.Info(); err == nil && time.Since(info.ModTime()) < IdentitySpoolMaxAge &&
			(passErr != nil || !identitySpoolRecordLeft(dir, entry, directoryAnswered)) {
			continue
		}
		_ = os.RemoveAll(filepath.Join(dir, entry.Name()))
	}
	return passErr
}

// identitySpoolRecordLeft reports whether entry, the young record of an
// account a successful pass did not list, belongs to an account that left:
// a local account, or a directory account while the directory answers (a
// listed directory account resolved in the pass). An unreadable record goes
// too. Any other file (a temporary one) waits for IdentitySpoolMaxAge.
func identitySpoolRecordLeft(dir string, entry os.DirEntry, directoryAnswered bool) bool {
	key, ok := strings.CutSuffix(entry.Name(), ".json")
	if !ok || !entry.Type().IsRegular() || !validIdentitySpoolKey(key) {
		return false
	}
	record, err := ReadIdentitySpoolRecord(dir, key, nil)
	return err != nil || directoryAnswered || !identitySpoolDirectoryRecord(record)
}

// identitySpoolDirectoryRecord reports whether record is a directory
// account's (SSSD, winbind, LDAP, an AD-bound Mac) rather than a local one.
func identitySpoolDirectoryRecord(record IdentitySpoolRecord) bool {
	facts := record.Facts
	if facts.Directory != "" {
		return facts.Directory != useridentity.DirectoryLocal
	}
	return record.SSSDDomain != "" || facts.Realm != "" || facts.Domain != "" || facts.UPN != ""
}

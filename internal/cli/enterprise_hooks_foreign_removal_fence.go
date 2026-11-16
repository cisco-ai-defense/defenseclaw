// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"context"
	"errors"
	"os"
	"time"
)

// enterpriseForeignHookCleanupFence is one cleanup's way to commit each of
// its removals (enterpriseForeignHookRemovalTx): lock opens the commit for
// one change of paths (the account's removal lock, the key rotation and
// the first ledger record), commit records what the change removed and
// lets go of the lock.
type enterpriseForeignHookCleanupFence interface {
	lock(connector string, paths []string) error
	commit(connector string, removed []string) error
}

// enterpriseForeignHookRemovalGuard is the GuardRemoval of one connector's
// cleanup. Each removal opens its commit, runs, commits and lets go before
// the cleanup reads anything else, so a scan never holds the account's
// lock. Once a commit cannot open, or a commit fails, the cleanup's later
// removals are refused without waiting again: those hooks stay in place,
// reported, and the guard keeps denying.
func enterpriseForeignHookRemovalGuard(connector string, fence enterpriseForeignHookCleanupFence) func([]string, func() error) error {
	var refused error
	return func(paths []string, remove func() error) error {
		if refused != nil {
			return refused
		}
		if err := fence.lock(connector, paths); err != nil {
			refused = err
			return err
		}
		removeErr := remove()
		var removed []string
		if removeErr == nil {
			removed = paths
		}
		if err := fence.commit(connector, removed); err != nil {
			refused = err
			return errors.Join(removeErr, err)
		}
		return removeErr
	}
}

// enterpriseForeignHookInProcessQueueWait bounds an in-process cleanup's
// wait to open a commit.
const enterpriseForeignHookInProcessQueueWait = 2 * time.Minute

// enterpriseForeignHookInProcessFence commits the removals of a cleanup the
// guardian runs in process with the user's identity
// (enterpriseForeignHookRunAsTarget, the Windows reconcile and its
// machine-policy pass). Its lock and commit act as the guardian
// (enterpriseForeignHookAsGuardian).
type enterpriseForeignHookInProcessFence struct {
	account, home string
	tx            *enterpriseForeignHookRemovalTx
	committed     map[string]bool
}

func newEnterpriseForeignHookInProcessFence(account, home string) *enterpriseForeignHookInProcessFence {
	return &enterpriseForeignHookInProcessFence{account: account, home: home, committed: map[string]bool{}}
}

func (f *enterpriseForeignHookInProcessFence) lock(connector string, paths []string) error {
	if f.tx != nil {
		return errors.New("foreign-hook removal: this cleanup already holds the account's lock")
	}
	return enterpriseForeignHookAsGuardian(func() error {
		ctx, cancel := context.WithTimeout(context.Background(), enterpriseForeignHookInProcessQueueWait)
		defer cancel()
		tx, err := beginEnterpriseForeignHookRemoval(ctx, os.Stderr, f.account, f.home, connector, paths)
		if err == nil {
			f.tx = tx
		}
		return err
	})
}

// commit records removed and lets go of the account's lock, even when the
// record could not be written (the first record, made before the change,
// still denies).
func (f *enterpriseForeignHookInProcessFence) commit(_ string, removed []string) error {
	if f.tx == nil {
		return errors.New("foreign-hook removal: this cleanup does not hold the account's lock")
	}
	tx := f.tx
	f.tx = nil
	return enterpriseForeignHookAsGuardian(func() error {
		err := tx.commit(removed)
		for _, path := range removed {
			f.committed[path] = true
		}
		return err
	})
}

// release ends a commit this cleanup opened and never committed.
func (f *enterpriseForeignHookInProcessFence) release() {
	if f.tx != nil {
		tx := f.tx
		f.tx = nil
		_ = enterpriseForeignHookAsGuardian(func() error { return tx.commit(nil) })
	}
}

// uncommitted lists the files of removed that no commit recorded.
func (f *enterpriseForeignHookInProcessFence) uncommitted(removed []string) []string {
	var out []string
	for _, path := range removed {
		if !f.committed[path] {
			out = append(out, path)
		}
	}
	return out
}

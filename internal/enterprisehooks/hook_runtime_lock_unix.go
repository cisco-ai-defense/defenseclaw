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
	"syscall"
	"time"
)

// sharedHookRuntimeLockPoll is how often a run waiting for the shared hook
// runtime lock tries again.
const sharedHookRuntimeLockPoll = 50 * time.Millisecond

// lockSharedHookRuntime takes the account's shared hook runtime lock, an
// exclusive flock on the home directory, which keeps its inode while the
// account exists. Install holds it from writing the hook scripts every
// connector shares to recording its connector in the hook contract lock,
// and the removal of an account's last connector holds it while it checks
// that no connector uses that runtime and removes it, so the removal cannot
// take the scripts of an install in progress. It waits until ctx ends. A
// file system without locks (some network homes) runs unlocked, as before.
// Run it as the account (withOwnerCredentials).
func lockSharedHookRuntime(ctx context.Context, home string) (unlock func(), err error) {
	dir, err := os.Open(home)
	if err != nil {
		return nil, fmt.Errorf("enterprise hooks: open the home to lock the shared hook runtime: %w", err)
	}
	if info, err := dir.Stat(); err != nil || !info.IsDir() {
		_ = dir.Close()
		return nil, fmt.Errorf("enterprise hooks: lock the shared hook runtime: %s is not a directory", home)
	}
	for {
		err := syscall.Flock(int(dir.Fd()), syscall.LOCK_EX|syscall.LOCK_NB)
		switch {
		case err == nil:
			return func() {
				_ = syscall.Flock(int(dir.Fd()), syscall.LOCK_UN)
				_ = dir.Close()
			}, nil
		case errors.Is(err, syscall.ENOLCK), errors.Is(err, syscall.EOPNOTSUPP), errors.Is(err, syscall.ENOTSUP):
			return func() { _ = dir.Close() }, nil
		case !errors.Is(err, syscall.EWOULDBLOCK) && !errors.Is(err, syscall.EINTR):
			_ = dir.Close()
			return nil, fmt.Errorf("enterprise hooks: lock the shared hook runtime: %w", err)
		}
		select {
		case <-ctx.Done():
			_ = dir.Close()
			return nil, fmt.Errorf("enterprise hooks: waiting for another DefenseClaw hook install or removal of this account: %w", ctx.Err())
		case <-time.After(sharedHookRuntimeLockPoll):
		}
	}
}

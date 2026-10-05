// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package cli

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"syscall"
	"time"
)

const hookColdStartSupported = true

// acquireGatewayStartLock takes the per-data-directory start lock so a hook
// cold start, a manual start and a restart cannot launch two gateways at
// once. The loser waits, then finds the winner's gateway already running. A
// data directory that does not exist yet, or a lock file this account cannot
// open, runs unlocked as before.
func acquireGatewayStartLock(dataDir string, wait time.Duration) (func(), error) {
	path := filepath.Join(dataDir, gatewayStartLockName)
	f, err := os.OpenFile(path, os.O_CREATE|os.O_RDONLY|syscall.O_NOFOLLOW, 0o600)
	if err != nil {
		return func() {}, nil
	}
	deadline := time.Now().Add(wait)
	for {
		err = syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB)
		if err == nil {
			return func() {
				_ = syscall.Flock(int(f.Fd()), syscall.LOCK_UN)
				_ = f.Close()
			}, nil
		}
		if !errors.Is(err, syscall.EWOULDBLOCK) && !errors.Is(err, syscall.EAGAIN) {
			_ = f.Close()
			return func() {}, nil
		}
		if time.Now().After(deadline) {
			_ = f.Close()
			return nil, fmt.Errorf("another gateway start is still in progress after %s (%s)", wait, path)
		}
		time.Sleep(100 * time.Millisecond)
	}
}

// liftHookResourceLimits undoes the soft limits the shell hook set on itself
// (CPU seconds, address space, open files) so the gateway it starts does not
// inherit them. Soft limits rise only to the hard limits already in place.
func liftHookResourceLimits() {
	for _, resource := range []int{syscall.RLIMIT_CPU, syscall.RLIMIT_AS} {
		var limit syscall.Rlimit
		if err := syscall.Getrlimit(resource, &limit); err == nil && limit.Cur != limit.Max {
			limit.Cur = limit.Max
			_ = syscall.Setrlimit(resource, &limit)
		}
	}
	// The Go runtime already raised this process's open-file soft limit, but
	// would hand children the hook's original one. Setting it explicitly
	// makes the raised value the one the gateway inherits.
	var files syscall.Rlimit
	if err := syscall.Getrlimit(syscall.RLIMIT_NOFILE, &files); err == nil {
		_ = syscall.Setrlimit(syscall.RLIMIT_NOFILE, &files)
	}
}

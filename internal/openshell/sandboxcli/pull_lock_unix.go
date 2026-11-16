// Copyright 2026 Cisco Systems, Inc. and its affiliates
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

package sandboxcli

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"syscall"
	"time"
)

// pullLockFile, next to the session leases, orders the pulls of one
// sandbox: two at once (a session's end and a `sandbox pull`, or two
// terminals' session ends) ran git in the same sandbox copy, and the second
// failed on git's index lock ("Another git process seems to be running").
const pullLockFile = ".pull"

// pullLockWait bounds the wait for another pull of the sandbox.
var pullLockWait = 10 * time.Minute

// lockPull holds sandbox name's pull lock until release, waiting up to
// pullLockWait for a pull another command makes.
func (a *App) lockPull(ctx context.Context, name string) (release func(), err error) {
	dir, err := a.sessionsDir(name)
	if err != nil {
		return nil, err
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, err
	}
	f, err := os.OpenFile(filepath.Join(dir, pullLockFile), os.O_CREATE|os.O_RDWR|syscall.O_NOFOLLOW, 0o600)
	if err != nil {
		return nil, err
	}
	deadline := time.Now().Add(pullLockWait)
	waiting := false
	for {
		err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB)
		if err == nil {
			break
		}
		if !errors.Is(err, syscall.EWOULDBLOCK) {
			_ = f.Close()
			return nil, err
		}
		if !waiting {
			waiting = true
			a.note("another pull of " + name + " is running; waiting for it to end…")
		}
		if time.Now().After(deadline) {
			_ = f.Close()
			return nil, fmt.Errorf("another pull of %s kept running for %s", name, pullLockWait)
		}
		t := time.NewTimer(sandboxGatePoll)
		select {
		case <-ctx.Done():
			t.Stop()
			_ = f.Close()
			return nil, ctx.Err()
		case <-t.C:
		}
	}
	return func() {
		_ = syscall.Flock(int(f.Fd()), syscall.LOCK_UN)
		_ = f.Close()
	}, nil
}

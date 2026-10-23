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

package openshell

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"time"
)

// lifecycleLockFile, in the account's OpenShell configuration directory,
// keeps DefenseClaw from creating, starting, attaching to, stopping or
// deleting a sandbox on the account's gateway while DefenseClaw restarts,
// upgrades or rolls back that gateway: the restart's or the upgrade's check
// of the sandboxes holds only until one starts, and an upgrade's restart
// comes minutes after it. A restart, an upgrade or a rollback holds it
// exclusively from its check to the healthy gateway after it
// (LockGatewayLifecycle); a create or a start holds it shared over
// OpenShell's call (LockSandboxStart), so a sandbox started before the
// check is in the list the check reads, and one started after waits; a
// session's attach and a stop or a delete hold it shared with the
// sandbox's own gate (LockGatewayShared). It is advisory, between
// DefenseClaw processes of the account (the CLI and its sandbox daemon):
// another OpenShell client, a raw `openshell sandbox start` for one, is not
// held back, which is why every restart checks OpenShell's own account of
// the sandboxes last, right before it, and why a raw start during a
// DefenseClaw rollback is unsupported.
const lifecycleLockFile = ".defenseclaw-lifecycle.lock"

// ErrGatewayBusy refuses a create or a start while DefenseClaw restarts,
// upgrades or rolls back the OpenShell gateway, an attach, a stop or a
// delete that waited for one past lifecycleLockWait, and a restart, an
// upgrade or a rollback while another is under way or a create, a start,
// an attach, a stop or a delete does not end in time.
var ErrGatewayBusy = errors.New("openshell: DefenseClaw is restarting or upgrading the OpenShell gateway")

// lifecycleLockWait bounds how long a restart or an upgrade waits for the
// creates and starts in flight, each of which holds the lock only for
// OpenShell's call.
var lifecycleLockWait = 2 * time.Minute

// lifecycleLockPoll is how often that wait tries the lock again.
const lifecycleLockPoll = 100 * time.Millisecond

// lifecycleLockPath is the lock file of the OpenShell configuration
// directory dir ("" is UserConfigDir). create makes a missing directory
// (owner only), as a restart or an upgrade does; otherwise a missing one
// is "": no gateway is registered there, and no restart or upgrade, which
// makes it first, holds the lock.
func lifecycleLockPath(dir string, create bool) (string, error) {
	if dir == "" {
		var err error
		if dir, err = UserConfigDir(); err != nil {
			return "", err
		}
	}
	dir, err := resolveConfigDir(dir)
	if err != nil {
		return "", err
	}
	if create {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			return "", fmt.Errorf("openshell: create %s for the gateway lifecycle lock: %w", dir, err)
		}
	} else if _, err := os.Stat(dir); errors.Is(err, fs.ErrNotExist) {
		return "", nil
	}
	return filepath.Join(dir, lifecycleLockFile), nil
}

// LockGatewayLifecycle takes the lifecycle lock of the OpenShell
// configuration directory dir ("" is UserConfigDir) for a restart or an
// upgrade of its gateway, waiting for the creates and starts in flight,
// up to lifecycleLockWait (ErrGatewayBusy after it) or the end of ctx.
// unlock releases it.
func LockGatewayLifecycle(ctx context.Context, dir string) (unlock func(), err error) {
	path, err := lifecycleLockPath(dir, true)
	if err != nil {
		return nil, err
	}
	deadline := time.Now().Add(lifecycleLockWait)
	for {
		u, lerr := tryLockFile(path, true)
		if !errors.Is(lerr, errLockHeld) {
			return u, lerr
		}
		if time.Now().After(deadline) {
			return nil, fmt.Errorf("%w: another restart, upgrade or rollback, or a sandbox create, start, attach, stop or delete, held it for %s; try again once it is done", ErrGatewayBusy, lifecycleLockWait)
		}
		t := time.NewTimer(lifecycleLockPoll)
		select {
		case <-ctx.Done():
			t.Stop()
			return nil, ctx.Err()
		case <-t.C:
		}
	}
}

// LockSandboxStart takes the lifecycle lock of the OpenShell configuration
// directory dir ("" is UserConfigDir) for a create or a start of a sandbox,
// shared with the others, and refuses with ErrGatewayBusy at once while a
// restart or an upgrade holds it. unlock releases it. A directory that
// does not exist holds no lock (lifecycleLockPath).
func LockSandboxStart(dir string) (unlock func(), err error) {
	path, err := lifecycleLockPath(dir, false)
	if err != nil {
		return nil, err
	}
	if path == "" {
		return func() {}, nil
	}
	unlock, err = tryLockFile(path, false)
	if errors.Is(err, errLockHeld) {
		return nil, ErrGatewayBusy
	}
	return unlock, err
}

// LockGatewayShared takes the lifecycle lock of the OpenShell
// configuration directory dir ("" is UserConfigDir) shared, waiting up to
// lifecycleLockWait for a restart, an upgrade or a rollback that holds it
// (ErrGatewayBusy after it, the end of ctx before it). DefenseClaw's
// sandbox commands hold it while they attach a session to a sandbox and
// while they stop or delete one (sandboxcli's per-sandbox gate), so a
// gateway restart, which holds it exclusively from its last check of the
// sandboxes to the healthy gateway, is the exclusive lock of every sandbox
// of the account. unlock releases it. A directory that does not exist
// holds no lock (lifecycleLockPath).
func LockGatewayShared(ctx context.Context, dir string) (unlock func(), err error) {
	path, err := lifecycleLockPath(dir, false)
	if err != nil {
		return nil, err
	}
	if path == "" {
		return func() {}, nil
	}
	deadline := time.Now().Add(lifecycleLockWait)
	for {
		u, lerr := tryLockFile(path, false)
		if !errors.Is(lerr, errLockHeld) {
			return u, lerr
		}
		if time.Now().After(deadline) {
			return nil, fmt.Errorf("%w: it held the lifecycle lock for %s; once it is done, retry the sandbox command", ErrGatewayBusy, lifecycleLockWait)
		}
		t := time.NewTimer(lifecycleLockPoll)
		select {
		case <-ctx.Done():
			t.Stop()
			return nil, ctx.Err()
		case <-t.C:
		}
	}
}

// LifecycleDrained is the line `defenseclaw-gateway sandbox-daemon drain`
// prints once it holds the account's lifecycle lock (LockGatewayLifecycle)
// and found nothing a stop of the account's gateway would end with no
// flush (CheckAccountGateways): the managed lifecycle, which runs it as the
// account, stops the account's units only after it, and lets the drain go
// once they are stopped.
const LifecycleDrained = "defenseclaw: OpenShell gateway lifecycle held, nothing to flush"

// CheckAccountGateways is the check a drain makes before the managed
// lifecycle stops the account's gateway: every local gateway registered for
// the account (RegistrationNames) must report each sandbox on it stopped
// (CheckSandboxesStopped, which refuses one it cannot read unless no
// MicroVM runs as the account), and no MicroVM may run as the account
// (vms), whatever gateway or client started it.
func CheckAccountGateways(ctx context.Context, vms VMCount) error {
	for _, name := range RegistrationNames(DiscoverOptions{}) {
		reg, err := Discover(DiscoverOptions{Gateway: name})
		if err != nil {
			if rerr := unreachableRefusal(ctx, ErrUnflushed, fmt.Errorf("the registration %s is not usable: %w", name, err), vms, "try again"); rerr != nil {
				return rerr
			}
			continue
		}
		if !reg.Local() {
			continue
		}
		c, err := Dial(reg, ClientOptions{RPCTimeout: 10 * time.Second})
		if err != nil {
			if rerr := unreachableRefusal(ctx, ErrUnflushed, fmt.Errorf("no connection to %s: %w", name, err), vms, "try again"); rerr != nil {
				return rerr
			}
			continue
		}
		err = CheckSandboxesStopped(ctx, c, vms)
		_ = c.Close()
		if err != nil {
			return fmt.Errorf("gateway %s: %w", name, err)
		}
	}
	n, err := vms(ctx)
	switch {
	case err != nil:
		return fmt.Errorf("%w (the MicroVMs of this account could not be counted: %v); try again", ErrUnflushed, err)
	case n > 0:
		return fmt.Errorf("%w (%s run as this account, which the gateway's stop would end with no flush); stop them, then try again",
			ErrUnflushed, plural(n, "MicroVM", "MicroVMs"))
	}
	return nil
}

// errLockHeld is a lock another holder keeps.
var errLockHeld = errors.New("openshell: lock held")

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
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/openshell"
)

// Attached sessions. Several sessions can attach to one sandbox (a `run`
// that resumes it, a `connect`, a `connect --shell`), and they share it:
// one session's end must not stop the sandbox, or undo the folder, under
// another's harness. Each session holds a lease while its harness or shell
// runs: a file in the sandbox's CLI state directory that the session's
// process keeps flock'ed, so the lease of a session that dies goes with its
// process.
//
// The sandbox's gate (sessionGateFile, next to the leases) orders the
// leases with every stop and delete DefenseClaw decides on (lockSandbox):
// an attach holds it shared while it registers its lease and checks that
// the sandbox still runs; a stop or a delete holds it exclusively from its
// count of the leases to the end of OpenShell's call. Either way it first
// holds the account's gateway lifecycle lock shared
// (openshell.LockGatewayShared), which a gateway restart or rollback holds
// exclusively: that is the exclusive lock of every sandbox of the account.

const leaseSuffix = ".lease"
const sessionGateFile = ".gate"

// sandboxGateWait bounds how long an attach, a stop or a delete waits for
// the sandbox's gate. Each holder keeps it only for a count and one
// OpenShell call, so a wait that long means one is stuck: the attach
// refuses, and a stop or a delete leaves the sandbox as it is.
var sandboxGateWait = 2 * time.Minute

// sandboxGatePoll is how often that wait tries the gate again.
const sandboxGatePoll = 50 * time.Millisecond

// errSandboxGateBusy is a gate another holder kept for sandboxGateWait.
var errSandboxGateBusy = errors.New("another DefenseClaw command is attaching to, stopping or deleting it")

func (a *App) sessionsDir(name string) (string, error) {
	dir, err := a.cliStateDir(name)
	if err != nil {
		return "", err
	}
	return filepath.Join(dir, "sessions"), nil
}

// lockSandbox takes the account's gateway lifecycle lock shared, then
// sandbox name's gate, exclusive or shared, each waiting up to its bound.
// release lets both go.
func (a *App) lockSandbox(ctx context.Context, name string, exclusive bool) (release func(), err error) {
	dir, err := a.sessionsDir(name)
	if err != nil {
		return nil, err
	}
	account, err := openshell.LockGatewayShared(ctx, a.LifecycleDir)
	if err != nil {
		return nil, err
	}
	how := syscall.LOCK_SH
	if exclusive {
		how = syscall.LOCK_EX
	}
	path := filepath.Join(dir, sessionGateFile)
	deadline := time.Now().Add(sandboxGateWait)
	var f *os.File
	for f == nil {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			account()
			return nil, err
		}
		g, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR|syscall.O_NOFOLLOW, 0o600)
		if err != nil {
			account()
			return nil, err
		}
		err = syscall.Flock(int(g.Fd()), how|syscall.LOCK_NB)
		switch {
		case err == nil:
			// A delete removes the sandbox's CLI state, its gate included,
			// while another command waits on it: a gate no longer at path
			// orders nothing, so take the one there now.
			if held, serr := g.Stat(); serr == nil {
				if now, perr := os.Stat(path); perr == nil && os.SameFile(held, now) {
					f = g
					continue
				}
			}
			_ = g.Close()
		case !errors.Is(err, syscall.EWOULDBLOCK):
			_ = g.Close()
			account()
			return nil, err
		default:
			_ = g.Close()
		}
		if time.Now().After(deadline) {
			account()
			return nil, fmt.Errorf("%w (for %s)", errSandboxGateBusy, sandboxGateWait)
		}
		t := time.NewTimer(sandboxGatePoll)
		select {
		case <-ctx.Done():
			t.Stop()
			account()
			return nil, ctx.Err()
		case <-t.C:
		}
	}
	var once sync.Once
	return func() {
		once.Do(func() {
			_ = syscall.Flock(int(f.Fd()), syscall.LOCK_UN)
			_ = f.Close()
			account()
		})
	}, nil
}

// lockForStop takes sandbox name's gate exclusively for a stop or a delete
// and counts, under it, the sessions attached to the sandbox: no session
// can attach until release, so a count of zero holds through OpenShell's
// call. An error (a gate that could not be had, a count that could not be
// made) is not zero sessions: the caller leaves the sandbox as it is
// (attachedUnknown).
func (a *App) lockForStop(ctx context.Context, name string) (others int, release func(), err error) {
	release, err = a.lockSandbox(ctx, name, true)
	if err != nil {
		return 0, nil, err
	}
	others, err = a.attachedSessions(name)
	if err != nil {
		release()
		return 0, nil, err
	}
	afterStopCount(name)
	return others, release, nil
}

// afterStopCount runs once a stop's or a delete's count is made, under the
// gate (a variable so tests can attach right after it).
var afterStopCount = func(string) {}

// holdSession records a harness or shell until release. Failure refuses the
// attach: without the lease another terminal cannot know to leave it running.
// running, when set, runs under the gate once the lease is recorded: an
// error from it (the sandbox no longer runs: a stop decided before the
// lease) releases the lease and refuses the attach with it.
func (a *App) holdSession(ctx context.Context, name string, running func(context.Context) error) (release func(), err error) {
	unlock, err := a.lockSandbox(ctx, name, false)
	if err != nil {
		return nil, fmt.Errorf("cannot record the session with %s: %w; run `%s status %s`, then retry the connect", name, err, CommandName, name)
	}
	defer unlock()
	dir, _ := a.sessionsDir(name)
	var id [6]byte
	if _, err := rand.Read(id[:]); err != nil {
		return nil, fmt.Errorf("cannot record the session with %s: %w; run `%s status %s` before retrying", name, err, CommandName, name)
	}
	path := filepath.Join(dir, strconv.Itoa(os.Getpid())+"-"+hex.EncodeToString(id[:])+leaseSuffix)
	// The lease is locked under another name and then renamed into place: a
	// count (one that holds no gate: status, a resume offer) never opens a
	// lease its session does not hold yet, which it would remove as dead.
	pending := path + ".new"
	f, err := os.OpenFile(pending, os.O_CREATE|os.O_EXCL|os.O_RDWR|syscall.O_NOFOLLOW, 0o600)
	if err != nil {
		return nil, fmt.Errorf("cannot record the session with %s: %w; run `%s status %s` before retrying", name, err, CommandName, name)
	}
	afterLeaseCreate(name)
	if err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		_ = f.Close()
		_ = os.Remove(pending)
		return nil, fmt.Errorf("cannot lock the session with %s: %w; run `%s status %s` before retrying", name, err, CommandName, name)
	}
	if err := os.Rename(pending, path); err != nil {
		_ = f.Close()
		_ = os.Remove(pending)
		return nil, fmt.Errorf("cannot record the session with %s: %w; run `%s status %s` before retrying", name, err, CommandName, name)
	}
	var once sync.Once
	release = func() {
		once.Do(func() {
			// Removed first: a count that opens it before the close sees it
			// held, one after finds nothing.
			_ = os.Remove(path)
			_ = f.Close()
		})
	}
	// After the lease is in place: a look at the copy that read the stamp
	// and then counted no lease, so missed this attach, finds the stamp
	// changed when it would record what it saw (attachStamp).
	if err := a.bumpAttachStamp(name); err != nil {
		release()
		return nil, fmt.Errorf("cannot record the session with %s: %w; run `%s status %s` before retrying", name, err, CommandName, name)
	}
	if running != nil {
		if err := running(ctx); err != nil {
			release()
			return nil, err
		}
	}
	return release, nil
}

// attachStampFile, next to the leases, changes with every attach
// (holdSession) and every `sandbox exec`: a session that attached and
// ended between two looks leaves no lease, but a new stamp.
const attachStampFile = ".attach-stamp"

// attachStamp reads sandbox name's attach stamp: "" when nothing attached
// yet. ok is false when it cannot be read; such a stamp matches no other
// (copyBase.unchanged).
func (a *App) attachStamp(name string) (stamp string, ok bool) {
	dir, err := a.sessionsDir(name)
	if err != nil {
		return "", false
	}
	f, err := os.OpenFile(filepath.Join(dir, attachStampFile), os.O_RDONLY|syscall.O_NOFOLLOW, 0)
	if errors.Is(err, fs.ErrNotExist) {
		return "", true
	}
	if err != nil {
		return "", false
	}
	defer f.Close()
	var b [64]byte
	n, err := f.Read(b[:])
	if err != nil || n == 0 {
		return "", false
	}
	return string(b[:n]), true
}

// bumpAttachStamp gives sandbox name a new attach stamp, in one rename.
func (a *App) bumpAttachStamp(name string) error {
	dir, err := a.sessionsDir(name)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	var id [12]byte
	if _, err := rand.Read(id[:]); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(dir, attachStampFile+".*.new")
	if err != nil {
		return err
	}
	_, err = tmp.WriteString(hex.EncodeToString(id[:]))
	if cerr := tmp.Close(); err == nil {
		err = cerr
	}
	if err == nil {
		err = os.Rename(tmp.Name(), filepath.Join(dir, attachStampFile))
	}
	if err != nil {
		_ = os.Remove(tmp.Name())
	}
	return err
}

// afterLeaseCreate runs once an attach created its lease file, before it
// locks it (a variable so tests can count the leases there).
var afterLeaseCreate = func(string) {}

// openLease opens a lease file to see whether its process still holds it
// (a variable so tests can race a release against a count).
var openLease = func(path string) (*os.File, error) {
	return os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW, 0)
}

// attachedSessions counts the sessions whose harness or shell runs in
// sandbox name now (on this machine, with this data dir). A lease whose
// process is gone is removed. A lease that is gone between the listing and
// its open (its session released it, or another count removed it as dead)
// is a session that ended; every other error is returned, and a caller
// that would stop or delete the sandbox keeps it (attachedUnknown). Only a
// count under the exclusive gate (lockForStop) holds until a stop: an
// attach may follow any other.
func (a *App) attachedSessions(name string) (int, error) {
	dir, err := a.sessionsDir(name)
	if err != nil {
		return 0, err
	}
	entries, err := os.ReadDir(dir)
	if errors.Is(err, fs.ErrNotExist) {
		// No session has attached yet.
		return 0, nil
	}
	if err != nil {
		return 0, err
	}
	n := 0
	for _, e := range entries {
		if !e.Type().IsRegular() || !strings.HasSuffix(e.Name(), leaseSuffix) {
			continue
		}
		path := filepath.Join(dir, e.Name())
		f, err := openLease(path)
		if errors.Is(err, fs.ErrNotExist) {
			continue
		}
		if err != nil {
			return 0, err
		}
		switch err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); {
		case errors.Is(err, syscall.EWOULDBLOCK):
			n++
		case err == nil:
			// Its process is gone.
			_ = os.Remove(path)
		case err != nil:
			_ = f.Close()
			return 0, err
		}
		_ = f.Close()
	}
	return n, nil
}

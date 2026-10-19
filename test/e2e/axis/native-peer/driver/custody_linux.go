// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package main

import (
	"bytes"
	"context"
	"errors"
	"io"
	"os"
	"os/exec"
	"runtime"
	"sync"
	"syscall"

	"golang.org/x/sys/unix"
)

const workerReady = "DC_AXIS_OUTER_WRAPPER_READY_V1\n"
const workerGrant = "DC_AXIS_OUTER_WRAPPER_GRANT_V1\n"

func readyThenGrant(ready io.Writer, grant io.Reader) error {
	if _, err := io.WriteString(ready, workerReady); err != nil {
		return errors.New("fixed worker READY failed")
	}
	message, err := io.ReadAll(io.LimitReader(grant, int64(len(workerGrant)+1)))
	if err != nil || string(message) != workerGrant {
		return errors.New("fixed worker GRANT absent or malformed")
	}
	return nil
}

// outerCustodian retains an atomic pidfd for the whole fixed worker PID
// namespace. Killing and reaping its init covers nested peer/workload namespaces.
// No raw host PID, name lookup, process group or JSON supplies cleanup authority.
type outerCustodian struct {
	mu                        sync.Mutex
	pidfd                     int
	starting, started, closed bool
	complete                  bool
	command                   *exec.Cmd
	done                      chan struct{}
	waitErr                   error
	exit                      int
}

func (o *outerCustodian) signalLocked() error {
	var err error
	if o.pidfd >= 0 {
		err = unix.PidfdSendSignal(o.pidfd, unix.SIGKILL, nil, 0)
	} else if o.started && !o.complete && o.command != nil {
		// Atomic pidfd refusal still needs exact os.Process cleanup. It never
		// authorizes GRANT, and Go synchronizes this handle against PID reuse.
		err = o.command.Process.Kill()
	}
	if errors.Is(err, unix.ESRCH) || errors.Is(err, os.ErrProcessDone) {
		return nil
	}
	return err
}

func (o *outerCustodian) stopAndWait(ctx context.Context) error {
	o.mu.Lock()
	o.closed = true
	err := o.signalLocked()
	o.mu.Unlock()
	if err != nil {
		return err
	}
	select {
	case <-o.done:
		return o.waitErr
	default:
	}
	select {
	case <-o.done:
		return o.waitErr
	case <-ctx.Done():
		return ctx.Err() // the exact owner stays reachable in its caller
	}
}

func (o *outerCustodian) Close(ctx context.Context) error       { return o.stopAndWait(ctx) }
func (o *outerCustodian) StopAndWait(ctx context.Context) error { return o.stopAndWait(ctx) }

func (o *outerCustodian) start(ctx context.Context, command *exec.Cmd, pidfd *int, childFiles []*os.File) error {
	o.mu.Lock()
	o.starting = true
	o.mu.Unlock()
	result := make(chan error, 1)
	go func() {
		// Worker PR_SET_PDEATHSIG refers to this creating thread. Retain it
		// until wait, without Go's pre-exec getppid check across CLONE_NEWPID.
		runtime.LockOSThread()
		defer runtime.UnlockOSThread()
		o.mu.Lock()
		abort := o.closed || ctx.Err() != nil
		o.mu.Unlock()
		var startErr error
		if abort {
			startErr = context.Canceled
		} else {
			startErr = command.Start()
		}
		var closeErr error
		for _, f := range childFiles {
			closeErr = errors.Join(closeErr, f.Close())
		}
		o.mu.Lock()
		o.starting = false
		if startErr != nil {
			o.closed, o.complete, o.waitErr = true, true, closeErr
			close(o.done)
			o.mu.Unlock()
			result <- errors.Join(errors.New("fixed outer namespace start refused"), closeErr)
			return
		}
		o.started, o.pidfd, o.command = true, *pidfd, command
		if *pidfd < 0 || o.closed || ctx.Err() != nil || closeErr != nil {
			o.closed = true
			startErr = errors.Join(errors.New("fixed outer atomic custody refused"), closeErr, o.signalLocked())
		}
		o.mu.Unlock()
		result <- startErr
		waitErr := command.Wait()
		exit := -1
		if command.ProcessState != nil {
			exit = command.ProcessState.ExitCode()
			if status, ok := command.ProcessState.Sys().(syscall.WaitStatus); ok && (status.Exited() || status.Signaled()) {
				var ordinaryExit *exec.ExitError
				if errors.As(waitErr, &ordinaryExit) {
					waitErr = nil // exit status is separately required for success
				}
			}
		}
		o.mu.Lock()
		if o.pidfd >= 0 {
			waitErr = errors.Join(waitErr, unix.Close(o.pidfd))
			o.pidfd = -1
		}
		o.waitErr, o.exit, o.complete, o.closed = waitErr, exit, true, true
		o.command = nil
		close(o.done)
		o.mu.Unlock()
	}()
	select {
	case err := <-result:
		return err
	case <-ctx.Done():
		return ctx.Err() // start goroutine owns child copies through kernel return
	}
}

type boundedCapture struct {
	mu       sync.Mutex
	data     []byte
	overflow bool
}

func (b *boundedCapture) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if len(p) > outputLimit-len(b.data) {
		b.overflow = true
		return 0, errors.New("fixed outer capture exceeded")
	}
	b.data = append(b.data, p...)
	return len(p), nil
}

func (b *boundedCapture) snapshot() ([]byte, bool) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return bytes.Clone(b.data), b.overflow
}

// This is a copy of the already running, externally source/image-admitted
// outer driver, not admission of an arbitrary path plus caller-provided digest.
// /proc/self/exe resolves the current executable inode, including after rename.
func sealedRunningImage() (_ *os.File, hash string, resultErr error) {
	source, err := os.Open("/proc/self/exe")
	if err != nil {
		return nil, "", err
	}
	defer func() { resultErr = errors.Join(resultErr, source.Close()) }()
	info, err := source.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Mode()&(os.ModeSetuid|os.ModeSetgid) != 0 || info.Size() < 64 || info.Size() > 64<<20 {
		return nil, "", errors.New("fixed running wrapper image refused")
	}
	data, err := io.ReadAll(io.LimitReader(source, (64<<20)+1))
	if err != nil || int64(len(data)) != info.Size() || validateStaticELF(data) != nil {
		return nil, "", errors.New("fixed running wrapper must be static Linux amd64")
	}
	fd, err := unix.MemfdCreate("fixed-native-peer-wrapper", unix.MFD_CLOEXEC|unix.MFD_ALLOW_SEALING)
	if err != nil {
		return nil, "", err
	}
	file := os.NewFile(uintptr(fd), "fixed-sealed-wrapper")
	accepted := false
	defer func() {
		if !accepted {
			resultErr = errors.Join(resultErr, file.Close())
		}
	}()
	if _, err := file.Write(data); err != nil || file.Chmod(0500) != nil {
		return nil, "", errors.New("fixed running wrapper sealing failed")
	}
	if _, err := unix.FcntlInt(file.Fd(), unix.F_ADD_SEALS, unix.F_SEAL_WRITE|unix.F_SEAL_GROW|unix.F_SEAL_SHRINK|unix.F_SEAL_SEAL); err != nil {
		return nil, "", err
	}
	accepted = true
	return file, digestBytes(data), nil
}

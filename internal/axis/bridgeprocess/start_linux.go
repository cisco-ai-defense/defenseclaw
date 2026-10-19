// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package bridgeprocess

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"runtime"
	"strconv"
	"sync"
	"syscall"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/axis/bridgeowner"
	"github.com/defenseclaw/defenseclaw/internal/axis/bridgeproto"
	"github.com/defenseclaw/defenseclaw/internal/axis/namespaceinit"
	"golang.org/x/sys/unix"
)

// namespaceCustody owns the pidfd of a freshly cloned PID-namespace init.
// Killing that exact init kills its namespace members, including nested PID
// namespaces. Reaping init completes only after the kernel's namespace teardown.
// It never enumerates, signals or adopts host PIDs, names or process groups.
type namespaceCustody struct {
	mu       sync.Mutex
	pidfd    int
	done     chan struct{}
	waitErr  error
	started  bool
	starting bool
	closed   bool
	complete bool
	command  *exec.Cmd
}

func (custody *namespaceCustody) StopAndWait(ctx context.Context) error {
	custody.mu.Lock()
	custody.closed = true
	if !custody.started && !custody.starting && !custody.complete {
		// Cleanup before start permanently closes admission. A start already
		// in the kernel retains this object and must stop its late peer before
		// publishing completion. Never hold mu across that kernel operation.
		custody.complete = true
		close(custody.done)
	}
	err := custody.signalLocked()
	custody.mu.Unlock()
	if err != nil {
		return err
	}
	// Prefer a completed native observation over an already-canceled cleanup
	// context; the channel close synchronizes the stored wait result.
	select {
	case <-custody.done:
		return custody.waitErr
	default:
	}
	select {
	case <-custody.done:
		return custody.waitErr
	case <-ctx.Done():
		// Retain ownership and the one bounded-by-native-exit reaper. No caller
		// timeout relabels an unobserved namespace as successfully cleaned up.
		return ctx.Err()
	}
}

// signalLocked operates only on retained native objects. mu protects the pidfd
// against closure/reuse by wait; no process start or blocking wait holds mu.
func (custody *namespaceCustody) signalLocked() error {
	var err error
	if custody.pidfd >= 0 {
		err = unix.PidfdSendSignal(custody.pidfd, unix.SIGKILL, nil, 0)
	} else if custody.started && !custody.complete && custody.command != nil {
		// Only an unsupported atomic-pidfd result can arrive here. Go's exact
		// os.Process synchronizes signal/wait, including PID reuse prevention.
		err = custody.command.Process.Kill()
	}
	if errors.Is(err, unix.ESRCH) || errors.Is(err, os.ErrProcessDone) {
		return nil
	}
	return err
}

func (custody *namespaceCustody) wait(command *exec.Cmd) {
	err := command.Wait()
	var exitError *exec.ExitError
	if errors.As(err, &exitError) && command.ProcessState != nil {
		status, ok := command.ProcessState.Sys().(syscall.WaitStatus)
		if ok && (status.Exited() || status.Signaled()) {
			err = nil
		}
	}
	custody.mu.Lock()
	if custody.pidfd >= 0 {
		if closeErr := unix.Close(custody.pidfd); err == nil {
			err = closeErr
		}
		custody.pidfd = -1
	}
	custody.waitErr = err
	custody.command = nil
	custody.closed = true
	custody.complete = true
	close(custody.done)
	custody.mu.Unlock()
}

func (custody *namespaceCustody) start(ctx context.Context, command *exec.Cmd, pidfd *int, childFiles []*os.File) error {
	custody.mu.Lock()
	if custody.closed || custody.starting || custody.started || ctx.Err() != nil {
		custody.mu.Unlock()
		for _, file := range childFiles {
			_ = file.Close()
		}
		return bridgeowner.ErrClosed
	}
	custody.starting = true
	custody.mu.Unlock()
	result := make(chan error, 1)
	go func() {
		// The peer's parent-death signal is tied to its creating OS thread.
		// Keep that same thread alive through native wait, without sharing it
		// with an unrelated Go task whose termination could kill the peer.
		runtime.LockOSThread()
		defer runtime.UnlockOSThread()
		release := func() error {
			var err error
			for _, file := range childFiles {
				err = errors.Join(err, file.Close())
			}
			return err
		}
		custody.mu.Lock()
		abort := custody.closed || ctx.Err() != nil
		custody.mu.Unlock()
		if abort {
			closeErr := release()
			custody.mu.Lock()
			custody.starting = false
			custody.closed, custody.complete, custody.waitErr = true, true, closeErr
			close(custody.done)
			custody.mu.Unlock()
			result <- errors.Join(bridgeowner.ErrClosed, closeErr)
			return
		}
		startErr := command.Start()
		// The caller can time out while Start is inside the kernel. Retain
		// these exact duplicate handles until Start has finished remapping;
		// closing them in the caller could otherwise allow FD-number reuse.
		closeErr := release()
		custody.mu.Lock()
		custody.starting = false
		if startErr != nil {
			custody.closed, custody.complete = true, true
			custody.waitErr = closeErr
			close(custody.done)
			custody.mu.Unlock()
			result <- errors.Join(fmt.Errorf("%w: native namespace creation or image execution failed", ErrUnavailable), closeErr)
			return
		}
		custody.started, custody.command, custody.pidfd = true, command, *pidfd
		if *pidfd < 0 {
			custody.closed = true
			startErr = ErrUnavailable
		}
		if custody.closed || ctx.Err() != nil || closeErr != nil {
			custody.closed = true
			startErr = errors.Join(startErr, closeErr, bridgeowner.ErrClosed, custody.signalLocked())
		}
		custody.mu.Unlock()
		result <- startErr
		custody.wait(command)
	}()
	select {
	case err := <-result:
		return err
	case <-ctx.Done():
		// Session retains custody even if the kernel start is still pending.
		// StopAndWait latches closure and remains bounded independently of it.
		return ctx.Err()
	}
}

func start(ctx context.Context, binding bridgeproto.Binding, plan bridgeproto.Preparation, inputs Inputs, limits bridgeowner.Limits) (*Session, error) {
	deadline, bounded := ctx.Deadline()
	if ctx.Err() != nil || !bounded || time.Until(deadline) <= 0 || time.Until(deadline) > 24*time.Hour ||
		limits.WriteTimeout <= 0 || limits.WriteTimeout > 30*time.Second || limits.CleanupTimeout <= 0 || limits.CleanupTimeout > 30*time.Second ||
		runtime.GOARCH != "amd64" || os.Geteuid() == 0 || os.Getuid() != os.Geteuid() || os.Getgid() != os.Getegid() {
		return nil, ErrAdmission
	}
	frame := bridgeproto.Frame{Version: bridgeproto.Version, Sequence: 1, Request: 1, Binding: binding, Kind: bridgeproto.Prepare, Plan: &plan}
	if frame.Validate() != nil || plan.Backend != "bubblewrap" || plan.Terminal != nil || len(plan.Filesystem.Deny) != 0 ||
		len(plan.Argv) == 0 || plan.Argv[0] != "/.defenseclaw/payload" ||
		len(inputs.Read) != len(plan.Filesystem.Read) || len(inputs.Write) != len(plan.Filesystem.Write) {
		return nil, ErrAdmission
	}
	proof, err := namespaceinit.Capture()
	if err != nil {
		return nil, err
	}
	extras := []*os.File{proof}
	defer func() {
		for _, file := range extras {
			_ = file.Close()
		}
	}()
	for _, image := range []*Image{inputs.Bubblewrap, inputs.Payload} {
		file, err := image.duplicate()
		if err != nil {
			return nil, err
		}
		extras = append(extras, file)
	}
	objects := append([]*os.File{inputs.CWD}, inputs.Read...)
	objects = append(objects, inputs.Write...)
	for index, object := range objects {
		file, err := duplicate(object)
		if err != nil {
			return nil, err
		}
		extras = append(extras, file)
		info, err := file.Stat()
		if err != nil || !info.IsDir() && !info.Mode().IsRegular() || index == 0 && !info.IsDir() {
			return nil, ErrAdmission
		}
	}
	peer, err := inputs.Peer.duplicate()
	if err != nil {
		return nil, err
	}
	extras = append(extras, peer)
	var channels []bridgeowner.PrivatePipe
	defer func() {
		for _, channel := range channels {
			_ = channel.Child.Close()
			if channel.Parent != nil {
				_ = channel.Parent.Close()
			}
		}
	}()
	for _, direction := range []bridgeowner.Direction{bridgeowner.ToPeer, bridgeowner.FromPeer, bridgeowner.FromPeer} {
		channel, err := bridgeowner.NewPrivatePipe(direction)
		if err != nil {
			return nil, err
		}
		channels = append(channels, channel)
	}
	pidfd := -1
	command := &exec.Cmd{
		// Go remaps ExtraFiles before exec. This resolves only the child's own
		// fixed descriptor, not an external host pathname or PATH entry.
		Path: "/proc/self/fd/" + strconv.Itoa(3+len(extras)-1),
		Args: []string{"defenseclaw-axis-peer"}, Env: []string{}, Dir: "/",
		ExtraFiles: extras, Stdin: channels[0].Child, Stdout: channels[1].Child, Stderr: channels[2].Child,
		SysProcAttr: &syscall.SysProcAttr{
			Cloneflags:  syscall.CLONE_NEWUSER | syscall.CLONE_NEWNS | syscall.CLONE_NEWPID | syscall.CLONE_NEWNET | syscall.CLONE_NEWIPC | syscall.CLONE_NEWUTS,
			AmbientCaps: []uintptr{unix.CAP_SYS_ADMIN},
			UidMappings: []syscall.SysProcIDMap{{ContainerID: os.Getuid(), HostID: os.Getuid(), Size: 1}},
			GidMappings: []syscall.SysProcIDMap{{ContainerID: os.Getgid(), HostID: os.Getgid(), Size: 1}},
			// Go's Pdeathsig checks getppid against the pre-clone PID, which
			// is not visible inside CLONE_NEWPID. The trusted peer sets its
			// own parent-death signal before processing any command instead.
			GidMappingsEnableSetgroups: false, PidFD: &pidfd,
		},
	}
	// Establish a cleanup owner before any native clone. Owner.New can cancel
	// pending creation; every subsequent failure returns that nonnil owner.
	custody := &namespaceCustody{pidfd: -1, done: make(chan struct{})}
	pipes := bridgeowner.Pipes{Input: channels[0].Parent, Output: channels[1].Parent, Diagnostics: channels[2].Parent, Custody: custody}
	owner, err := bridgeowner.New(ctx, binding, pipes, limits)
	if owner == nil {
		return nil, err
	}
	session := &Session{Protocol: owner, native: custody}
	for index := range channels {
		channels[index].Parent = nil
	}
	if err == nil {
		// CLONE_PIDFD is requested atomically by Go's clone syscall. No later
		// pidfd_open or name-based discovery supplies lifecycle authority.
		// Transfer child-side copies even if cancellation wins while Start is
		// pending. The creating thread closes them after native remapping.
		childFiles := append([]*os.File(nil), extras...)
		extras = nil
		for index := range channels {
			childFiles = append(childFiles, channels[index].Child)
			channels[index].Child = nil
		}
		err = custody.start(ctx, command, &pidfd, childFiles)
	}
	if err != nil {
		cleanup, cancel := context.WithTimeout(context.Background(), limits.CleanupTimeout)
		defer cancel()
		return session, errors.Join(err, session.Close(cleanup))
	}
	return session, nil
}

// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package processutil

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"math"
	"os"
	"os/exec"
	"os/signal"
	"runtime"
	"strconv"
	"syscall"
	"time"

	"golang.org/x/sys/unix"
)

// On Linux, RunContained runs cmd below a runner that is PID 1 of a new PID
// namespace. Nothing the command starts can address a process outside the
// namespace, and the runner is its init, which it cannot SIGKILL. When the
// runner exits or is killed, however it dies, the kernel kills every process
// in the namespace, also one in a session or group of its own, before the
// runner's exit is reported. A hook that SIGKILLed the subreaper custodian
// RunContained used before took its runner and itself down, and the kernel
// handed its setsid child to init, which kept running (r104 W5b review).
//
// RunTracked starts the scanner itself as PID 1 of a new PID namespace.
// Killing that process kills all descendants in the namespace, including
// detached children, before its pidfd becomes readable. The namespace also
// keeps the gateway and its unrelated children out of the scanner's PID map,
// and a Landlock domain of the scanner's own keeps every process outside it
// out of the scanner's ptrace reach (guardTrackedInit). Containment changes
// only the scanner's tree: the gateway's own dumpable and ptrace state never
// changes, so daemon status, stop, restart and upgrade read its /proc entries
// during a scan as at any other time.
const (
	containSupervisorArg0   = "defenseclaw-contained-run"
	containSupervisorEnv    = "DEFENSECLAW_CONTAINED_RUN_SUPERVISOR"
	containInitMode         = "init"
	containLauncherMode     = "launcher"
	containTrackedMode      = "tracked-launcher"
	containTrackedInit      = "tracked-init"
	containHostStatEnv      = "DEFENSECLAW_TRACKED_HOST_STAT_FD"
	containFailNamespaceEnv = "DC_PROCESSUTIL_TEST_FAIL_NAMESPACE"
)

// Supervisor exit codes. Any other code is the command's own (128+signal
// for a command killed by a signal).
const (
	// containExitTerminated: the supervisor was told to end (cancellation
	// or the death of its parent) and ended everything.
	containExitTerminated = 124
	// containExitNotContained: the supervisor could not prove that nothing
	// the command started still runs, or the runner is not the init of a PID
	// namespace of its own.
	containExitNotContained = 125
	// containExitNotStarted: the command could not start.
	containExitNotStarted = 127
	// containExitNoNamespace: the launcher could not create the runner's
	// namespaces, so the command never ran (ErrContainmentUnavailable). A
	// command that ran and exited 123 is reported by the launcher as 1.
	containExitNoNamespace = 123
)

// A killed PID-namespace init can briefly leave a descendant holding a pipe.
const containPipeWaitDelay = 2 * time.Second

// containIDMap maps this process's IDs into the runner's user namespace;
// tests map an ID this process does not have to reach the fail-closed result.
var containIDMap = func(id int) []syscall.SysProcIDMap {
	return []syscall.SysProcIDMap{{ContainerID: id, HostID: id, Size: 1}}
}

func init() {
	if len(os.Args) < 5 || os.Args[0] != containSupervisorArg0 || os.Args[3] != "--" ||
		os.Getenv(containSupervisorEnv) != "1" {
		return
	}
	switch os.Args[1] {
	case containInitMode:
		if os.Args[2] != "0s" {
			os.Exit(containExitNotContained)
		}
		os.Exit(runContainedCommand(os.Args[4:]))
	case containLauncherMode:
		if os.Args[2] != "0s" {
			os.Exit(containExitNotContained)
		}
		os.Exit(launchContained(os.Args[4:]))
	case containTrackedMode:
		parent, err := strconv.Atoi(os.Args[2])
		if err != nil || parent < 1 {
			os.Exit(containExitNotContained)
		}
		os.Exit(launchTracked(os.Args[4:], parent))
	case containTrackedInit:
		if os.Args[2] != "3,4" {
			os.Exit(containExitNotContained)
		}
		os.Exit(execTracked(os.Args[4:]))
	default:
		os.Exit(containExitNotContained)
	}
}

func runContained(cmd *exec.Cmd) error {
	return runContainedMode(cmd, containLauncherMode)
}

func runContainedDirect(cmd *exec.Cmd) error {
	return runContainedMode(cmd, containInitMode)
}

func runContainedMode(cmd *exec.Cmd, mode string) error {
	if cmd.Process != nil {
		return errors.New("processutil: RunContained: already started")
	}
	target := cmd.Path
	cmd.Path = "/proc/self/exe"
	cmd.Args = append([]string{containSupervisorArg0, mode, "0s", "--", target}, cmd.Args[1:]...)
	env := cmd.Env
	if env == nil {
		env = os.Environ()
	}
	cmd.Env = append(withoutEnv(env, containSupervisorEnv), containSupervisorEnv+"=1")
	if cmd.SysProcAttr == nil {
		cmd.SysProcAttr = &syscall.SysProcAttr{}
	}
	attr := cmd.SysProcAttr
	attr.Setpgid = true
	// The runner, or the launcher that starts it, ends with this thread.
	attr.Pdeathsig = syscall.SIGKILL
	if mode == containLauncherMode {
		// The launcher ends the namespace and waits for it.
		if cmd.Cancel != nil {
			cmd.Cancel = func() error { return cmd.Process.Signal(syscall.SIGTERM) }
		}
	} else {
		attr.Cloneflags |= syscall.CLONE_NEWPID
		switch caps := effectiveCapabilities(); {
		case caps&(1<<unix.CAP_SYS_ADMIN) != 0:
			// A PID namespace alone: every file keeps its owner and access.
		case caps&(1<<unix.CAP_SETUID) != 0 && caps&(1<<unix.CAP_SETGID) != 0:
			// The identity map of every ID, so every file keeps its owner.
			// Ubuntu's AppArmor restriction of unprivileged user namespaces
			// drops the capabilities of one created without CAP_SYS_ADMIN.
			attr.Cloneflags |= syscall.CLONE_NEWUSER
			attr.UidMappings = []syscall.SysProcIDMap{{ContainerID: 0, HostID: 0, Size: math.MaxInt32}}
			attr.GidMappings = attr.UidMappings
			attr.GidMappingsEnableSetgroups = true
		default:
			attr.Cloneflags |= syscall.CLONE_NEWUSER
			attr.UidMappings = containIDMap(os.Geteuid())
			attr.GidMappings = containIDMap(os.Getegid())
			attr.GidMappingsEnableSetgroups = false
		}
		// Killing the runner ends the namespace.
		if cmd.Cancel != nil {
			cmd.Cancel = func() error { return cmd.Process.Kill() }
		}
	}
	// The parent-death signal follows the thread that started the child.
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	if err := cmd.Start(); err != nil {
		// No namespace (user namespaces disabled, a sandbox that refuses
		// them): the command never runs.
		if mode == containInitMode && namespaceRefused(err) {
			return fmt.Errorf("%w: %w: %s: %v", ErrNotContained, ErrContainmentUnavailable, target, err)
		}
		return fmt.Errorf("%w: %s: %v", ErrNotContained, target, err)
	}
	err := cmd.Wait()
	var exitErr *exec.ExitError
	if errors.As(err, &exitErr) && exitErr.ExitCode() == containExitNotContained {
		return fmt.Errorf("%w: %s", ErrNotContained, target)
	}
	if mode == containLauncherMode && errors.As(err, &exitErr) && exitErr.ExitCode() == containExitNoNamespace {
		return fmt.Errorf("%w: %w: %s", ErrNotContained, ErrContainmentUnavailable, target)
	}
	return err
}

// namespaceRefused reports whether a runner start failed because a seccomp
// filter or sandbox (EPERM) or a namespace limit (ENOSPC, EUSERS) refused its
// namespaces. Any other start failure stays ErrNotContained alone.
func namespaceRefused(err error) bool {
	for _, errno := range []syscall.Errno{syscall.EPERM, syscall.ENOSPC, syscall.EUSERS} {
		if errors.Is(err, errno) {
			return true
		}
	}
	return false
}

// mixedCredentials reports whether this process's real, effective and saved
// IDs differ, as in the root hook guardian while it acts as a user. Such a
// process is not dumpable, so its child's ID maps are owned by root and it
// cannot write them.
func mixedCredentials() bool {
	ruid, euid, suid := unix.Getresuid()
	rgid, egid, sgid := unix.Getresgid()
	return ruid != euid || suid != euid || rgid != egid || sgid != egid
}

// dumpable reports whether this process is dumpable. One that is not (the
// hook guardian's per-user worker makes itself so: its request carries
// scoped hook tokens) shares that state with the child it starts until the
// child executes, so the child's ID maps are owned by root and a caller
// without privilege cannot write them: every managed Linux Hermes probe
// failed to start and Verify reported "owned hook command not present"
// (GAP-0846). It runs the command through the launcher instead, which is a
// new image and sets itself dumpable.
func dumpable() bool {
	state, err := unix.PrctlRetInt(unix.PR_GET_DUMPABLE, 0, 0, 0, 0)
	return err == nil && state == 1
}

// launchContained becomes the effective user and group alone, which needs no
// privilege, makes itself dumpable, and runs argv in a PID namespace of its
// own from there. The hook guardian's probe ran the user's hook with the
// guardian's real root UID, which bash restores as its effective UID. The
// launcher holds only its arguments and the environment the command gets
// too, so being dumpable exposes nothing the command could not read.
func launchContained(argv []string) int {
	runtime.LockOSThread()
	terms := make(chan os.Signal, 1)
	signal.Notify(terms, syscall.SIGTERM)
	uid, gid := os.Geteuid(), os.Getegid()
	if syscall.Setresgid(gid, gid, gid) != nil || syscall.Setresuid(uid, uid, uid) != nil || mixedCredentials() {
		return containExitNotContained
	}
	if err := unix.Prctl(unix.PR_SET_DUMPABLE, 1, 0, 0, 0); err != nil || !dumpable() {
		return containExitNotContained
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	if os.Getenv(containFailNamespaceEnv) == "1" {
		return containExitNoNamespace
	}
	go func() {
		<-terms
		cancel()
	}()
	child := exec.CommandContext(ctx, argv[0], argv[1:]...)
	child.Env = withoutEnv(os.Environ(), containSupervisorEnv)
	child.Stdin, child.Stdout, child.Stderr = os.Stdin, os.Stdout, os.Stderr
	err := runContainedDirect(child)
	var exitErr *exec.ExitError
	switch {
	case ctx.Err() != nil:
		return containExitTerminated
	case err == nil:
		return 0
	case errors.As(err, &exitErr) && exitErr.ExitCode() == containExitNoNamespace:
		// The command ran and ended with the code this launcher keeps for
		// a refused namespace: report it as a plain failure, so a command
		// that ran is never read as one that could not (GAP-1945).
		return 1
	case errors.As(err, &exitErr) && exitErr.ExitCode() >= 0:
		return exitErr.ExitCode()
	case errors.Is(err, ErrContainmentUnavailable):
		return containExitNoNamespace
	default:
		return containExitNotContained
	}
}

// effectiveCapabilities returns this process's effective capability set.
func effectiveCapabilities() uint64 {
	header := unix.CapUserHeader{Version: unix.LINUX_CAPABILITY_VERSION_3}
	var data [2]unix.CapUserData
	if err := unix.Capget(&header, &data[0]); err != nil {
		return 0
	}
	return uint64(data[1].Effective)<<32 | uint64(data[0].Effective)
}

// runTracked runs a scanner as PID 1 in a private PID namespace. The
// launcher is outside that namespace, so the scanner cannot address it or the
// gateway by PID. The launcher holds a pidfd for the scanner and is linked to
// the gateway by a parent-death signal and its own pidfd.
func runTracked(cmd *exec.Cmd) error {
	if cmd.Process != nil {
		return errors.New("processutil: RunTracked: already started")
	}
	if len(cmd.ExtraFiles) != 0 {
		return errors.New("processutil: RunTracked: ExtraFiles are not passed to the scanner")
	}
	target := cmd.Path
	cmd.Path = "/proc/self/exe"
	cmd.Args = append([]string{containSupervisorArg0, containTrackedMode, strconv.Itoa(os.Getpid()), "--", target}, cmd.Args[1:]...)
	env := cmd.Env
	if env == nil {
		env = os.Environ()
	}
	cmd.Env = append(withoutEnv(env, containSupervisorEnv), containSupervisorEnv+"=1")
	if cmd.SysProcAttr == nil {
		cmd.SysProcAttr = &syscall.SysProcAttr{}
	}
	attr := cmd.SysProcAttr
	attr.Setpgid = true
	attr.Pdeathsig = syscall.SIGKILL
	pidfd := -1
	attr.PidFD = &pidfd
	fds, err := unix.Socketpair(unix.AF_UNIX, unix.SOCK_STREAM|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		return fmt.Errorf("%w: cannot establish scanner custody channel: %v", ErrNotContained, err)
	}
	owner := os.NewFile(uintptr(fds[0]), "scanner-custody")
	launcherChannel := os.NewFile(uintptr(fds[1]), "scanner-custody-child")
	defer owner.Close()
	defer launcherChannel.Close()
	cmd.ExtraFiles = []*os.File{launcherChannel}
	if cmd.WaitDelay == 0 || cmd.WaitDelay > containPipeWaitDelay {
		cmd.WaitDelay = containPipeWaitDelay
	}
	ready := make(chan struct{})
	if cmd.Cancel != nil {
		cmd.Cancel = func() error {
			<-ready
			if pidfd < 0 {
				return cmd.Process.Kill()
			}
			err := unix.PidfdSendSignal(pidfd, unix.SIGKILL, nil, 0)
			if errors.Is(err, unix.ESRCH) {
				return os.ErrProcessDone
			}
			return err
		}
	}
	scannerFD := -1
	defer func() {
		if scannerFD >= 0 {
			_ = unix.Close(scannerFD)
		}
	}()
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	if err := cmd.Start(); err != nil {
		close(ready)
		_ = launcherChannel.Close()
		return fmt.Errorf("%w: %s: %v", ErrNotContained, target, err)
	}
	_ = launcherChannel.Close()
	close(ready)
	if pidfd < 0 {
		_ = cmd.Process.Kill()
		_ = cmd.Wait()
		return fmt.Errorf("%w: no launcher pidfd", ErrNotContained)
	}
	defer unix.Close(pidfd)
	if err := unix.SetsockoptTimeval(int(owner.Fd()), unix.SOL_SOCKET, unix.SO_RCVTIMEO, &unix.Timeval{Sec: 10}); err != nil {
		_ = unix.PidfdSendSignal(pidfd, unix.SIGKILL, nil, 0)
		_ = cmd.Wait()
		return fmt.Errorf("%w: scanner custody deadline: %v", ErrNotContained, err)
	}
	var scannerPID [4]byte
	if _, err := io.ReadFull(owner, scannerPID[:]); err != nil {
		_ = unix.PidfdSendSignal(pidfd, unix.SIGKILL, nil, 0)
		_ = cmd.Wait()
		return fmt.Errorf("%w: scanner custody handshake: %v", ErrNotContained, err)
	}
	scannerFD, err = unix.PidfdOpen(int(binary.LittleEndian.Uint32(scannerPID[:])), 0)
	if err != nil {
		_ = unix.PidfdSendSignal(pidfd, unix.SIGKILL, nil, 0)
		_ = cmd.Wait()
		return fmt.Errorf("%w: cannot own scanner pidfd: %v", ErrNotContained, err)
	}
	if _, err := owner.Write([]byte{1}); err != nil {
		_ = unix.PidfdSendSignal(scannerFD, unix.SIGKILL, nil, 0)
		_ = unix.PidfdSendSignal(pidfd, unix.SIGKILL, nil, 0)
		_ = cmd.Wait()
		_ = waitScannerPidfd(scannerFD, 5*time.Second)
		return fmt.Errorf("%w: scanner custody acknowledge: %v", ErrNotContained, err)
	}
	_ = owner.Close()
	err = cmd.Wait()
	if err != nil {
		// The launcher may have been killed before it observed the command's
		// exit. Its parent-death signal is backed by this scanner pidfd.
		_ = unix.PidfdSendSignal(scannerFD, unix.SIGKILL, nil, 0)
	}
	if !waitScannerPidfd(scannerFD, 5*time.Second) {
		return fmt.Errorf("%w: scanner did not end with its launcher", ErrNotContained)
	}
	return err
}

func waitScannerPidfd(fd int, timeout time.Duration) bool {
	events := []unix.PollFd{{Fd: int32(fd), Events: unix.POLLIN}}
	deadline := time.Now().Add(timeout)
	for {
		remaining := time.Until(deadline)
		if remaining <= 0 {
			return false
		}
		n, err := unix.Poll(events, int(remaining.Milliseconds())+1)
		if errors.Is(err, unix.EINTR) {
			continue
		}
		return err == nil && n == 1 && events[0].Revents&unix.POLLIN != 0
	}
}

// launchTracked is a short-lived child of the gateway. It owns only one
// scanner namespace. A gate holds the scanner's exec until this process has
// finished the user-ID map and made its own /proc memory inaccessible, and
// until the scanner's init has entered its Landlock domain and filter.
func launchTracked(argv []string, expectedParent int) int {
	runtime.LockOSThread()
	if os.Getppid() != expectedParent {
		return containExitNotContained
	}
	owner := os.NewFile(3, "scanner-custody")
	defer owner.Close()
	unix.CloseOnExec(3)
	gateRead, gateWrite, err := os.Pipe()
	if err != nil {
		return containExitNotContained
	}
	defer gateWrite.Close()
	readyRead, readyWrite, err := os.Pipe()
	if err != nil {
		_ = gateRead.Close()
		return containExitNotContained
	}
	defer readyRead.Close()
	defer readyWrite.Close()
	statFDs, err := unix.Socketpair(unix.AF_UNIX, unix.SOCK_SEQPACKET|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		_ = gateRead.Close()
		return containExitNotContained
	}
	statOwner := os.NewFile(uintptr(statFDs[0]), "scanner-host-stat-owner")
	statChild := os.NewFile(uintptr(statFDs[1]), "scanner-host-stat-child")
	statOwnerFD := int(statOwner.Fd())
	var statDone chan struct{}
	defer func() {
		_ = unix.Shutdown(statOwnerFD, unix.SHUT_RDWR)
		if statDone != nil {
			select {
			case <-statDone:
			case <-time.After(containPipeWaitDelay):
			}
		}
		_ = statOwner.Close()
	}()
	defer statChild.Close()
	child := exec.Command("/proc/self/exe", argv...)
	child.Args = append([]string{containSupervisorArg0, containTrackedInit, "3,4", "--"}, argv...)
	child.Env = append(withoutEnv(os.Environ(), containHostStatEnv), containHostStatEnv+"=5")
	child.Stdin, child.Stdout, child.Stderr = os.Stdin, os.Stdout, os.Stderr
	child.ExtraFiles = []*os.File{gateRead, readyWrite, statChild}
	pidfd := -1
	child.SysProcAttr = &syscall.SysProcAttr{
		Setsid: true, Pdeathsig: syscall.SIGKILL, PidFD: &pidfd,
		Cloneflags: syscall.CLONE_NEWPID | syscall.CLONE_NEWUSER,
	}
	// Map only this scanner's IDs, even for a privileged gateway. A scanner
	// cannot switch to another mapped UID and thereby clear Pdeathsig.
	child.SysProcAttr.UidMappings = containIDMap(os.Geteuid())
	child.SysProcAttr.GidMappings = containIDMap(os.Getegid())
	child.SysProcAttr.GidMappingsEnableSetgroups = false
	if err := child.Start(); err != nil {
		_ = gateRead.Close()
		return containExitNotContained
	}
	_ = gateRead.Close()
	_ = readyWrite.Close()
	_ = statChild.Close()
	statDone = make(chan struct{})
	go func() {
		serveTrackedHostStat(statOwnerFD)
		close(statDone)
	}()
	if pidfd < 0 {
		_ = child.Process.Kill()
		_ = child.Wait()
		return containExitNotContained
	}
	defer unix.Close(pidfd)
	if os.Getppid() != expectedParent || unix.Prctl(unix.PR_SET_DUMPABLE, 0, 0, 0, 0) != nil {
		_ = unix.PidfdSendSignal(pidfd, unix.SIGKILL, nil, 0)
		_ = child.Wait()
		return containExitNotContained
	}
	var guarded [1]byte
	if _, err := io.ReadFull(readyRead, guarded[:]); err != nil || guarded[0] != 1 {
		_ = unix.PidfdSendSignal(pidfd, unix.SIGKILL, nil, 0)
		_ = child.Wait()
		return containExitNotContained
	}
	var scannerPID [4]byte
	binary.LittleEndian.PutUint32(scannerPID[:], uint32(child.Process.Pid))
	if _, err := owner.Write(scannerPID[:]); err != nil {
		_ = unix.PidfdSendSignal(pidfd, unix.SIGKILL, nil, 0)
		_ = child.Wait()
		return containExitNotContained
	}
	var acknowledge [1]byte
	if _, err := io.ReadFull(owner, acknowledge[:]); err != nil || acknowledge[0] != 1 {
		_ = unix.PidfdSendSignal(pidfd, unix.SIGKILL, nil, 0)
		_ = child.Wait()
		return containExitNotContained
	}
	_ = owner.Close()
	if _, err := gateWrite.Write([]byte{1}); err != nil {
		_ = unix.PidfdSendSignal(pidfd, unix.SIGKILL, nil, 0)
		_ = child.Wait()
		return containExitNotContained
	}
	_ = gateWrite.Close()
	releaseStdio()
	waitErr := child.Wait()
	var exitErr *exec.ExitError
	switch {
	case waitErr == nil:
		return 0
	case errors.As(waitErr, &exitErr):
		if status, ok := exitErr.Sys().(syscall.WaitStatus); ok && status.Signaled() {
			return 128 + int(status.Signal())
		}
		return exitErr.ExitCode()
	default:
		return containExitNotContained
	}
}

// execTracked is the scanner's PID-namespace init until the gate opens.
// Exec keeps PID 1 while replacing this trusted launcher with the scanner.
func execTracked(argv []string) int {
	if os.Getpid() != 1 {
		return containExitNotContained
	}
	if err := guardTrackedInit(); err != nil {
		return containExitNotContained
	}
	ready := os.NewFile(4, "scanner-filter-ready")
	unix.CloseOnExec(4)
	if _, err := ready.Write([]byte{1}); err != nil {
		_ = ready.Close()
		return containExitNotContained
	}
	_ = ready.Close()
	gate := os.NewFile(3, "scanner-start-gate")
	var token [1]byte
	n, err := gate.Read(token[:])
	_ = gate.Close()
	if err != nil || n != 1 || token[0] != 1 {
		return containExitNotContained
	}
	if err := syscall.Exec(argv[0], argv, withoutEnv(os.Environ(), containSupervisorEnv)); err != nil {
		fmt.Fprintf(os.Stderr, "processutil: start scanner: %v\n", err)
		return containExitNotStarted
	}
	return 0
}

// serveTrackedHostStat reports the real host UID for the exact inode the
// scanner inspected. A one-ID user namespace otherwise turns every root-owned
// runtime file into overflow UID 65534, which rejects the managed install.
// This broker never opens or writes a file; it rechecks dev+ino and returns
// only the metadata needed by the existing custody checks.
func serveTrackedHostStat(fd int) {
	var packet [4096 + 26]byte
	for {
		n, _, err := unix.Recvfrom(fd, packet[:], 0)
		if err != nil || n < 26 {
			return
		}
		length := int(binary.BigEndian.Uint16(packet[24:26]))
		if length == 0 || n != 26+length {
			return
		}
		uid := ^uint32(0)
		path := string(packet[26:n])
		if info, err := os.Lstat(path); err == nil {
			if stat, ok := info.Sys().(*syscall.Stat_t); ok &&
				stat.Dev == binary.BigEndian.Uint64(packet[0:8]) &&
				stat.Ino == binary.BigEndian.Uint64(packet[8:16]) {
				uid = stat.Uid
			}
		}
		var response [12]byte
		copy(response[:8], packet[16:24])
		binary.BigEndian.PutUint32(response[8:], uid)
		if _, err := unix.SendmsgN(fd, response[:], nil, nil, unix.MSG_NOSIGNAL); err != nil {
			return
		}
	}
}

// runContainedCommand is PID 1 of the hook probe's namespace. Its exit
// ends everything else in the namespace.
func runContainedCommand(argv []string) int {
	runtime.LockOSThread()
	if os.Getpid() != 1 || os.Getppid() == 1 {
		return containExitNotContained
	}
	child := exec.Command(argv[0], argv[1:]...)
	child.Env = withoutEnv(os.Environ(), containSupervisorEnv)
	child.Stdin, child.Stdout, child.Stderr = os.Stdin, os.Stdout, os.Stderr
	child.SysProcAttr = &syscall.SysProcAttr{Setpgid: true, Pdeathsig: syscall.SIGKILL}
	if err := child.Start(); err != nil {
		return containExitNotStarted
	}
	releaseStdio()
	err := child.Wait()
	var exitErr *exec.ExitError
	switch {
	case err == nil:
		return 0
	case errors.As(err, &exitErr):
		if status, ok := exitErr.Sys().(syscall.WaitStatus); ok && status.Signaled() {
			return 128 + int(status.Signal())
		}
		return exitErr.ExitCode()
	default:
		return containExitNotContained
	}
}

// releaseStdio points the supervisor's standard streams at /dev/null.
func releaseStdio() {
	null, err := unix.Open(os.DevNull, unix.O_RDWR|unix.O_CLOEXEC, 0)
	if err != nil {
		return
	}
	for fd := 0; fd <= 2; fd++ {
		_ = unix.Dup3(null, fd, 0)
	}
	_ = unix.Close(null)
}

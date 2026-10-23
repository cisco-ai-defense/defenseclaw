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
	"errors"
	"fmt"
	"math"
	"os"
	"os/exec"
	"os/signal"
	"runtime"
	"strconv"
	"strings"
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
// RunTracked runs cmd below a child subreaper custodian and a separate
// runner. A command that kills its immediate parent kills the runner; its
// descendants are then reparented to the custodian, which kills and reaps
// them. The command cannot end the custodian instead: the runner's seccomp
// filter refuses positive signal targets and remote prlimit, and the runner
// starts a separate session so a command cannot join the custodian's group
// and signal it with kill(0) (guardCustodian). The custodian is a
// separate process so gateway children are never included in its sweep. Scanners keep it: without privilege the PID
// namespace needs a user namespace mapping only this process's IDs, where
// root-owned files read as owned by the overflow user, and DefenseClaw's own
// plugin-scanner then refuses its root-owned runtime.
const (
	containSupervisorArg0 = "defenseclaw-contained-run"
	containSupervisorEnv  = "DEFENSECLAW_CONTAINED_RUN_SUPERVISOR"
	containCustodianMode  = "custodian"
	containRunnerMode     = "runner"
	containInitMode       = "init"
	containLauncherMode   = "launcher"
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
)

// containSweepBudget bounds the supervisor's sweep of what the command left;
// tests set it to zero to reach the fail-closed result.
var containSweepBudget = 2 * time.Second

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
	budget, err := time.ParseDuration(os.Args[2])
	if err != nil || budget < 0 {
		os.Exit(containExitNotContained)
	}
	switch os.Args[1] {
	case containCustodianMode:
		os.Exit(superviseContained(os.Args[4:], budget))
	case containRunnerMode:
		os.Exit(runContainedCommand(os.Args[4:], false))
	case containInitMode:
		os.Exit(runContainedCommand(os.Args[4:], true))
	case containLauncherMode:
		os.Exit(launchContained(os.Args[4:]))
	default:
		os.Exit(containExitNotContained)
	}
}

func runContained(cmd *exec.Cmd) error {
	if cmd.Process != nil {
		return errors.New("processutil: RunContained: already started")
	}
	mode := containInitMode
	if mixedCredentials() || !dumpable() {
		mode = containLauncherMode
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
		return fmt.Errorf("%w: %s: %v", ErrNotContained, target, err)
	}
	err := cmd.Wait()
	var exitErr *exec.ExitError
	if errors.As(err, &exitErr) && exitErr.ExitCode() == containExitNotContained {
		return fmt.Errorf("%w: %s", ErrNotContained, target)
	}
	return err
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
	go func() {
		<-terms
		cancel()
	}()
	child := exec.CommandContext(ctx, argv[0], argv[1:]...)
	child.Env = withoutEnv(os.Environ(), containSupervisorEnv)
	child.Stdin, child.Stdout, child.Stderr = os.Stdin, os.Stdout, os.Stderr
	err := runContained(child)
	var exitErr *exec.ExitError
	switch {
	case ctx.Err() != nil:
		return containExitTerminated
	case err == nil:
		return 0
	case errors.As(err, &exitErr) && exitErr.ExitCode() >= 0:
		return exitErr.ExitCode()
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

// runTracked runs cmd below the subreaper custodian, which owns every orphan
// of the tree.
func runTracked(cmd *exec.Cmd) error {
	if cmd.Process != nil {
		return errors.New("processutil: RunTracked: already started")
	}
	target := cmd.Path
	cmd.Path = "/proc/self/exe"
	cmd.Args = append([]string{containSupervisorArg0, containCustodianMode, containSweepBudget.String(), "--", target}, cmd.Args[1:]...)
	env := cmd.Env
	if env == nil {
		env = os.Environ()
	}
	cmd.Env = append(withoutEnv(env, containSupervisorEnv), containSupervisorEnv+"=1")
	if cmd.SysProcAttr == nil {
		cmd.SysProcAttr = &syscall.SysProcAttr{}
	}
	cmd.SysProcAttr.Setpgid = true
	// The supervisor ends and reaps the tree when this thread dies or the
	// command is canceled. Killing the supervisor instead would hand what
	// left the command's group to init.
	cmd.SysProcAttr.Pdeathsig = syscall.SIGTERM
	if cmd.Cancel != nil {
		cmd.Cancel = func() error { return cmd.Process.Signal(syscall.SIGTERM) }
	}
	// The parent-death signal follows the thread that started the child.
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	err := cmd.Run()
	var exitErr *exec.ExitError
	if errors.As(err, &exitErr) && exitErr.ExitCode() == containExitNotContained {
		return fmt.Errorf("%w: %s", ErrNotContained, target)
	}
	return err
}

// superviseContained owns the tree after the runner exits, including when a
// hook sends SIGKILL to the runner. Its own wait and sweep are confined to this
// process, never to the gateway that launched it.
func superviseContained(argv []string, budget time.Duration) int {
	runtime.LockOSThread()
	terms := make(chan os.Signal, 1)
	signal.Notify(terms, syscall.SIGTERM)
	if err := unix.Prctl(unix.PR_SET_CHILD_SUBREAPER, 1, 0, 0, 0); err != nil {
		return containExitNotContained
	}
	// Not dumpable: the command cannot trace it or write its memory.
	if err := unix.Prctl(unix.PR_SET_DUMPABLE, 0, 0, 0, 0); err != nil {
		return containExitNotContained
	}
	if os.Getppid() == 1 {
		// The parent died before the parent-death signal was armed.
		return containExitTerminated
	}
	child := exec.Command("/proc/self/exe", argv...)
	child.Args = append([]string{containSupervisorArg0, containRunnerMode, budget.String(), "--"}, argv...)
	child.Env = os.Environ()
	child.Stdin, child.Stdout, child.Stderr = os.Stdin, os.Stdout, os.Stderr
	// A separate session keeps the command from joining the custodian's
	// process group, which would let kill(0) bypass the signal filter.
	child.SysProcAttr = &syscall.SysProcAttr{Setsid: true, Pdeathsig: syscall.SIGKILL}
	if err := child.Start(); err != nil {
		return containExitNotStarted
	}
	// Only the command and what it started hold its streams now, so the
	// parent's pipe closes when they are gone.
	releaseStdio()
	done := make(chan error, 1)
	go func() { done <- child.Wait() }()
	terminated := false
	var waitErr error
	select {
	case waitErr = <-done:
	case <-terms:
		terminated = true
		_ = unix.Kill(-child.Process.Pid, unix.SIGKILL)
		_ = child.Process.Kill()
		waitErr = <-done
	}
	if !reapAllChildren(budget) {
		return containExitNotContained
	}
	select {
	case <-terms:
		terminated = true
	default:
	}
	if terminated {
		return containExitTerminated
	}
	var exitErr *exec.ExitError
	switch {
	case waitErr == nil:
		return 0
	case errors.As(waitErr, &exitErr):
		if status, ok := exitErr.Sys().(syscall.WaitStatus); ok && status.Signaled() {
			return containExitNotContained
		}
		return exitErr.ExitCode()
	default:
		return containExitNotContained
	}
}

// runContainedCommand is the command's immediate parent. Below the custodian
// it is deliberately not a subreaper: if the command kills it, every orphan
// moves to the custodian. As the init of a PID namespace (asInit), its exit
// ends everything else in the namespace.
func runContainedCommand(argv []string, asInit bool) int {
	runtime.LockOSThread()
	if asInit != (os.Getpid() == 1) || os.Getppid() == 1 {
		return containExitNotContained
	}
	// Below the custodian, the command must not end it (GAP-0631). This
	// thread starts the command, so the filter is the command's.
	if !asInit && guardCustodian(os.Getppid()) != nil {
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

// reapAllChildren kills and reaps this process's children until it has
// none. As a subreaper, this process becomes the parent of every orphaned
// descendant, so no child left means no descendant left. It reports false
// when children remain after budget.
func reapAllChildren(budget time.Duration) bool {
	deadline := time.Now().Add(budget)
	self := os.Getpid()
	for {
		for {
			var status unix.WaitStatus
			pid, err := unix.Wait4(-1, &status, unix.WNOHANG, nil)
			if errors.Is(err, unix.ECHILD) {
				return true
			}
			if errors.Is(err, unix.EINTR) {
				continue
			}
			if err != nil {
				return false
			}
			if pid <= 0 {
				break
			}
		}
		if !time.Now().Before(deadline) {
			return false
		}
		for _, pid := range childPIDs(self) {
			_ = unix.Kill(pid, unix.SIGKILL)
		}
		time.Sleep(5 * time.Millisecond)
	}
}

// childPIDs lists the processes whose parent is parent.
func childPIDs(parent int) []int {
	entries, err := os.ReadDir("/proc")
	if err != nil {
		return nil
	}
	want := strconv.Itoa(parent)
	var pids []int
	for _, entry := range entries {
		pid, err := strconv.Atoi(entry.Name())
		if err != nil {
			continue
		}
		raw, err := os.ReadFile("/proc/" + entry.Name() + "/stat")
		if err != nil {
			continue
		}
		stat := string(raw)
		fields := strings.Fields(stat[strings.LastIndexByte(stat, ')')+1:])
		if len(fields) > 1 && fields[1] == want {
			pids = append(pids, pid)
		}
	}
	return pids
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

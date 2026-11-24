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
	"errors"
	"fmt"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sync"
	"syscall"
	"time"

	"golang.org/x/sys/unix"
)

// The pod-contained mode (GAP-0828). A container's default seccomp profile
// (Kubernetes RuntimeDefault) refuses the user and PID namespaces RunTracked
// needs to a non-root container with no capabilities, so in the Agent
// Substrate scanner sidecar RunTracked always fails closed and nothing is
// scanned. There the container is the boundary instead: the scan worker is
// PID 1 of the container's own PID namespace (the pod does not share process
// namespaces), it runs one scanner at a time as its direct child, and after
// each one it kills and reaps every other process in the namespace and
// empties the scratch folder. Only the scan worker selects this mode, from an
// explicit flag the chart passes; nothing selects it after a namespace call
// fails, and RunTracked is unchanged everywhere.
//
// The scanner shares the worker's user, so the container's own limits do not
// keep it from the worker: its Landlock domain allows writes only beneath the
// scratch folder (and to /dev/null), and reads only its private job and the
// runtime (GAP-0873, GAP-0902). It may not signal the worker (GAP-0874;
// Landlock signal scoping, or a seccomp filter on kernels without it).
const containPodMode = "pod-scanner"

// podSweepTimeout bounds how long a sweep waits for the killed processes to
// be reaped before it reports the namespace as not empty.
const podSweepTimeout = 5 * time.Second

// PodRunner runs scanner commands in the pod-contained mode. Run and Reset
// take one lock, so at most one scanner runs at a time.
type PodRunner struct {
	mu       sync.Mutex
	scratch  string
	clear    []string
	setup    error
	prepared bool
}

// NewPodRunner returns the pod's scan worker runner. scratch is the one
// folder the scanner may write, which Reset empties after each job (the
// container's tmp); Reset also empties each folder of clear (the pod's
// /dev/shm). A runner with no usable scratch folder refuses every command;
// Check says why.
func NewPodRunner(scratch string, clear ...string) *PodRunner {
	p := &PodRunner{scratch: filepath.Clean(scratch)}
	for _, d := range append([]string{scratch}, clear...) {
		c := filepath.Clean(d)
		if d == "" || c == "/" || !filepath.IsAbs(c) {
			p.setup = fmt.Errorf("the folder %q is not an absolute folder below /", d)
			return p
		}
		if d != scratch {
			p.clear = append(p.clear, c)
		}
	}
	return p
}

// prepareLocked makes this process, once it is known to be PID 1, the pod's
// scan worker: no core dumps and no ptrace or /proc memory access by its
// same-UID children (PR_SET_DUMPABLE 0), and no privilege gain by anything
// it starts (PR_SET_NO_NEW_PRIVS).
func (p *PodRunner) prepareLocked() error {
	if p.prepared {
		return nil
	}
	if unix.Prctl(unix.PR_SET_DUMPABLE, 0, 0, 0, 0) != nil {
		return podUnavailable("cannot make the scan worker non-dumpable")
	}
	if unix.Prctl(unix.PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != nil {
		return podUnavailable("cannot set no_new_privs on the scan worker")
	}
	p.prepared = true
	return nil
}

func podUnavailable(format string, args ...any) error {
	return &podError{msg: fmt.Sprintf(format, args...)}
}

// podRestart is a refusal only a new container can clear (ErrPodRestart).
func podRestart(format string, args ...any) error {
	return &podError{msg: fmt.Sprintf(format, args...), restart: true}
}

// Check reports whether this process can contain a scanner in pod mode: it
// is PID 1 of its PID namespace, it is not root and has no capabilities, it
// is in the chart's container (podMountsCheck: a read-only root and its own
// mount on each folder Reset empties, GAP-1031), and no other process runs
// in the namespace. It kills and reaps any other
// process first (a kubectl exec, a scanner's leftover).
func (p *PodRunner) Check() error {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.checkLocked()
}

func (p *PodRunner) checkLocked() error {
	if p.setup != nil {
		return podUnavailable("%v", p.setup)
	}
	if os.Getpid() != 1 {
		return podUnavailable("it is PID %d, not PID 1 of the container's own PID namespace (is shareProcessNamespace set?)", os.Getpid())
	}
	if os.Geteuid() == 0 {
		return podUnavailable("it runs as root; the sidecar must run as a non-root user")
	}
	if caps := effectiveCapabilities(); caps != 0 {
		return podUnavailable("it has capabilities (effective %#x); the sidecar must drop all", caps)
	}
	if err := podMountsCheck(p.scratch, p.clear); err != nil {
		return podUnavailable("%v", err)
	}
	if err := podGuardAvailable(); err != nil {
		return podUnavailable("%v", err)
	}
	if err := p.prepareLocked(); err != nil {
		return err
	}
	return p.sweepLocked()
}

// sweepLocked kills every process of the namespace but this one, reaps them,
// and checks that none is left. Only PID 1 may call it: kill(-1) of any
// other process reaches every process of its user outside the namespace too.
func (p *PodRunner) sweepLocked() error {
	deadline := time.Now().Add(podSweepTimeout)
	for {
		// As PID 1, kill(-1) reaches every other process in the namespace,
		// whatever its session or group, and never this one.
		_ = unix.Kill(-1, unix.SIGKILL)
		var err error
		for {
			var status unix.WaitStatus
			var pid int
			pid, err = unix.Wait4(-1, &status, unix.WNOHANG, nil)
			if pid <= 0 && !errors.Is(err, unix.EINTR) {
				break
			}
		}
		if errors.Is(err, unix.ECHILD) {
			// kill(-1, 0) from PID 1 finds no process exactly when no other
			// process is left in this namespace or one below it; one it may
			// not signal (another user) answers EPERM.
			alone := errors.Is(unix.Kill(-1, 0), unix.ESRCH)
			if alone {
				return nil
			}
			if time.Now().After(deadline) {
				return podRestart("other processes still run in the namespace after the sweep")
			}
		} else if time.Now().After(deadline) {
			return podRestart("killed children were not reaped in %s", podSweepTimeout)
		}
		time.Sleep(5 * time.Millisecond)
	}
}

// Run runs cmd as a direct child of the scan worker after a Check, behind
// the scanner's Landlock domain and filter (guardPodScanner) and at the
// scanner's lower priority, then sweeps the namespace. A command that ran but
// left a process that could not be killed and reaped is reported as
// unavailable, never as a result.
func (p *PodRunner) Run(cmd *exec.Cmd) error { return p.run(cmd, "") }

// RunJob confines a scan to one private job folder. The caller moves the
// accepted job there before starting the scanner.
func (p *PodRunner) RunJob(cmd *exec.Cmd, readJob string) error {
	if !filepath.IsAbs(readJob) || filepath.Clean(readJob) != readJob || readJob == "/" {
		return fmt.Errorf("%w: invalid private scan job %q", ErrNotContained, readJob)
	}
	fi, err := os.Lstat(readJob)
	if err != nil || !fi.IsDir() {
		return fmt.Errorf("%w: private scan job is not a real folder: %v", ErrNotContained, err)
	}
	return p.run(cmd, readJob)
}

func (p *PodRunner) run(cmd *exec.Cmd, readJob string) error {
	if cmd.Process != nil {
		return errors.New("processutil: PodRunner.Run: already started")
	}
	if len(cmd.ExtraFiles) != 0 {
		return errors.New("processutil: PodRunner.Run: ExtraFiles are not passed to the scanner")
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if err := p.checkLocked(); err != nil {
		return err
	}
	target := cmd.Path
	cmd.Path = "/proc/self/exe"
	cmd.Args = append([]string{containSupervisorArg0, containPodMode, p.scratch, readJob, "--", target}, cmd.Args[1:]...)
	env := cmd.Env
	if env == nil {
		env = os.Environ()
	}
	cmd.Env = append(withoutEnv(env, containSupervisorEnv), containSupervisorEnv+"=1")
	if cmd.SysProcAttr == nil {
		cmd.SysProcAttr = &syscall.SysProcAttr{}
	}
	cmd.SysProcAttr.Setpgid = true
	cmd.SysProcAttr.Pdeathsig = syscall.SIGKILL
	if cmd.WaitDelay == 0 || cmd.WaitDelay > containPipeWaitDelay {
		cmd.WaitDelay = containPipeWaitDelay
	}
	pidfd := -1
	cmd.SysProcAttr.PidFD = &pidfd
	// Pdeathsig follows the thread that started the child.
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	if err := cmd.Start(); err != nil {
		return fmt.Errorf("%w: %s: %v", ErrNotContained, target, err)
	}
	if pidfd >= 0 {
		// When the scanner ends, end what it left at once, as the end of
		// RunTracked's namespace does: a leftover holding its output
		// cannot add to it or hold Wait.
		waitPidfdExit(pidfd)
		_ = unix.Close(pidfd)
		_ = unix.Kill(-1, unix.SIGKILL)
	}
	err := cmd.Wait()
	if serr := p.sweepLocked(); serr != nil {
		return serr
	}
	if pidfd < 0 {
		return fmt.Errorf("%w: no scanner pidfd", ErrNotContained)
	}
	if err != nil && !errors.As(err, new(*exec.ExitError)) {
		return fmt.Errorf("%w: %s: %v", ErrNotContained, target, err)
	}
	return err
}

// waitPidfdExit waits until the process of fd has ended; a poll error ends
// the wait early, and the caller's kill then ends the process.
func waitPidfdExit(fd int) {
	events := []unix.PollFd{{Fd: int32(fd), Events: unix.POLLIN}}
	for {
		if _, err := unix.Poll(events, -1); !errors.Is(err, unix.EINTR) {
			return
		}
	}
}

// Reset ends a job: it sweeps the namespace and empties the scratch folder
// and the clear folders, so nothing a scan started or wrote reaches the next
// one. A sweep or a folder that fails is ErrPodRestart: what is left there
// stays until the container is replaced (GAP-0875).
func (p *PodRunner) Reset() error {
	p.mu.Lock()
	defer p.mu.Unlock()
	if err := p.checkLocked(); err != nil {
		return err
	}
	for i, dir := range append([]string{p.scratch}, p.clear...) {
		err := emptyFolder(dir)
		if i > 0 && errors.Is(err, fs.ErrNotExist) {
			// A container without that folder has nothing to clear.
			continue
		}
		if err != nil {
			return podRestart("cannot empty %s: %v", dir, err)
		}
	}
	return nil
}

// emptyFolder removes everything in dir. The scanner may have made a folder
// of its own (or dir itself, where it owns it) read-only to the worker's
// user, which it shares, so each folder gets the user's write and search
// access back before it is removed (GAP-0875). Links are removed, never
// followed.
func emptyFolder(dir string) error {
	fi, err := os.Lstat(dir)
	if err != nil {
		return err
	}
	if !fi.IsDir() {
		return fmt.Errorf("%s is not a folder", dir)
	}
	if fi.Mode().Perm()&0o700 != 0o700 {
		if err := os.Chmod(dir, fi.Mode().Perm()|0o700); err != nil {
			return err
		}
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		return err
	}
	for _, e := range entries {
		path := filepath.Join(dir, e.Name())
		_ = filepath.WalkDir(path, func(p string, d fs.DirEntry, err error) error {
			if err == nil && d.IsDir() {
				_ = os.Chmod(p, 0o700)
			}
			return nil
		})
		if err := os.RemoveAll(path); err != nil {
			return err
		}
	}
	return nil
}

// execPodScanner is the trusted stage between the scan worker and the
// scanner: it enters the scanner's Landlock domain and filter, which allow
// writes only beneath scratch and reads only the private job and runtime,
// then execs it.
func execPodScanner(argv []string, scratch, readJob string) int {
	if os.Getppid() != 1 || !filepath.IsAbs(scratch) || filepath.Clean(scratch) != scratch || scratch == "/" ||
		(readJob != "" && (!filepath.IsAbs(readJob) || filepath.Clean(readJob) != readJob || readJob == "/")) {
		return containExitNotContained
	}
	lowerScannerPriority()
	if err := guardPodScanner(scratch, readJob); err != nil {
		fmt.Fprintf(os.Stderr, "processutil: scanner guard: %v\n", err)
		return containExitNotContained
	}
	if err := syscall.Exec(argv[0], argv, withoutEnv(os.Environ(), containSupervisorEnv)); err != nil {
		fmt.Fprintf(os.Stderr, "processutil: start scanner: %v\n", err)
		return containExitNotStarted
	}
	return 0
}

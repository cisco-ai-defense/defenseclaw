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

//go:build darwin

package processutil

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"syscall"

	"golang.org/x/sys/unix"
)

const (
	containDarwinArg0       = "defenseclaw-contained-forkless"
	containExitNotContained = 125
)

var armContainedDarwinWatchdog = armGroupWatchdog

func init() {
	if len(os.Args) < 4 || os.Args[0] != containDarwinArg0 || os.Args[2] != "--" {
		return
	}
	gateFD, err := strconv.Atoi(os.Args[1])
	if err != nil || gateFD < 3 {
		os.Exit(containExitNotContained)
	}
	os.Exit(execForklessDarwin(gateFD, os.Args[3:]))
}

// runContained launches a short-lived copy of this binary. Only that copy
// changes credentials and RLIMIT_NPROC; the long-lived gateway and its other
// children keep their normal limits. The kernel refuses fork and posix_spawn
// for a non-root process with a zero process limit, even if the hook leaves
// its process group and closes every inherited descriptor.
func runContained(cmd *exec.Cmd) error {
	if cmd.Process != nil {
		return errors.New("processutil: RunContained: already started")
	}
	self, err := os.Executable()
	if err != nil {
		return fmt.Errorf("%w: locate forkless launcher: %v", ErrNotContained, err)
	}
	gateRead, gateWrite, err := os.Pipe()
	if err != nil {
		return fmt.Errorf("%w: create launch gate: %v", ErrNotContained, err)
	}
	defer gateRead.Close()
	defer gateWrite.Close()
	gateFD := 3 + len(cmd.ExtraFiles)
	cmd.ExtraFiles = append(cmd.ExtraFiles, gateRead)
	target := cmd.Path
	cmd.Path = self
	cmd.Args = append([]string{containDarwinArg0, strconv.Itoa(gateFD), "--", target}, cmd.Args[1:]...)
	err = runContainedDarwinArmed(cmd, gateRead, gateWrite)
	var exitErr *exec.ExitError
	if errors.As(err, &exitErr) && exitErr.ExitCode() == containExitNotContained {
		return fmt.Errorf("%w: forkless launcher for %s", ErrNotContained, target)
	}
	return err
}

// The launcher remains in its own process group and waits for one byte before
// it may execute the command. The gateway arms the watchdog first. If the
// gateway dies before that point, the gate closes and the command does not
// run; after that point, the watchdog owns the group until the command has
// exited.
func runContainedDarwinArmed(cmd *exec.Cmd, gateRead, gateWrite *os.File) error {
	r, w, err := os.Pipe()
	if err != nil {
		return fmt.Errorf("%w: lifeline: %v", ErrNotContained, err)
	}
	defer r.Close()
	defer w.Close()
	cmd.ExtraFiles = append(cmd.ExtraFiles, w)
	exitWithParent(cmd)
	if err := cmd.Start(); err != nil {
		return err
	}
	_ = gateRead.Close()
	_ = w.Close()
	release, err := armContainedDarwinWatchdog(cmd.Process.Pid)
	if err != nil {
		_ = gateWrite.Close()
		_ = killGroup(cmd.Process.Pid)
		_ = cmd.Wait()
		return fmt.Errorf("%w: %v", ErrNotContained, err)
	}
	_, gateErr := gateWrite.Write([]byte{1})
	_ = gateWrite.Close()
	exited := waitExitedUnreaped(cmd.Process.Pid)
	_ = killGroup(cmd.Process.Pid)
	release()
	waitErr := cmd.Wait()
	if gateErr != nil || !exited {
		return fmt.Errorf("%w: command launch or exit could not be proven", ErrNotContained)
	}
	if waitErr != nil {
		return waitErr
	}
	if !lifelineClosed(r, lifelineWait) {
		return fmt.Errorf("%w: command left an inherited lifeline open", ErrNotContained)
	}
	return nil
}

// execForklessDarwin changes the real UID before applying RLIMIT_NPROC. The
// managed guardian invokes Verify with a target user's effective UID but
// retains real UID 0; XNU checks the real UID and exempts root from this
// limit, so the launcher must irrevocably drop both IDs first.
func execForklessDarwin(gateFD int, argv []string) int {
	gate := os.NewFile(uintptr(gateFD), "launch gate")
	if gate == nil {
		return containExitNotContained
	}
	var token [1]byte
	n, err := gate.Read(token[:])
	_ = gate.Close()
	if err != nil || n != 1 || token[0] != 1 {
		return containExitNotContained
	}
	uid, euid, egid := os.Getuid(), os.Geteuid(), os.Getegid()
	if euid <= 0 {
		return containExitNotContained
	}
	if uid == 0 {
		if err := unix.Seteuid(0); err != nil {
			return containExitNotContained
		}
		if err := unix.Setgid(egid); err != nil {
			return containExitNotContained
		}
		if err := unix.Setuid(euid); err != nil {
			return containExitNotContained
		}
	} else if uid != euid {
		return containExitNotContained
	}
	if os.Getuid() != euid || os.Geteuid() != euid {
		return containExitNotContained
	}
	if err := unix.Setrlimit(unix.RLIMIT_NPROC, &unix.Rlimit{Cur: 0, Max: 0}); err != nil {
		return containExitNotContained
	}
	// Verify the limit at use, so a future kernel that ignores this limit
	// fails the proof before the registered hook gets to run.
	self, err := os.Executable()
	if err != nil {
		return containExitNotContained
	}
	pid, err := syscall.ForkExec(self, []string{"defenseclaw-fork-test"}, &syscall.ProcAttr{Files: []uintptr{0, 1, 2}})
	if err == nil {
		_ = syscall.Kill(pid, syscall.SIGKILL)
		_, _ = syscall.Wait4(pid, nil, 0, nil)
		return containExitNotContained
	}
	if !errors.Is(err, syscall.EAGAIN) {
		return containExitNotContained
	}
	// The proof must come from the registered hook. Noninteractive bash reads
	// BASH_ENV and imports exported functions before its script starts.
	for _, entry := range os.Environ() {
		name, _, _ := strings.Cut(entry, "=")
		if name == "BASH_ENV" || name == "ENV" || strings.HasPrefix(name, "BASH_FUNC_") {
			if err := os.Unsetenv(name); err != nil {
				return containExitNotContained
			}
		}
	}
	if err := syscall.Exec(argv[0], argv, os.Environ()); err != nil {
		return containExitNotContained
	}
	return 0
}

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

// Package processutil creates noninteractive subprocesses whose standard
// streams are captured by DefenseClaw.
package processutil

import (
	"context"
	"errors"
	"os/exec"
)

// CommandContext is equivalent to exec.CommandContext with platform-specific
// configuration for a captured background process.
func CommandContext(ctx context.Context, name string, args ...string) *exec.Cmd {
	cmd := exec.CommandContext(ctx, name, args...)
	configureCapturedCommand(cmd)
	return cmd
}

// CombinedOutputTree captures cmd's combined output. On Windows, cancellation
// and command completion terminate every non-breakaway descendant through a
// kill-on-close Job Object. On other platforms, it is equivalent to
// cmd.CombinedOutput and does not guarantee descendant cleanup.
//
// allowManagedBreakaway is reserved for trusted launchers whose separately
// identity-checked daemon must intentionally survive the short-lived command.
func CombinedOutputTree(cmd *exec.Cmd, allowManagedBreakaway bool) ([]byte, error) {
	return combinedOutputTree(cmd, allowManagedBreakaway)
}

// RunTree runs cmd with the streams the caller set and ties it to this
// process: on Windows a kill-on-close Job Object ends the whole tree. On
// Linux and macOS the child runs in a process group of its own, and the
// group is killed when the child exits, when cmd is canceled and when this
// process dies, also when it ends with os.Exit; on Linux the child also gets
// SIGKILL when this process dies. A killed gateway left its skill-scanner
// running at full CPU, and a second one started for the same skill after the
// restart (GAP-0418); a managed hook that exited once its answer was out
// left the tools it had started running (G-small); a Hermes hook Verify
// probed on macOS left the child it started running (r104 W5b). A
// descendant that leaves the group (setsid, setpgid) is not followed; use
// RunContained when the result must prove that nothing is left. Other
// platforms run cmd as is.
func RunTree(cmd *exec.Cmd) error {
	return runTree(cmd, false)
}

// ErrNotContained reports that RunContained could not establish that the
// command left nothing running.
var ErrNotContained = errors.New("processutil: could not establish that the command left nothing running")

// RunContained is RunTree for a command whose success counts only when
// nothing it started outlives it. A Hermes hook that Verify probed could
// start a child in a session of its own (setsid), out of the process group
// RunTree kills, and Verify passed while the child kept running (r104 W5b).
//
// On Linux the command runs below a runner that is PID 1 of a new PID
// namespace, owned by a user namespace of its own unless this process may
// create one without (CAP_SYS_ADMIN). The command cannot address any process
// outside the namespace, and when the runner ends, however it ends, the
// kernel kills every process in it, also one that left the group or session.
// A hook that SIGKILLed the child-subreaper custodian used before left its
// setsid child running (r104 W5b review). Where the namespaces cannot be
// created, RunContained never runs cmd and returns ErrNotContained.
// On macOS a short-lived launcher waits for the gateway's process-group
// watchdog before it irreversibly drops real root credentials (if any),
// checks that RLIMIT_NPROC prevents forks, and executes the command with
// that limit. A descendant cannot start, including one that would close
// inherited descriptors. On Windows it is RunTree: the Job
// Object refuses breakaway. Other
// platforms never run cmd and return ErrNotContained.
//
// cmd must not have been started. On Linux, cmd.Cancel kills the runner and
// with it the tree.
func RunContained(cmd *exec.Cmd) error {
	return runContained(cmd)
}

// RunTracked runs a command under a process-tree supervisor without limiting
// what it may start: the skill-scanner starts helpers on every scan, and the
// no-fork launcher of RunContained failed every macOS gateway skill scan
// (r104 W5b). The supervisor ends descendants when the command exits, cmd is
// canceled, or this process dies, subject to the OS limits below.
//
// On Linux a trusted launcher starts the command as PID 1 of a new PID and
// user namespace. When the command exits, the kernel ends every process in
// that namespace, including detached children. The gateway holds the
// launcher's pidfd, and the launcher holds the command's pidfd. Parent-death
// signals link both processes to their owners. The command can signal its
// children by PID; the gateway and launcher are outside its PID namespace and
// its Landlock domain, which refuses ptrace access (memory, environment,
// descriptors) to every process outside it, and its inherited seccomp filter
// refuses ptrace, cross-process memory/fd access and clearing its parent-death
// signal. Containment changes only the command's tree, never this process's
// own state, so daemon status, stop, restart and upgrade work during a scan.
// A read-only launcher channel reports the real UID of an inode after matching
// its device and inode numbers, so managed root-owned files retain their
// custody checks. If a namespace, pidfd, Landlock domain or filter cannot be
// established, nothing from the command runs and RunTracked returns
// ErrNotContained.
// On macOS a supervisor, a short-lived copy of this binary in a process
// group of its own, runs the command in a session of its own. It follows
// every descendant with kqueue NOTE_FORK and NOTE_EXIT and the
// process table, by parent, group and session, also once it starts a
// session of its own; it watches this process with NOTE_EXIT. To end the
// tree it stops every process, reads the table again until nothing new
// appears, and only then kills them, so no parent dies with a child it has
// not seen. It reports each process it follows; if the supervisor itself
// dies, RunTracked kills those and returns ErrNotContained. Known limit: a
// child that forks, starts a new session and exits, all before the next
// table read, hands its own child to launchd unseen; when that child keeps
// the inherited lifeline descriptor the run fails with ErrNotContained,
// otherwise it is not found. Processes started through launchd (open,
// launchctl, XPC) are not descendants. On Windows it is RunTree: the Job
// Object refuses breakaway. Other platforms never run cmd and return
// ErrNotContained.
//
// cmd must not have been started. On Linux and macOS it must not set
// ExtraFiles. Both platforms set a bounded WaitDelay when needed so a dead
// supervisor cannot leave RunTracked waiting on a descendant's pipe.
// cmd.Cancel asks the supervisor to end the tree.
func RunTracked(cmd *exec.Cmd) error {
	return runTracked(cmd)
}

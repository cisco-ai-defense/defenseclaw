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
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"
	"unsafe"

	"github.com/defenseclaw/defenseclaw/internal/managed"
	"golang.org/x/sys/unix"
)

// Shell fragments for the tests below. $1 is the pid file. The escaped
// child writes its own pid as this test sees it (/proc/self, not $$, which
// counts in the command's PID namespace), then runs as sleep with that pid.
const (
	containChild     = `sh -c 'read -r p _ < /proc/self/stat; echo $p > "$0"; exec sleep 60' "$1" </dev/null >/dev/null 2>&1`
	containClosedFDs = `sh -c 'read -r p _ < /proc/self/stat; echo $p > "$0"; exec sleep 60 3>&- 4>&- 5>&- 6>&- 7>&- 8>&- 9>&-' "$1" </dev/null >/dev/null 2>&1`
	containWaitPID   = `while [ ! -s "$1" ]; do sleep 0.01; done`
	containNewGroup  = `perl -e 'setpgrp(0, 0) or die; exec @ARGV or die' `
)

// Both contained hook probes and tracked scanners must end detached children.
var containRunners = map[string]func(*exec.Cmd) error{"RunContained": RunContained, "RunTracked": RunTracked}

func requireContainTools(t *testing.T) {
	t.Helper()
	for _, tool := range []string{"setsid", "perl"} {
		if _, err := exec.LookPath(tool); err != nil {
			t.Skipf("%s not installed", tool)
		}
	}
}

// r104 W5b: RunTree kills the command's process group only. A descendant in
// a session or group of its own outlived it, and the Hermes probe passed.
func TestRunContainedEndsDescendantsThatLeaveTheGroup(t *testing.T) {
	requireContainTools(t)
	for _, tc := range []struct {
		name    string
		script  string
		timeout time.Duration
		wantErr bool
	}{
		{"new session", "setsid " + containChild + " &\n" + containWaitPID + "\nexit 0", time.Minute, false},
		{"double fork into a new session", "( setsid " + containChild + " & )\n" + containWaitPID + "\nexit 0", time.Minute, false},
		{"new session, inherited descriptors closed", "setsid " + containClosedFDs + " &\n" + containWaitPID + "\nexit 0", time.Minute, false},
		{"own process group", containNewGroup + containChild + " &\n" + containWaitPID + "\nexit 0", time.Minute, false},
		{"session leader that forks again", `setsid sh -c '( sh -c "read -r p _ < /proc/self/stat; echo \$p > \"\$0\"; exec sleep 60" "$0" & ) ; exit 0' "$1" </dev/null >/dev/null 2>&1 &` + "\n" + containWaitPID + "\nexit 0", time.Minute, false},
		{"canceled", "setsid " + containChild + " &\n" + containWaitPID + "\nsleep 60", 500 * time.Millisecond, true},
	} {
		for name, run := range containRunners {
			t.Run(name+"/"+tc.name, func(t *testing.T) {
				pidFile := filepath.Join(t.TempDir(), "escaped.pid")
				ctx, cancel := context.WithTimeout(context.Background(), tc.timeout)
				defer cancel()
				cmd := CommandContext(ctx, "/bin/sh", "-c", tc.script, "sh", pidFile)
				cmd.WaitDelay = time.Second
				err := run(cmd)
				pid := readContainPID(t, pidFile)
				if helperRunning(pid) {
					_ = syscall.Kill(pid, syscall.SIGKILL)
					t.Fatalf("%s returned (%v) while descendant %d still runs", name, err, pid)
				}
				if (err != nil) != tc.wantErr {
					t.Fatalf("%s = %v, want error %v", name, err, tc.wantErr)
				}
			})
		}
	}
}

// Where the runner's namespaces cannot be created, the command never runs.
func TestRunContainedFailsClosedWithoutANamespace(t *testing.T) {
	if effectiveCapabilities() != 0 {
		t.Skip("a privileged process maps no IDs of its own")
	}
	previous := containIDMap
	containIDMap = func(id int) []syscall.SysProcIDMap {
		return []syscall.SysProcIDMap{{ContainerID: id, HostID: id + 1, Size: 1}}
	}
	t.Cleanup(func() { containIDMap = previous })
	ran := filepath.Join(t.TempDir(), "ran")
	err := runContainedDirect(CommandContext(context.Background(), "/bin/sh", "-c", `: > "$1"`, "sh", ran))
	if !errors.Is(err, ErrNotContained) {
		t.Fatalf("RunContained = %v, want ErrNotContained", err)
	}
	if _, statErr := os.Stat(ran); statErr == nil {
		t.Fatal("the command ran outside a namespace of its own")
	}
}

// Exercise the public launcher path when it cannot create the runner's namespace.
func TestRunContainedLauncherFailsClosedWithoutANamespace(t *testing.T) {
	t.Setenv("DC_PROCESSUTIL_TEST_FAIL_NAMESPACE", "1")
	ran := filepath.Join(t.TempDir(), "ran")
	err := RunContained(CommandContext(context.Background(), "/bin/sh", "-c", `: > "$1"`, "sh", ran))
	if !errors.Is(err, ErrNotContained) || !errors.Is(err, ErrContainmentUnavailable) {
		t.Fatalf("RunContained = %v, want ErrNotContained and ErrContainmentUnavailable", err)
	}
	if _, statErr := os.Stat(ran); !errors.Is(statErr, os.ErrNotExist) {
		t.Fatalf("command executed without containment: %v", statErr)
	}
}

// A privileged caller (root without CAP_SYS_ADMIN, as in the hook guardian's
// unit) keeps every file's owner in the namespace.
func TestRunContainedKeepsFileOwnersWhenPrivileged(t *testing.T) {
	caps := effectiveCapabilities()
	if caps&(1<<unix.CAP_SYS_ADMIN) == 0 && (caps&(1<<unix.CAP_SETUID) == 0 || caps&(1<<unix.CAP_SETGID) == 0) {
		t.Skip("needs CAP_SYS_ADMIN or CAP_SETUID and CAP_SETGID")
	}
	dir := t.TempDir()
	file := filepath.Join(dir, "owned")
	if err := os.WriteFile(file, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	const uid, gid = 4242, 4343
	if err := os.Chown(file, uid, gid); err != nil {
		t.Fatal(err)
	}
	var out strings.Builder
	cmd := CommandContext(context.Background(), "/bin/sh", "-c", `stat -c %u:%g "$1"`, "sh", file)
	cmd.Stdout, cmd.Stderr = &out, &out
	if err := RunContained(cmd); err != nil {
		t.Fatalf("RunContained = %v: %s", err, out.String())
	}
	if got, want := strings.TrimSpace(out.String()), strconv.Itoa(uid)+":"+strconv.Itoa(gid); got != want {
		t.Fatalf("owner in the namespace = %q, want %q", got, want)
	}
}

const containGuardianHelperEnv = "DC_PROCESSUTIL_CONTAIN_GUARDIAN_HELPER"

// TestRunContainedGuardianHelper is the helper process of
// TestRunContainedAsTheGuardianActingAsAUser: as the root hook guardian does
// for a user's probe, it keeps its real root IDs and acts as nobody.
func TestRunContainedGuardianHelper(t *testing.T) {
	if os.Getenv(containGuardianHelperEnv) == "" {
		t.Skip("helper process of TestRunContainedAsTheGuardianActingAsAUser")
	}
	if syscall.Setegid(65534) != nil || syscall.Seteuid(65534) != nil {
		os.Exit(3)
	}
	cmd := exec.Command("/bin/sh", "-c", `echo "$(id -u) $(id -ru) $(id -g) $(id -rg)"`)
	cmd.Stdout = os.Stdout
	if err := RunContained(cmd); err != nil {
		os.Exit(4)
	}
	os.Exit(0)
}

// The root hook guardian runs a user's probe with its real IDs still root.
// It could not write its child's ID maps (it is not dumpable then), and the
// probe ran the user's hook with the guardian's real root UID.
func TestRunContainedAsTheGuardianActingAsAUser(t *testing.T) {
	if os.Getenv(containGuardianHelperEnv) != "" {
		t.Skip("running as the helper")
	}
	if os.Geteuid() != 0 {
		t.Skip("needs root")
	}
	self, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	helper := exec.Command(self, "-test.run=^TestRunContainedGuardianHelper$", "-test.count=1")
	helper.Env = append(os.Environ(), containGuardianHelperEnv+"=1")
	helper.Dir = "/"
	out, err := helper.Output()
	if err != nil {
		t.Fatalf("helper = %v:\n%s", err, out)
	}
	if strings.TrimSpace(string(out)) != "65534 65534 65534 65534" {
		t.Fatalf("probe ran as %q, want the user's IDs alone", out)
	}
}

const containWorkerHelperEnv = "DC_PROCESSUTIL_CONTAIN_WORKER_HELPER"

// TestRunContainedWorkerHelper is the helper process of
// TestRunContainedFromANonDumpableWorker: as the hook guardian's per-user
// worker does, it holds one account's IDs alone (as root it becomes nobody)
// and makes itself not dumpable, then runs the probe.
func TestRunContainedWorkerHelper(t *testing.T) {
	if os.Getenv(containWorkerHelperEnv) == "" {
		t.Skip("helper process of TestRunContainedFromANonDumpableWorker")
	}
	if os.Geteuid() == 0 {
		if syscall.Setgroups(nil) != nil || syscall.Setresgid(65534, 65534, 65534) != nil || syscall.Setresuid(65534, 65534, 65534) != nil {
			os.Exit(3)
		}
	}
	if unix.Prctl(unix.PR_SET_DUMPABLE, 0, 0, 0, 0) != nil {
		os.Exit(3)
	}
	cmd := exec.Command("/bin/sh", "-c", `echo "$(id -u) $(id -ru)"`)
	cmd.Stdout = os.Stdout
	if err := RunContained(cmd); err != nil {
		os.Exit(4)
	}
	os.Exit(0)
}

// GAP-0846: the hook guardian's per-user worker is not dumpable, so the ID
// maps of the child RunContained starts were root's, the worker could not
// write them, and every managed Linux Hermes probe failed closed: Verify
// reported "owned hook command not present" for a working hook.
func TestRunContainedFromANonDumpableWorker(t *testing.T) {
	if os.Getenv(containWorkerHelperEnv) != "" {
		t.Skip("running as the helper")
	}
	// A host that cannot create the namespaces at all fails every probe the
	// same way; that is TestRunContainedFailsClosedWithoutANamespace.
	if err := RunContained(exec.Command("/bin/true")); err != nil {
		t.Skipf("no PID namespace for this test process: %v", err)
	}
	self, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	helper := exec.Command(self, "-test.run=^TestRunContainedWorkerHelper$", "-test.count=1")
	helper.Env = append(os.Environ(), containWorkerHelperEnv+"=1")
	helper.Dir = "/"
	out, err := helper.Output()
	if err != nil {
		t.Fatalf("helper = %v:\n%s", err, out)
	}
	uid := os.Geteuid()
	if uid == 0 {
		uid = 65534
	}
	if want := strconv.Itoa(uid) + " " + strconv.Itoa(uid); strings.TrimSpace(string(out)) != want {
		t.Fatalf("probe ran as %q, want %q", out, want)
	}
}

// Scanner runtimes use positive PIDs to stop their own helpers. In particular,
// Python's subprocess timeout kills by PID before it can return to the caller.
func TestRunTrackedCanStopItsOwnChildByPID(t *testing.T) {
	pidFile := filepath.Join(t.TempDir(), "child.pid")
	cmd := CommandContext(context.Background(), "/bin/sh", "-c",
		`sh -c 'read -r p _ < /proc/self/stat; echo "$p" > "$1"; exec sleep 60' sh "$1" & child=$!; while [ ! -s "$1" ]; do sleep 0.01; done; kill -TERM "$child" || exit 11; wait "$child"; [ "$?" -eq 143 ]`,
		"sh", pidFile)
	if err := RunTracked(cmd); err != nil {
		t.Fatalf("RunTracked could not stop its child by PID: %v", err)
	}
	pid := readContainPID(t, pidFile)
	if helperRunning(pid) {
		_ = syscall.Kill(pid, syscall.SIGKILL)
		t.Fatalf("child %d still runs after a successful wait", pid)
	}
}

func TestRunTrackedKeepsCommandExit125(t *testing.T) {
	err := RunTracked(CommandContext(context.Background(), "/bin/sh", "-c", "exit 125"))
	var exitErr *exec.ExitError
	if errors.Is(err, ErrNotContained) || !errors.As(err, &exitErr) || exitErr.ExitCode() != 125 {
		t.Fatalf("RunTracked = %v, want command exit 125", err)
	}
}

func TestRunTrackedPythonSubprocessTimeout(t *testing.T) {
	python, err := exec.LookPath("python3")
	if err != nil {
		t.Skip("python3 is not installed")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	cmd := CommandContext(ctx, python, "-c", `import subprocess
try:
    subprocess.run(["sleep", "60"], timeout=0.1, check=True)
except subprocess.TimeoutExpired:
    print("timeout handled")
else:
    raise AssertionError("sleep did not time out")`)
	var out strings.Builder
	cmd.Stdout, cmd.Stderr = &out, &out
	if err := RunTracked(cmd); err != nil {
		t.Fatalf("Python could not handle the subprocess timeout: %v: %s", err, out.String())
	}
	if strings.TrimSpace(out.String()) != "timeout handled" {
		t.Fatalf("Python timeout result = %q", out.String())
	}
}

func TestRunTrackedPreservesRootOwnedExecutableCustody(t *testing.T) {
	if os.Getenv("DC_TRACKED_MANAGED_HELPER") == "1" {
		if err := managed.ValidateTrustedFilePath("/etc/passwd", "root-owned file"); err != nil {
			t.Fatal(err)
		}
		return
	}
	if _, err := exec.LookPath("python3"); err != nil {
		t.Skip("python3 is not installed")
	}
	cli, err := filepath.Abs("../../cli")
	if err != nil {
		t.Fatal(err)
	}
	testBinary, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	code := `import os
from defenseclaw.config import _managed_config_trust_problem
from defenseclaw.file_permissions import tracked_host_owner_uid, trusted_posix_executable_path
from defenseclaw.pinned_exec import run_pinned_executable
assert _managed_config_trust_problem('/etc/passwd') is None
path = trusted_posix_executable_path('/bin/echo')
result = run_pinned_executable([path, 'root-owned'], capture_output=True, text=True)
assert result.returncode == 0 and result.stdout.strip() == 'root-owned', result
assert tracked_host_owner_uid('/bin/echo', os.stat('/bin/sh')) == -1
helper = trusted_posix_executable_path(os.environ['DC_TRACKED_TEST_BINARY'])
result = run_pinned_executable([helper, '-test.run=^TestRunTrackedPreservesRootOwnedExecutableCustody$'],
                               capture_output=True, text=True,
                               env={**os.environ, 'DC_TRACKED_MANAGED_HELPER': '1'})
assert result.returncode == 0, (result.stdout, result.stderr)`
	cmd := CommandContext(context.Background(), "python3", "-c", code)
	cmd.Env = append(os.Environ(), "PYTHONPATH="+cli, "DC_TRACKED_TEST_BINARY="+testBinary)
	var out strings.Builder
	cmd.Stdout, cmd.Stderr = &out, &out
	if err := RunTracked(cmd); err != nil {
		t.Fatalf("root-owned executable custody inside scanner = %v: %s", err, out.String())
	}
}

// When the runner dies, however it dies, nothing the command started is left:
// the kernel ends the runner's namespace with it. RunContained is also called
// by the long-lived gateway, so an unrelated gateway child must survive.
func TestRunContainedEndsTheTreeWhenTheRunnerIsKilled(t *testing.T) {
	requireContainTools(t)
	unrelated := exec.Command("sleep", "60")
	if err := unrelated.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = unrelated.Process.Kill()
		_ = unrelated.Wait()
	})
	dir := t.TempDir()
	pidFile, runnerFile := filepath.Join(dir, "escaped.pid"), filepath.Join(dir, "runner.pid")
	done := make(chan error, 1)
	go func() {
		done <- RunContained(CommandContext(context.Background(), "/bin/sh", "-c",
			"setsid "+containChild+" &\n"+containWaitPID+"\n"+
				`read -r _ _ _ a _ < /proc/self/stat; echo $a > "$2"; sleep 60`, "sh", pidFile, runnerFile))
	}()
	pid := readContainPID(t, pidFile)
	t.Cleanup(func() { _ = syscall.Kill(pid, syscall.SIGKILL) })
	runner := readContainPID(t, runnerFile)
	if err := syscall.Kill(runner, syscall.SIGKILL); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("RunContained passed after its runner was killed")
		}
	case <-time.After(10 * time.Second):
		t.Fatal("RunContained did not return after its runner was killed")
	}
	if helperRunning(pid) {
		t.Fatalf("RunContained returned after its runner died while descendant %d still runs", pid)
	}
	if !helperRunning(unrelated.Process.Pid) {
		t.Fatalf("RunContained killed unrelated gateway child %d", unrelated.Process.Pid)
	}
}

// A command can read host ancestor IDs from /proc even inside a PID
// namespace. It must not be able to signal them or leave a detached child.
func TestRunContainedSurvivesTheCommandKillingEverySupervisor(t *testing.T) {
	requireContainTools(t)
	// Collect every supervisor ancestor by the pids this test sees, outermost
	// first, and SIGKILL them together, one by one and by process group.
	ancestors := `read -r _ _ _ a _ < /proc/self/stat; list=""
while [ "${a:-0}" -gt 1 ]; do
  case "$(tr '\0' ' ' < /proc/$a/cmdline)" in ` + containSupervisorArg0 + `*) list="$a $list" ;; esac
  read -r _ _ _ a _ < /proc/$a/stat || break
done
[ -n "$list" ] || exit 7
`
	for _, kill := range []struct {
		name, script string
		amd64        bool // raw amd64 system call numbers
	}{
		{"kill", `kill -9 $list`, false},
		{"process groups", `for p in $list; do kill -9 -$p; done`, false},
		{"perl", `perl -e 'kill 9, @ARGV' $list`, false},
		{"tgkill", `perl -e 'syscall(234, $_+0, $_+0, 9) for @ARGV' $list`, true},
		{"tkill", `for p in $list; do for t in /proc/$p/task/*; do perl -e 'syscall(200, $ARGV[0]+0, 9)' "${t##*/}"; done; done`, true},
		{"pidfd", `perl -e 'for (@ARGV) { my $fd = syscall(434, $_+0, 0); syscall(424, $fd, 9, 0, 0) if $fd >= 0 }' $list`, false},
		{"I/O owner", `perl -e 'for (@ARGV) { pipe(my $r, my $w) or die; fcntl($r, 8, $_+0); fcntl($r, 10, 9); fcntl($r, 4, 020000); syswrite($w, "x") }' $list`, false},
		{"socket owner", `perl -MSocket -e 'for (@ARGV) { socketpair(my $r, my $w, AF_UNIX, SOCK_STREAM, 0) or die; ioctl($r, 0x8901, pack("i", $_)); fcntl($r, 10, 9); fcntl($r, 4, 020000); syswrite($w, "x") }' $list`, false},
		{"sigqueue", `perl -e 'for (@ARGV) { my $i = pack("iii", 9, 0, -1) . "\0" x 116; syscall(129, $_+0, 9, $i) }' $list`, true},
	} {
		for name, run := range containRunners {
			t.Run(name+"/"+kill.name, func(t *testing.T) {
				if kill.amd64 && runtime.GOARCH != "amd64" {
					t.Skip("raw syscall numbers are amd64's")
				}
				pidFile := filepath.Join(t.TempDir(), "escaped.pid")
				err := run(CommandContext(context.Background(), "/bin/sh", "-c",
					"setsid "+containChild+" &\n"+containWaitPID+"\n"+ancestors+kill.script+"\nsleep 1\nexit 0", "sh", pidFile))
				pid := readContainPID(t, pidFile)
				t.Cleanup(func() { _ = syscall.Kill(pid, syscall.SIGKILL) })
				var exitErr *exec.ExitError
				if errors.As(err, &exitErr) && exitErr.ExitCode() == 7 {
					t.Fatal("the command found no supervisor ancestor")
				}
				if helperRunning(pid) {
					t.Fatalf("%s returned (%v) while descendant %d still runs", name, err, pid)
				}
			})
		}
	}
}

func TestRunTrackedLauncherIsNotDumpable(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root owns every /proc entry it has")
	}
	var out strings.Builder
	cmd := CommandContext(context.Background(), "/bin/sh", "-c", `read -r _ _ _ parent _ < /proc/self/stat; stat -c %u /proc/$parent/status`)
	cmd.Stdout, cmd.Stderr = &out, &out
	if err := RunTracked(cmd); err != nil {
		t.Fatalf("RunTracked = %v: %s", err, out.String())
	}
	if got := strings.TrimSpace(out.String()); got == strconv.Itoa(os.Geteuid()) {
		t.Fatalf("the launcher's /proc status belongs to the scanner UID %q", got)
	}
}

const containInjectionHelperEnv = "DC_PROCESSUTIL_INJECTION_HELPER"

func TestRunTrackedCannotInjectIntoOwnerHelper(t *testing.T) {
	gateway, err := strconv.Atoi(os.Getenv(containInjectionHelperEnv))
	if err != nil || gateway <= 1 {
		t.Skip("helper process of TestRunTrackedCannotInjectIntoOwner")
	}
	raw, err := os.ReadFile("/proc/self/stat")
	if err != nil {
		t.Fatal(err)
	}
	fields := strings.Fields(string(raw[strings.LastIndexByte(string(raw), ')')+1:]))
	launcher, err := strconv.Atoi(fields[1])
	if err != nil {
		t.Fatal(err)
	}
	for name, target := range map[string]int{"gateway": gateway, "launcher": launcher} {
		if memory, err := os.Open("/proc/" + strconv.Itoa(target) + "/mem"); err == nil {
			_ = memory.Close()
			t.Errorf("scanner opened %s memory", name)
		} else if !errors.Is(err, os.ErrPermission) {
			t.Errorf("open %s memory = %v, want permission denied", name, err)
		}
		if fd, err := unix.PidfdOpen(target, 0); err == nil {
			_ = unix.Close(fd)
			t.Errorf("scanner opened %s pidfd", name)
		}
		// PTRACE_SEIZE does not stop the target. If it ever succeeds,
		// detach before reporting the failure.
		_, _, errno := unix.Syscall6(unix.SYS_PTRACE, 0x4206, uintptr(target), 0, 0, 0, 0)
		if errno == 0 {
			_, _, _ = unix.Syscall6(unix.SYS_PTRACE, 17, uintptr(target), 0, 0, 0, 0)
			t.Errorf("scanner attached to %s", name)
		} else if errno != unix.EPERM {
			t.Errorf("ptrace %s = %v, want EPERM", name, errno)
		}
		for _, call := range []struct {
			name string
			nr   uintptr
		}{
			{"process_vm_readv", unix.SYS_PROCESS_VM_READV},
			{"process_vm_writev", unix.SYS_PROCESS_VM_WRITEV},
		} {
			_, _, errno := unix.Syscall6(call.nr, uintptr(target), 0, 0, 0, 0, 0)
			if errno != unix.EPERM {
				t.Errorf("%s %s = %v, want EPERM", call.name, name, errno)
			}
		}
	}
	fd, err := unix.PidfdOpen(os.Getpid(), 0)
	if err != nil {
		t.Fatalf("pidfd_open self: %v", err)
	}
	defer unix.Close(fd)
	if _, err := unix.PidfdGetfd(fd, 0, 0); err != unix.EPERM {
		t.Errorf("pidfd_getfd self = %v, want EPERM", err)
	}
}

func TestRunTrackedCannotInjectIntoOwner(t *testing.T) {
	cmd := CommandContext(context.Background(), os.Args[0], "-test.run=^TestRunTrackedCannotInjectIntoOwnerHelper$")
	cmd.Env = append(os.Environ(), containInjectionHelperEnv+"="+strconv.Itoa(os.Getpid()))
	var out strings.Builder
	cmd.Stdout, cmd.Stderr = &out, &out
	if err := RunTracked(cmd); err != nil {
		t.Fatalf("injection probe = %v: %s", err, out.String())
	}
}

const containDeathHelperEnv = "DC_PROCESSUTIL_CONTAIN_DEATH_HELPER"

// TestRunContainedDeathHelper is the helper process of
// TestRunContainedEndsTheTreeWhenTheGatewayDies: it runs a command that
// starts a child in a session of its own and stalls.
func TestRunContainedDeathHelper(t *testing.T) {
	pidFile := os.Getenv(containDeathHelperEnv)
	if pidFile == "" {
		t.Skip("helper process of TestRunContainedEndsTheTreeWhenTheGatewayDies")
	}
	_ = RunContained(exec.Command("/bin/sh", "-c", "setsid "+containChild+" &\nsleep 60", "sh", pidFile))
	os.Exit(1)
}

// A gateway that is SIGKILLed during a scan leaves nothing of it running.
func TestRunContainedEndsTheTreeWhenTheGatewayDies(t *testing.T) {
	requireContainTools(t)
	if os.Getenv(containDeathHelperEnv) != "" {
		t.Skip("running as the helper")
	}
	pidFile := filepath.Join(t.TempDir(), "escaped.pid")
	helper := exec.Command(os.Args[0], "-test.run=^TestRunContainedDeathHelper$", "-test.count=1")
	helper.Env = append(os.Environ(), containDeathHelperEnv+"="+pidFile)
	if err := helper.Start(); err != nil {
		t.Fatal(err)
	}
	pid := readContainPID(t, pidFile)
	t.Cleanup(func() { _ = syscall.Kill(pid, syscall.SIGKILL) })
	_ = helper.Process.Kill()
	_ = helper.Wait()
	for deadline := time.Now().Add(5 * time.Second); helperRunning(pid); time.Sleep(20 * time.Millisecond) {
		if time.Now().After(deadline) {
			t.Fatalf("descendant %d outlived the gateway that ran it", pid)
		}
	}
}

// The supervisor reports the command's own result and hides its marker.
func TestRunContainedKeepsTheCommandResult(t *testing.T) {
	for _, tc := range []struct {
		script string
		want   int
	}{
		{"exit 0", 0},
		{"exit 3", 3},
		{"trap 'exit 143' TERM; kill -TERM $$", 128 + int(syscall.SIGTERM)},
		{`[ -z "${` + containSupervisorEnv + `+x}" ] || exit 9`, 0},
	} {
		for name, run := range containRunners {
			err := run(CommandContext(context.Background(), "/bin/sh", "-c", tc.script))
			got := 0
			var exitErr *exec.ExitError
			if errors.As(err, &exitErr) {
				got = exitErr.ExitCode()
			} else if err != nil {
				t.Fatalf("%s %q: %v", name, tc.script, err)
			}
			if got != tc.want {
				t.Fatalf("%s %q exited %d, want %d", name, tc.script, got, tc.want)
			}
		}
	}
	for name, run := range containRunners {
		if err := run(CommandContext(context.Background(), filepath.Join(t.TempDir(), "missing"))); err == nil {
			t.Fatalf("%s: a command that cannot start passed", name)
		}
	}
}

func readContainPID(t *testing.T, path string) int {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for {
		raw, err := os.ReadFile(path)
		if pid, convErr := strconv.Atoi(strings.TrimSpace(string(raw))); err == nil && convErr == nil {
			return pid
		}
		if time.Now().After(deadline) {
			t.Fatalf("command never wrote %s: %v", path, err)
		}
		time.Sleep(20 * time.Millisecond)
	}
}

const lateGatewayThreadEnv = "DC_PROCESSUTIL_LATE_GATEWAY_THREAD"

const clearParentDeathEnv = "DC_PROCESSUTIL_CLEAR_PARENT_DEATH"

// The kernel keeps a parent-death signal per thread: the scanner's main
// thread, the one that executed it, has it, and every thread Go starts later
// has none. A test goroutine runs on any thread, so PR_GET_PDEATHSIG there
// read 0 whenever the goroutine was not on the main thread. The scanner side
// of TestRunTrackedCannotClearParentDeathSignal therefore runs in init, which
// Go runs on the main thread, and exits before any test starts.
func init() {
	if os.Getenv(clearParentDeathEnv) == "" {
		return
	}
	runtime.LockOSThread()
	if err := scannerKeepsParentDeathSignal(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	os.Exit(0)
}

// scannerKeepsParentDeathSignal is the scanner's half of the test, on the
// main thread: it cannot clear the signal, and setting its own IDs keeps it.
func scannerKeepsParentDeathSignal() error {
	if err := unix.Prctl(unix.PR_SET_PDEATHSIG, 0, 0, 0, 0); err != unix.EPERM {
		return fmt.Errorf("scanner cleared parent-death signal: %v", err)
	}
	uid, gid := os.Geteuid(), os.Getegid()
	if err := unix.Setresuid(uid, uid, uid); err != nil {
		return fmt.Errorf("scanner could not set its own UID: %v", err)
	}
	if err := unix.Setresgid(gid, gid, gid); err != nil {
		return fmt.Errorf("scanner could not set its own GID: %v", err)
	}
	var signal int
	if err := unix.Prctl(unix.PR_GET_PDEATHSIG, uintptr(unsafe.Pointer(&signal)), 0, 0, 0); err != nil || signal != int(unix.SIGKILL) {
		return fmt.Errorf("scanner lost its parent-death signal after an identity call: signal=%d err=%v", signal, err)
	}
	return nil
}

func TestRunTrackedCannotClearParentDeathSignal(t *testing.T) {
	cmd := CommandContext(context.Background(), os.Args[0], "-test.run=^TestRunTrackedCannotClearParentDeathSignal$")
	cmd.Env = append(os.Environ(), clearParentDeathEnv+"=1")
	var out strings.Builder
	cmd.Stdout, cmd.Stderr = &out, &out
	if err := RunTracked(cmd); err != nil {
		t.Fatalf("scanner parent-death guard = %v: %s", err, out.String())
	}
}

// A scanner can exec a setuid-marked file. With no_new_privs the exec must
// leave the PID-namespace init's parent-death signal in place.
func TestRunTrackedSetuidExecKeepsParentDeathSignal(t *testing.T) {
	source, err := os.Open(os.Args[0])
	if err != nil {
		t.Fatal(err)
	}
	defer source.Close()
	path := filepath.Join(t.TempDir(), "setuid-scanner")
	dst, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o755)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := io.Copy(dst, source); err != nil {
		_ = dst.Close()
		t.Fatal(err)
	}
	if err := dst.Close(); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, 0o4755); err != nil {
		t.Fatal(err)
	}
	cmd := CommandContext(context.Background(), path, "-test.run=^TestRunTrackedCannotClearParentDeathSignal$")
	cmd.Env = append(os.Environ(), clearParentDeathEnv+"=1")
	var out strings.Builder
	cmd.Stdout, cmd.Stderr = &out, &out
	if err := RunTracked(cmd); err != nil {
		t.Fatalf("setuid-marked scanner lost parent-death guard: %v: %s", err, out.String())
	}
}

// A snapshot of the gateway's thread IDs becomes stale as soon as Go starts
// another thread. Keep the attempted kill in a helper so a vulnerable run
// cannot end the test process.
func TestRunTrackedCannotSignalLateGatewayThread(t *testing.T) {
	if base := os.Getenv(lateGatewayThreadEnv); base != "" {
		ready, ids := base+".ready", base+".ids"
		cmd := CommandContext(context.Background(), "/bin/sh", "-c",
			`: > "$1"; while [ ! -s "$2" ]; do sleep 0.01; done; for tid in $(cat "$2"); do kill -9 "$tid" 2>/dev/null || :; done`,
			"sh", ready, ids)
		done := make(chan error, 1)
		go func() { done <- RunTracked(cmd) }()
		for deadline := time.Now().Add(5 * time.Second); ; time.Sleep(10 * time.Millisecond) {
			if _, err := os.Stat(ready); err == nil {
				break
			}
			if time.Now().After(deadline) {
				t.Fatal("scanner did not start")
			}
		}
		threads := make(chan int, 32)
		release := make(chan struct{})
		for range 32 {
			go func() {
				runtime.LockOSThread()
				defer runtime.UnlockOSThread()
				threads <- unix.Gettid()
				<-release
			}()
		}
		var list strings.Builder
		for range 32 {
			fmt.Fprintln(&list, <-threads)
		}
		if err := os.WriteFile(ids, []byte(list.String()), 0o600); err != nil {
			t.Fatal(err)
		}
		err := <-done
		close(release)
		if err != nil {
			t.Fatalf("tracked command = %v", err)
		}
		return
	}
	base := filepath.Join(t.TempDir(), "gateway")
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	helper := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestRunTrackedCannotSignalLateGatewayThread$")
	helper.Env = append(os.Environ(), lateGatewayThreadEnv+"="+base)
	out, err := helper.CombinedOutput()
	if err != nil {
		t.Fatalf("scanner signaled a newly created gateway thread: %v: %s", err, out)
	}
}

const filteredGatewayChildEnv = "DC_PROCESSUTIL_FILTERED_GATEWAY_CHILD"

func TestRunTrackedLeavesUnrelatedFilteredGatewayChildHelper(t *testing.T) {
	ready := os.Getenv(filteredGatewayChildEnv)
	if ready == "" {
		t.Skip("helper process")
	}
	filter := []unix.SockFilter{{Code: unix.BPF_RET | unix.BPF_K, K: unix.SECCOMP_RET_ALLOW}}
	prog := unix.SockFprog{Len: uint16(len(filter)), Filter: &filter[0]}
	if err := unix.Prctl(unix.PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0); err != nil {
		t.Fatal(err)
	}
	if err := unix.Prctl(unix.PR_SET_SECCOMP, unix.SECCOMP_MODE_FILTER, uintptr(unsafe.Pointer(&prog)), 0, 0); err != nil {
		t.Fatal(err)
	}
	runtime.KeepAlive(filter)
	if err := os.WriteFile(ready, []byte("ready"), 0o600); err != nil {
		t.Fatal(err)
	}
	time.Sleep(time.Minute)
}

// A separate gateway child can install its own seccomp filter during a scan.
// Ending the scanner's supervisor must leave that gateway child untouched.
func TestRunTrackedLeavesUnrelatedFilteredGatewayChild(t *testing.T) {
	requireContainTools(t)
	dir := t.TempDir()
	pidFile, supervisorFile := filepath.Join(dir, "detached.pid"), filepath.Join(dir, "supervisor.pid")
	cmd := CommandContext(context.Background(), "/bin/sh", "-c",
		"setsid "+containChild+" &\n"+containWaitPID+"\n"+
			`read -r _ _ _ ancestor _ < /proc/self/stat; outer=0
while [ "${ancestor:-0}" -gt 1 ]; do
  case "$(tr '\0' ' ' < /proc/$ancestor/cmdline)" in `+containSupervisorArg0+`*) outer=$ancestor ;; esac
  read -r _ _ _ ancestor _ < /proc/$ancestor/stat || break
done
[ "$outer" -gt 1 ] || exit 7
echo "$outer" > "$2"
sleep 60`, "sh", pidFile, supervisorFile)
	done := make(chan error, 1)
	go func() { done <- RunTracked(cmd) }()
	child := readContainPID(t, pidFile)
	t.Cleanup(func() { _ = unix.Kill(child, unix.SIGKILL) })
	supervisor := readContainPID(t, supervisorFile)
	ready := filepath.Join(dir, "unrelated.ready")
	unrelated := exec.Command(os.Args[0], "-test.run=^TestRunTrackedLeavesUnrelatedFilteredGatewayChildHelper$")
	unrelated.Env = append(os.Environ(), filteredGatewayChildEnv+"="+ready)
	if err := unrelated.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = unrelated.Process.Kill(); _ = unrelated.Wait() })
	for deadline := time.Now().Add(5 * time.Second); ; time.Sleep(10 * time.Millisecond) {
		if _, err := os.Stat(ready); err == nil {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("unrelated child did not install its filter")
		}
	}
	if err := unix.Kill(supervisor, unix.SIGKILL); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("RunTracked passed after its supervisor was killed")
		}
	case <-time.After(10 * time.Second):
		t.Fatal("RunTracked did not return after its supervisor was killed")
	}
	if helperRunning(child) {
		t.Fatalf("scanner descendant %d outlived its supervisor", child)
	}
	if !helperRunning(unrelated.Process.Pid) {
		t.Fatalf("unrelated filtered gateway child %d was killed", unrelated.Process.Pid)
	}
}

// GAP-1945: a command that ran and failed is never reported as a host that
// refused the namespaces, also when its own exit code is the launcher's.
func TestRunContainedCommandThatRanIsNotContainmentUnavailable(t *testing.T) {
	err := RunContained(CommandContext(context.Background(), "/bin/sh", "-c", "exit 1"))
	if err == nil || errors.Is(err, ErrContainmentUnavailable) {
		t.Fatalf("RunContained = %v, want the command's own failure", err)
	}
}

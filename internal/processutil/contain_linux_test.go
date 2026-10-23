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
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

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

// containRunners are the two Linux supervisors: the PID namespace runner and
// the subreaper custodian scanners keep.
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
	err := RunContained(CommandContext(context.Background(), "/bin/sh", "-c", `: > "$1"`, "sh", ran))
	if !errors.Is(err, ErrNotContained) {
		t.Fatalf("RunContained = %v, want ErrNotContained", err)
	}
	if _, statErr := os.Stat(ran); statErr == nil {
		t.Fatal("the command ran outside a namespace of its own")
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

// When the supervisor cannot sweep what is left, the run fails closed.
func TestRunTrackedFailsClosedWhenItCannotEndTheTree(t *testing.T) {
	requireContainTools(t)
	previous := containSweepBudget
	containSweepBudget = 0
	t.Cleanup(func() { containSweepBudget = previous })
	pidFile := filepath.Join(t.TempDir(), "escaped.pid")
	err := RunTracked(CommandContext(context.Background(), "/bin/sh", "-c",
		"setsid "+containChild+" &\n"+containWaitPID+"\nexit 0", "sh", pidFile))
	pid := readContainPID(t, pidFile)
	_ = syscall.Kill(pid, syscall.SIGKILL)
	if !errors.Is(err, ErrNotContained) {
		t.Fatalf("RunTracked = %v, want ErrNotContained", err)
	}
}

// A command that kills its supervisor cannot pass.
func TestRunTrackedFailsWhenTheSupervisorIsKilled(t *testing.T) {
	requireContainTools(t)
	// RunContained is also called by the long-lived gateway. Its custodian
	// must never sweep another child of the gateway while ending this probe.
	unrelated := exec.Command("sleep", "60")
	if err := unrelated.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = unrelated.Process.Kill()
		_ = unrelated.Wait()
	})
	pidFile := filepath.Join(t.TempDir(), "escaped.pid")
	err := RunTracked(CommandContext(context.Background(), "/bin/sh", "-c",
		"setsid "+containChild+" &\n"+containWaitPID+"\n"+
			// Only ever the supervisor: never the test binary.
			`case "$(tr '\0' ' ' < /proc/$PPID/cmdline)" in `+containSupervisorArg0+`*) kill -9 -$PPID ;; esac`+
			"\nexit 0", "sh", pidFile))
	pid := readContainPID(t, pidFile)
	t.Cleanup(func() { _ = syscall.Kill(pid, syscall.SIGKILL) })
	if err == nil {
		t.Fatal("RunTracked passed after the command killed its supervisor")
	}
	if helperRunning(pid) {
		t.Fatalf("RunTracked returned after its supervisor died while descendant %d still runs", pid)
	}
	if !helperRunning(unrelated.Process.Pid) {
		t.Fatalf("RunContained killed unrelated gateway child %d", unrelated.Process.Pid)
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

// r104 W5b review: a hook that SIGKILLed the subreaper custodian, its
// grandparent, took the runner and itself down with it, and the kernel handed
// its setsid child to init, which kept running; the same held for a scanner
// below RunTracked (GAP-0631). The command must not be able to end anything
// that contains it, whichever ancestor it targets and however it signals,
// and nothing it started may outlive the run.
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
		trackedOnly  bool
	}{
		{"kill", `kill -9 $list`, false, false},
		{"process groups", `for p in $list; do kill -9 -$p; done`, false, false},
		{"perl", `perl -e 'kill 9, @ARGV' $list`, false, false},
		{"tgkill", `perl -e 'syscall(234, $_+0, $_+0, 9) for @ARGV' $list`, true, false},
		{"tkill", `for p in $list; do for t in /proc/$p/task/*; do perl -e 'syscall(200, $ARGV[0]+0, 9)' "${t##*/}"; done; done`, true, false},
		{"pidfd", `perl -e 'for (@ARGV) { my $fd = syscall(434, $_+0, 0); syscall(424, $fd, 9, 0, 0) if $fd >= 0 }' $list`, false, false},
		{"I/O owner", `perl -e 'for (@ARGV) { pipe(my $r, my $w) or die; fcntl($r, 8, $_+0); fcntl($r, 10, 9); fcntl($r, 4, 020000); syswrite($w, "x") }' $list`, false, false},
		{"socket owner", `perl -MSocket -e 'for (@ARGV) { socketpair(my $r, my $w, AF_UNIX, SOCK_STREAM, 0) or die; ioctl($r, 0x8901, pack("i", $_)); fcntl($r, 10, 9); fcntl($r, 4, 020000); syswrite($w, "x") }' $list`, false, false},
		{"sigqueue", `perl -e 'for (@ARGV) { my $i = pack("iii", 9, 0, -1) . "\0" x 116; syscall(129, $_+0, 9, $i) }' $list`, true, false},
		{"kill by thread ID", `set -- $list; p=$1; t=$p; for path in /proc/$p/task/*; do [ "${path##*/}" != "$p" ] && { t=${path##*/}; break; }; done; [ "$t" != "$p" ] || exit 7; kill -9 "$t"`, false, true},
		{"sigqueue by thread ID", `set -- $list; p=$1; t=$p; for path in /proc/$p/task/*; do [ "${path##*/}" != "$p" ] && { t=${path##*/}; break; }; done; [ "$t" != "$p" ] || exit 7; perl -e 'my $i = pack("iii", 9, 0, -1) . "\0" x 116; syscall(129, $ARGV[0]+0, 9, $i)' "$t"`, true, true},
		{"I/O owner by thread ID", `set -- $list; p=$1; t=$p; for path in /proc/$p/task/*; do [ "${path##*/}" != "$p" ] && { t=${path##*/}; break; }; done; [ "$t" != "$p" ] || exit 7; perl -e 'pipe(my $r, my $w) or die; fcntl($r, 8, $ARGV[0]+0); fcntl($r, 10, 9); fcntl($r, 4, 020000); syswrite($w, "x")' "$t"`, false, true},
		{"prlimit custodian", `set -- $list; perl -e 'my $limit = pack("QQ", 0, 0); syscall(302, $ARGV[0]+0, 7, $limit, 0)' "$1"`, true, true},
		{"join custodian group then kill zero", `set -- $list; perl -e 'syscall(109, 0, $ARGV[0]+0) == 0 or die "setpgid: $!"; kill 9, 0' "$1"`, true, true},
	} {
		for name, run := range containRunners {
			t.Run(name+"/"+kill.name, func(t *testing.T) {
				if kill.trackedOnly && name != "RunTracked" {
					t.Skip("the PID-namespace runner has no subreaper custodian")
				}
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

// The custodian is not dumpable, so the command cannot trace it and make it
// exit (GAP-0631): its /proc entries belong to root.
func TestRunTrackedCustodianIsNotDumpable(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root owns every /proc entry it has")
	}
	var out strings.Builder
	cmd := CommandContext(context.Background(), "/bin/sh", "-c", `read -r _ _ _ a _ < /proc/self/stat
while [ "${a:-0}" -gt 1 ]; do
  case "$(tr '\0' ' ' < /proc/$a/cmdline)" in "`+containSupervisorArg0+` `+containCustodianMode+` "*) stat -c %u /proc/$a/status; exit 0 ;; esac
  read -r _ _ _ a _ < /proc/$a/stat || break
done
exit 7`)
	cmd.Stdout, cmd.Stderr = &out, &out
	if err := RunTracked(cmd); err != nil {
		t.Fatalf("RunTracked = %v: %s", err, out.String())
	}
	if got := strings.TrimSpace(out.String()); got != "0" {
		t.Fatalf("the custodian's /proc status belongs to %q, want root (not dumpable)", got)
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
		{"kill -TERM 0", 128 + int(syscall.SIGTERM)},
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

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

//go:build linux

package harness

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

// The launchers' job control (launcherJobControl), driven the way `openshell
// sandbox exec --tty` starts them: as the leader of a new session with a
// pseudo-terminal as its controlling terminal, so the stub standing in for
// the harness is in an orphaned process group unless the launcher
// supervises it.

// stubState prints the stub's pid, process group, session and the
// terminal's foreground process group, from /proc.
const stubState = `st() { local s; read -r s </proc/$$/stat; s=${s##*) }; set -- $s; echo "pid=$$ pgrp=$3 sid=$4 tpgid=$6"; }
`

// stubStops stops the stub the three ways a harness can: Ctrl-Z's SIGTSTP
// to its process group (Claude Code, OpenCode), SIGTTIN for a read from the
// background and SIGSTOP; then it exits 42.
const stubStops = stubState + `echo "stub start $(st)"
kill -TSTP 0
echo "stub resumed TSTP $(st)"
kill -TTIN 0
echo "stub resumed TTIN $(st)"
kill -STOP $$
echo "stub resumed STOP $(st)"
exit 42
`

var stubLine = regexp.MustCompile(`^stub (start|resumed [A-Z]+) pid=(\d+) pgrp=(\d+) sid=(\d+) tpgid=(-?\d+)$`)

// ptyRun is a command started in a new session on a pseudo-terminal.
type ptyRun struct {
	t      *testing.T
	cmd    *exec.Cmd
	master *os.File
	mu     sync.Mutex
	out    bytes.Buffer
	read   chan struct{}
	done   chan struct{}
	err    error
}

// startPTY starts argv as the leader of a new session whose controlling
// terminal is a fresh pseudo-terminal on its stdin, stdout and stderr, in
// dir with env.
func startPTY(t *testing.T, dir string, env []string, argv ...string) *ptyRun {
	t.Helper()
	// The master stays non-blocking, in the runtime poller, so closing it
	// (the hangup) interrupts the reader.
	fd, err := unix.Open("/dev/ptmx", unix.O_RDWR|unix.O_NOCTTY|unix.O_CLOEXEC|unix.O_NONBLOCK, 0)
	if err != nil {
		t.Skipf("no pseudo-terminal: %v", err)
	}
	master := os.NewFile(uintptr(fd), "/dev/ptmx")
	if err := unix.IoctlSetPointerInt(fd, unix.TIOCSPTLCK, 0); err != nil {
		t.Fatal(err)
	}
	n, err := unix.IoctlGetUint32(fd, unix.TIOCGPTN)
	if err != nil {
		t.Fatal(err)
	}
	slave, err := os.OpenFile("/dev/pts/"+strconv.FormatUint(uint64(n), 10), os.O_RDWR|syscall.O_NOCTTY, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer slave.Close()
	if err := unix.IoctlSetWinsize(int(slave.Fd()), unix.TIOCSWINSZ, &unix.Winsize{Row: 24, Col: 80}); err != nil {
		t.Fatal(err)
	}
	r := &ptyRun{t: t, master: master, read: make(chan struct{}), done: make(chan struct{})}
	r.cmd = exec.Command(argv[0], argv[1:]...)
	r.cmd.Dir = dir
	r.cmd.Env = append([]string{"PATH=/usr/bin:/bin", "HOME=" + dir}, env...)
	r.cmd.Stdin, r.cmd.Stdout, r.cmd.Stderr = slave, slave, slave
	r.cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true, Setctty: true, Ctty: 0}
	if err := r.cmd.Start(); err != nil {
		t.Fatal(err)
	}
	go func() {
		defer close(r.read)
		buf := make([]byte, 4096)
		for {
			n, err := master.Read(buf)
			r.mu.Lock()
			r.out.Write(buf[:n])
			r.mu.Unlock()
			if err != nil {
				return
			}
		}
	}()
	go func() {
		r.err = r.cmd.Wait()
		close(r.done)
	}()
	t.Cleanup(func() {
		select {
		case <-r.done:
		default:
			_ = r.cmd.Process.Kill()
			<-r.done
		}
		_ = master.Close()
	})
	return r
}

// resize sets the terminal's window size, as a client resize does.
func (r *ptyRun) resize(rows, cols uint16) {
	r.t.Helper()
	raw, err := r.master.SyscallConn()
	if err != nil {
		r.t.Fatal(err)
	}
	var ioctlErr error
	if err := raw.Control(func(fd uintptr) {
		ioctlErr = unix.IoctlSetWinsize(int(fd), unix.TIOCSWINSZ, &unix.Winsize{Row: rows, Col: cols})
	}); err != nil || ioctlErr != nil {
		r.t.Fatalf("resize: %v %v", err, ioctlErr)
	}
}

// output is what the terminal showed so far, without carriage returns.
func (r *ptyRun) output() string {
	r.mu.Lock()
	defer r.mu.Unlock()
	return strings.ReplaceAll(r.out.String(), "\r", "")
}

// waitOutput waits until the terminal shows want.
func (r *ptyRun) waitOutput(want string) {
	r.t.Helper()
	deadline := time.Now().Add(20 * time.Second)
	for !strings.Contains(r.output(), want) {
		if time.Now().After(deadline) {
			r.t.Fatalf("the terminal never showed %q:\n%s", want, r.output())
		}
		time.Sleep(20 * time.Millisecond)
	}
}

// wait waits for the command to end and returns its exit code (128+n for
// a signal) and everything the terminal showed.
func (r *ptyRun) wait() (int, string) {
	r.t.Helper()
	select {
	case <-r.done:
	case <-time.After(30 * time.Second):
		r.t.Fatalf("the command did not end (a stopped harness nobody resumed?):\n%s", r.output())
	}
	// The terminal's output is complete once every holder of the terminal
	// is gone; a straggler keeps it open, so do not wait for long.
	select {
	case <-r.read:
	case <-time.After(2 * time.Second):
	}
	var exit *exec.ExitError
	switch {
	case r.err == nil:
		return 0, r.output()
	case errors.As(r.err, &exit):
		if ws, ok := exit.Sys().(syscall.WaitStatus); ok && ws.Signaled() {
			return 128 + int(ws.Signal()), r.output()
		}
		return exit.ExitCode(), r.output()
	}
	r.t.Fatalf("wait: %v", r.err)
	return 0, ""
}

// defaultDisposition makes the commands this test starts get SIGINT and
// SIGHUP with their default action, also when the test binary itself was
// started with them ignored (nohup, a background job): the runtime handles
// a notified signal, and exec resets handled signals to the default.
func defaultDisposition(t *testing.T) {
	ch := make(chan os.Signal, 1)
	signal.Notify(ch, syscall.SIGINT, syscall.SIGHUP)
	t.Cleanup(func() { signal.Stop(ch) })
}

// requireBash skips without the shell the launchers and stubs run under.
func requireBash(t *testing.T) {
	t.Helper()
	for _, f := range []string{"/bin/bash", "/usr/bin/env", "/usr/bin/python3", "/proc/self/stat"} {
		if _, err := os.Stat(f); err != nil {
			t.Skipf("%s is required", f)
		}
	}
}

// supervisorNotice starts the line the supervisor shows each time it
// resumes a harness that stopped or tried to.
const supervisorNotice = "defenseclaw: Ctrl-Z cannot suspend a harness in an OpenShell sandbox"

// checkResumed reports whether out is exactly the stub's four lines and the
// supervisor's notice for each of its three stops, the stub ran in a
// process group of its own, not as the launcher (pid), and it was the
// terminal's foreground group every time it came back.
func checkResumed(t *testing.T, out string, launcherPID int) {
	t.Helper()
	var lines []string
	notices := 0
	for _, l := range strings.Split(out, "\n") {
		switch l = strings.TrimSpace(l); {
		case l == "":
		case strings.HasPrefix(l, supervisorNotice):
			notices++
		default:
			lines = append(lines, l)
		}
	}
	want := []string{"start", "resumed TSTP", "resumed TTIN", "resumed STOP"}
	if len(lines) != len(want) || notices != len(want)-1 {
		t.Fatalf("the terminal showed %d lines and %d notices, want the stub's %d and a notice per stop (nothing else from the launcher):\n%s", len(lines), notices, len(want), out)
	}
	for i, l := range lines {
		m := stubLine.FindStringSubmatch(l)
		if m == nil || m[1] != want[i] {
			t.Fatalf("line %d = %q, want the stub's %q line:\n%s", i+1, l, want[i], out)
		}
		pid, _ := strconv.Atoi(m[2])
		if pid == launcherPID {
			t.Errorf("the stub runs as the launcher (pid %d): nothing supervises it", pid)
		}
		if m[2] != m[3] {
			t.Errorf("%s: the stub is not the leader of its own process group", l)
		}
		if m[3] != m[5] {
			t.Errorf("%s: the stub is not the terminal's foreground process group", l)
		}
		if m[4] != strconv.Itoa(launcherPID) {
			t.Errorf("%s: the stub left the launcher's session (%d)", l, launcherPID)
		}
	}
}

// TestLaunchersResumeAStoppedHarness starts every launcher on a terminal,
// as `openshell sandbox exec --tty` does, with a stub harness that stops
// itself three times: each launcher brings it back to the foreground, adds
// nothing to the screen and exits with the stub's status.
func TestLaunchersResumeAStoppedHarness(t *testing.T) {
	requireBash(t)
	for _, name := range Names() {
		spec, _ := Get(name)
		t.Run(name, func(t *testing.T) {
			launcher, dir := launcherFixture(t, spec, stubStops)
			r := startPTY(t, dir, nil, launcher)
			code, out := r.wait()
			if code != 42 {
				t.Fatalf("exit %d, want the stub's 42:\n%s", code, out)
			}
			checkResumed(t, out, r.cmd.Process.Pid)
		})
	}
	t.Run("sandbox-env", func(t *testing.T) {
		dir := t.TempDir()
		wrapper := filepath.Join(dir, "sandbox-env")
		supervisor := filepath.Join(dir, "dc_supervisor.py")
		if err := os.WriteFile(supervisor, shellFile(t, Codex, SupervisorPath).Data, 0o755); err != nil {
			t.Fatal(err)
		}
		script := strings.ReplaceAll(string(shellFile(t, Codex, SandboxEnvPath).Data), SupervisorPath, supervisor)
		if err := os.WriteFile(wrapper, []byte(script), 0o755); err != nil {
			t.Fatal(err)
		}
		stub := filepath.Join(dir, "stub")
		if err := os.WriteFile(stub, []byte("#!/bin/bash\n"+stubStops), 0o755); err != nil {
			t.Fatal(err)
		}
		r := startPTY(t, dir, nil, wrapper, stub)
		code, out := r.wait()
		if code != 42 {
			t.Fatalf("exit %d, want the stub's 42:\n%s", code, out)
		}
		checkResumed(t, out, r.cmd.Process.Pid)
	})
}

// TestLauncherJobControl covers the supervised harness's signals, exit
// status and scrubbed environment, and the runs that keep the plain exec.
func TestLauncherJobControl(t *testing.T) {
	requireBash(t)
	defaultDisposition(t)
	run := func(t *testing.T, stub string, env ...string) (*ptyRun, string) {
		launcher, dir := launcherFixture(t, ClaudeCode, stub)
		return startPTY(t, dir, env, launcher), dir
	}

	t.Run("exit status and environment", func(t *testing.T) {
		startup := filepath.Join(t.TempDir(), "startup")
		if err := os.WriteFile(startup, []byte("echo sourced-startup-file\n"), 0o644); err != nil {
			t.Fatal(err)
		}
		// The stub's own environment, as it was exec'd.
		r, _ := run(t, `kill -TSTP 0; tr '\0' '\n' </proc/$$/environ | sed -n 's/^\(BASH_ENV\|SHELLOPTS\|NODE_OPTIONS\|PATH\)=/env \1=/p'; exit 7`+"\n",
			"BASH_ENV="+startup, "SHELLOPTS=noexec", "NODE_OPTIONS=--require=/tmp/x.js")
		code, out := r.wait()
		if code != 7 {
			t.Fatalf("exit %d, want 7:\n%s", code, out)
		}
		if strings.Contains(out, "sourced-startup-file") {
			t.Errorf("a start-up file ran:\n%s", out)
		}
		for _, bad := range []string{"env BASH_ENV=", "env SHELLOPTS=", "env NODE_OPTIONS="} {
			if strings.Contains(out, bad) {
				t.Errorf("the supervised harness got %s:\n%s", bad, out)
			}
		}
		if want := "env PATH=" + LauncherSystemPATH + ":"; !strings.Contains(out, want) {
			t.Errorf("PATH does not lead with the system directories, want %q:\n%s", want, out)
		}
	})

	for _, tc := range []struct {
		name string
		sig  syscall.Signal
	}{{"SIGKILL", syscall.SIGKILL}, {"SIGTERM", syscall.SIGTERM}, {"SIGSEGV", syscall.SIGSEGV}} {
		t.Run("killed by "+tc.name, func(t *testing.T) {
			// ulimit -c 0: no core file for SIGSEGV.
			r, _ := run(t, fmt.Sprintf("ulimit -c 0; echo stub-up; kill -%d $$; sleep 5\n", int(tc.sig)))
			code, out := r.wait()
			if code != 128+int(tc.sig) {
				t.Fatalf("exit %d, want %d:\n%s", code, 128+int(tc.sig), out)
			}
			if got := strings.TrimSpace(out); got != "stub-up" {
				t.Errorf("the terminal showed more than the stub's line (a job notice?):\n%s", out)
			}
		})
	}

	t.Run("Ctrl-C reaches the harness", func(t *testing.T) {
		r, _ := run(t, "trap 'echo stub-got-INT; exit 9' INT; echo stub-up; for i in $(seq 1 100); do sleep 0.1; done; exit 0\n")
		r.waitOutput("stub-up")
		if _, err := r.master.Write([]byte{0x03}); err != nil {
			t.Fatal(err)
		}
		code, out := r.wait()
		if code != 9 || !strings.Contains(out, "stub-got-INT") {
			t.Fatalf("exit %d, want the stub's INT trap (9):\n%s", code, out)
		}
	})

	t.Run("resizes reach the harness", func(t *testing.T) {
		r, _ := run(t, "trap 'echo \"stub-winch $(stty size)\"; exit 0' WINCH; echo stub-up; for i in $(seq 1 100); do sleep 0.1; done; exit 1\n")
		r.waitOutput("stub-up")
		r.resize(40, 100)
		code, out := r.wait()
		if code != 0 || !strings.Contains(out, "stub-winch 40 100") {
			t.Fatalf("exit %d, want the stub's WINCH trap with the new size:\n%s", code, out)
		}
	})

	t.Run("a hangup reaches the harness", func(t *testing.T) {
		r, dir := run(t, `trap 'echo hup >"${0%/*}/hup"; exit 1' HUP; echo stub-up; for i in $(seq 1 300); do sleep 0.1; done; exit 0`+"\n")
		r.waitOutput("stub-up")
		_ = r.master.Close()
		r.wait()
		// The supervising bash, the session leader, ends on the SIGHUP; the
		// harness gets it when it does and runs its handler after that.
		deadline := time.Now().Add(5 * time.Second)
		for {
			if got, _ := os.ReadFile(filepath.Join(dir, "hup")); strings.TrimSpace(string(got)) == "hup" {
				break
			}
			if time.Now().After(deadline) {
				t.Fatal("the harness never got SIGHUP when the terminal hung up")
			}
			time.Sleep(50 * time.Millisecond)
		}
	})

	t.Run("what the harness leaves in its group gets SIGHUP", func(t *testing.T) {
		r, dir := run(t, `sleep 60 & echo $! >"${0%/*}/leftover"; exit 3`+"\n")
		if code, out := r.wait(); code != 3 {
			t.Fatalf("exit %d, want 3:\n%s", code, out)
		}
		raw, err := os.ReadFile(filepath.Join(dir, "leftover"))
		if err != nil {
			t.Fatal(err)
		}
		pid, _ := strconv.Atoi(strings.TrimSpace(string(raw)))
		deadline := time.Now().Add(5 * time.Second)
		for syscall.Kill(pid, 0) == nil {
			if time.Now().After(deadline) {
				_ = syscall.Kill(pid, syscall.SIGKILL)
				t.Fatalf("the harness's leftover %d outlived the session (a session leader's exit hangs up its foreground group)", pid)
			}
			time.Sleep(50 * time.Millisecond)
		}
	})

	t.Run("without a terminal the launcher execs the harness", func(t *testing.T) {
		launcher, dir := launcherFixture(t, ClaudeCode, "echo \"stub pid=$$\"; exit 5\n")
		cmd := exec.Command(launcher)
		cmd.Dir, cmd.Env = dir, []string{"PATH=/usr/bin:/bin", "HOME=" + dir}
		cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
		var out bytes.Buffer
		cmd.Stdout, cmd.Stderr = &out, &out
		if err := cmd.Start(); err != nil {
			t.Fatal(err)
		}
		err := cmd.Wait()
		var exit *exec.ExitError
		if !errors.As(err, &exit) || exit.ExitCode() != 5 {
			t.Fatalf("exit %v, want 5:\n%s", err, out.String())
		}
		if want := fmt.Sprintf("stub pid=%d", cmd.Process.Pid); strings.TrimSpace(out.String()) != want {
			t.Errorf("headless output %q, want %q (the harness keeps the launcher's pid)", out.String(), want)
		}
	})

	t.Run("without the supervisor's interpreter the launcher execs the harness", func(t *testing.T) {
		// A base image without /usr/bin/python3: the terminal session
		// would supervise the harness, but the launcher must still start it.
		launcher, dir := launcherFixture(t, ClaudeCode, "echo \"stub pid=$$\"; exit 5\n")
		rewriteLauncher(t, launcher, SupervisorInterpreter+" ", filepath.Join(dir, "no-python3")+" ")
		r := startPTY(t, dir, nil, launcher)
		code, out := r.wait()
		if code != 5 {
			t.Fatalf("exit %d, want the harness's 5:\n%s", code, out)
		}
		if want := fmt.Sprintf("stub pid=%d", r.cmd.Process.Pid); strings.TrimSpace(out) != want {
			t.Errorf("output %q, want %q (the harness keeps the launcher's pid)", out, want)
		}
	})

	t.Run("under a job-control shell the launcher supervises the harness", func(t *testing.T) {
		// The shell (a `sandbox connect --shell` prompt) runs the launcher
		// as a foreground job. In a sandbox its fg could not resume a
		// stopped job (killpg is refused), so the supervisor resumes the
		// harness and the shell never sees it stop.
		launcher, dir := launcherFixture(t, ClaudeCode, stubState+`echo "stub parent=$PPID $(st)"; kill -TSTP 0; echo stub-resumed; exit 6`+"\n")
		shell := filepath.Join(dir, "shell")
		script := `set -m
` + shellQuote(launcher) + `
rc=$?
dc_fg() { fg %% >/dev/null; rc=$?; }
while jobs %% >/dev/null 2>&1; do echo "shell: job stopped"; dc_fg; done
echo "shell pid=$$"
exit $rc
`
		if err := os.WriteFile(shell, []byte(script), 0o755); err != nil {
			t.Fatal(err)
		}
		r := startPTY(t, dir, nil, "/bin/bash", shell)
		code, out := r.wait()
		if code != 6 || strings.Contains(out, "shell: job stopped") || !strings.Contains(out, "stub-resumed") ||
			!strings.Contains(out, supervisorNotice) {
			t.Fatalf("exit %d, want the supervisor to resume the stub, say so, and the stub's 6:\n%s", code, out)
		}
		if unwanted := fmt.Sprintf("stub parent=%d ", r.cmd.Process.Pid); strings.Contains(out, unwanted) {
			t.Errorf("the harness is the shell's own job: nothing supervises it\n%s", out)
		}
	})

	t.Run("a harness in the background of a shell is left alone", func(t *testing.T) {
		// The supervisor would take the terminal from the shell.
		launcher, dir := launcherFixture(t, ClaudeCode, stubState+`echo "stub parent=$PPID $(st)"; exit 4`+"\n")
		shell := filepath.Join(dir, "shell")
		script := `set -m
` + shellQuote(launcher) + ` &
wait $!
rc=$?
echo "shell pid=$$"
exit $rc
`
		if err := os.WriteFile(shell, []byte(script), 0o755); err != nil {
			t.Fatal(err)
		}
		r := startPTY(t, dir, nil, "/bin/bash", shell)
		code, out := r.wait()
		if want := fmt.Sprintf("stub parent=%d ", r.cmd.Process.Pid); code != 4 || !strings.Contains(out, want) {
			t.Fatalf("exit %d, want the stub's 4 as the shell's own background job (%q):\n%s", code, want, out)
		}
	})
}

// stubCannotStop is a TUI whose own suspend cannot stop it, as in an
// OpenShell sandbox, which refuses a kill() aimed at a process group: it
// takes the terminal into raw mode, gives it back in canonical mode as a
// suspending TUI does, waits for the SIGCONT that ends a suspend, and takes
// the terminal back into raw mode, as a resumed TUI redraws, before it exits.
const stubCannotStop = `trap 'echo "stub resumed CONT"; stty raw -echo; sleep 0.6; stty sane; exit 5' CONT
stty raw -echo
sleep 0.5
stty sane
echo "stub suspended"
while :; do sleep 0.1; done
`

// stubShutsDown is a TUI that gives the terminal back in canonical mode to
// shut down, which takes it longer than a suspend is waited for.
const stubShutsDown = `stty raw -echo
sleep 0.5
stty sane
echo "stub shutting down"
sleep 1.5
exit 0
`

// TestLauncherResumesAHarnessWhoseSuspendFailed: a harness that gave the
// terminal back and waits for SIGCONT without having stopped gets it from
// the supervisor, so its TUI comes back instead of hanging, and once it
// exits the terminal says why it was not suspended. A TUI that gives the
// terminal back to shut down gets no such notice.
func TestLauncherResumesAHarnessWhoseSuspendFailed(t *testing.T) {
	requireBash(t)
	if _, err := exec.LookPath("stty"); err != nil {
		t.Skip("stty is required")
	}
	launcher, dir := launcherFixture(t, ClaudeCode, stubCannotStop)
	r := startPTY(t, dir, nil, launcher)
	code, out := r.wait()
	resumed := strings.Index(out, "stub resumed CONT")
	if code != 5 || resumed < 0 || strings.LastIndex(out, supervisorNotice) < resumed {
		t.Fatalf("exit %d, want the stub's 5 after a SIGCONT, then the supervisor's notice:\n%s", code, out)
	}
	// It is said at once too, in the title (kept, and restored before the
	// exit's notice), while the TUI owns the screen (cert copilot:F3: only
	// "kill EPERM" showed until the harness exited).
	title := strings.Index(out, "\x1b]2;[defenseclaw] Ctrl-Z cannot suspend a harness")
	if push, pop := strings.Index(out, "\x1b[22;0t"), strings.LastIndex(out, "\x1b[23;0t"); title < resumed || push < 0 || push > title ||
		pop < title || pop > strings.LastIndex(out, supervisorNotice) {
		t.Fatalf("title notice at %d (push %d, pop %d), resumed at %d, want it between them:\n%q", title, push, pop, resumed, out)
	}

	launcher, dir = launcherFixture(t, ClaudeCode, stubShutsDown)
	r = startPTY(t, dir, nil, launcher)
	code, out = r.wait()
	if code != 0 || !strings.Contains(out, "stub shutting down") || strings.Contains(out, supervisorNotice) {
		t.Fatalf("exit %d, want the stub's 0 without a suspend notice:\n%s", code, out)
	}
}

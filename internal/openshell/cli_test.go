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

package openshell_test

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/openshell"
)

func TestCLIArgv(t *testing.T) {
	cli := openshell.CLI{Gateway: "openshell"}
	// cmd is the argv of an openshell subcommand on the default gateway.
	cmd := func(sub, rest string) string { return "openshell " + sub + " -g openshell --workspace default " + rest }
	stage, _ := filepath.Abs("stage")
	cases := []struct {
		name        string
		inv         func() (openshell.Invocation, error)
		want        string
		interactive bool
		detaches    bool
		timeout     time.Duration
	}{
		{name: "exec automation", inv: func() (openshell.Invocation, error) {
			return cli.Exec("dc-claude-app-7f3a", []string{"git", "-C", "/work/app", "status"}, openshell.CLIExecOptions{
				WorkDir: "/work/app/", Timeout: 1500 * time.Millisecond, Env: map[string]string{"LANG": "C", "A": "b c"}})
		}, want: cmd("sandbox exec", "--color never --name dc-claude-app-7f3a --workdir /work/app --timeout 2 --no-tty --no-login-shell --env A=b c --env LANG=C -- git -C /work/app status"),
			timeout: 12 * time.Second},
		{name: "exec tty", inv: func() (openshell.Invocation, error) {
			return cli.Exec("box", []string{"claude", "--dangerously-skip-permissions"}, openshell.CLIExecOptions{TTY: true, LoginShell: true})
		}, want: cmd("sandbox exec", "--name box --tty -- claude --dangerously-skip-permissions"), interactive: true},
		{name: "connect", inv: func() (openshell.Invocation, error) { return cli.Connect("box") }, want: cmd("sandbox connect", "-- box"), interactive: true},
		{name: "upload staged tree", inv: func() (openshell.Invocation, error) {
			return cli.Upload("box", "stage", "/sandbox/work/../work", false)
		}, want: cmd("sandbox upload", "--color never --no-git-ignore -- box "+stage+" /sandbox/work"), timeout: openshell.DefaultTransferTimeout},
		{name: "upload honouring gitignore", inv: func() (openshell.Invocation, error) { return cli.Upload("box", "/tmp/x", "/sandbox", true) },
			want: cmd("sandbox upload", "--color never -- box /tmp/x /sandbox"), timeout: openshell.DefaultTransferTimeout},
		{name: "download", inv: func() (openshell.Invocation, error) { return cli.Download("box", "/sandbox/result.bundle", "/tmp/out") },
			want: cmd("sandbox download", "--color never -- box /sandbox/result.bundle /tmp/out"), timeout: openshell.DefaultTransferTimeout},
		// Only the background forward leaves a process behind.
		{name: "forward start", inv: func() (openshell.Invocation, error) { return cli.ForwardStart("box", 18789, "") },
			want: cmd("forward start", "--color never --background -- 127.0.0.1:18789 box"), detaches: true, timeout: openshell.DefaultForwardTimeout},
		{name: "forward start ipv6 loopback", inv: func() (openshell.Invocation, error) { return cli.ForwardStart("box", 8080, "::1") },
			want: cmd("forward start", "--color never --background -- [::1]:8080 box"), detaches: true, timeout: openshell.DefaultForwardTimeout},
		{name: "forward stop", inv: func() (openshell.Invocation, error) { return cli.ForwardStop("box", 18789) },
			want: cmd("forward stop", "--color never -- 18789 box"), timeout: openshell.DefaultForwardTimeout},
		{name: "custom binary and workspace", inv: func() (openshell.Invocation, error) {
			return openshell.CLI{Binary: "/usr/bin/openshell", Gateway: "work", Workspace: "team_a"}.Connect("box")
		}, want: "/usr/bin/openshell sandbox connect -g work --workspace team_a -- box", interactive: true},
		{name: "version", inv: func() (openshell.Invocation, error) { return cli.Version(), nil }, want: "openshell --version", timeout: 30 * time.Second},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			inv, err := tc.inv()
			if err != nil {
				t.Fatal(err)
			}
			if got := strings.Join(inv.Argv, " "); got != tc.want {
				t.Fatalf("argv\n got %s\nwant %s", got, tc.want)
			}
			if inv.Interactive != tc.interactive || inv.Detaches != tc.detaches || inv.Timeout != tc.timeout {
				t.Fatalf("interactive=%v detaches=%v timeout=%s", inv.Interactive, inv.Detaches, inv.Timeout)
			}
		})
	}
}

func TestCLIRefusesUnsafeArguments(t *testing.T) {
	cli := openshell.CLI{Gateway: "openshell"}
	exec := func(argv []string, o openshell.CLIExecOptions) func() error {
		return func() error { _, err := cli.Exec("box", argv, o); return err }
	}
	for name, fn := range map[string]func() error{
		"no gateway":         func() error { _, err := openshell.CLI{}.Connect("box"); return err },
		"gateway flag":       func() error { _, err := openshell.CLI{Gateway: "--gateway-insecure"}.Connect("box"); return err },
		"bad workspace":      func() error { _, err := openshell.CLI{Gateway: "g", Workspace: "a b"}.Connect("box"); return err },
		"option as sandbox":  func() error { _, err := cli.Connect("--editor=vscode"); return err },
		"empty command":      exec(nil, openshell.CLIExecOptions{}),
		"relative workdir":   exec([]string{"ls"}, openshell.CLIExecOptions{WorkDir: "work"}),
		"env name":           exec([]string{"ls"}, openshell.CLIExecOptions{Env: map[string]string{"A=B": "c"}}),
		"env newline":        exec([]string{"ls"}, openshell.CLIExecOptions{Env: map[string]string{"A": "b\nc"}}),
		"relative dest":      func() error { _, err := cli.Upload("box", "/tmp/x", "sandbox", true); return err },
		"option-like remote": func() error { _, err := cli.Download("box", "-rf", "/tmp/x"); return err },
		"public bind":        func() error { _, err := cli.ForwardStart("box", 80, "0.0.0.0"); return err },
		"hostname bind":      func() error { _, err := cli.ForwardStart("box", 80, "localhost"); return err },
		"port zero":          func() error { _, err := cli.ForwardStart("box", 0, ""); return err },
		"port range":         func() error { _, err := cli.ForwardStop("box", 70000); return err },
	} {
		if fn() == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

func TestEnvironScrubsGatewayOverrides(t *testing.T) {
	got := openshell.Environ([]string{"PATH=/bin", "OPENSHELL_GATEWAY=evil", "OPENSHELL_GATEWAY_INSECURE=1",
		"OPENSHELL_GATEWAY_ENDPOINT=https://x", "OPENSHELL_WORKSPACE=w", "OPENSHELL_COLOR=never", "HOME=/h"})
	if strings.Join(got, " ") != "PATH=/bin OPENSHELL_COLOR=never HOME=/h" {
		t.Fatalf("Environ = %v", got)
	}
}

// fakeCLI writes a stand-in openshell binary.
func fakeCLI(t *testing.T, body string) string {
	t.Helper()
	skipOnWindows(t)
	path := filepath.Join(t.TempDir(), "openshell")
	if err := os.WriteFile(path, []byte("#!/bin/sh\n"+body), 0o755); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestInvocationCommandNonInteractive(t *testing.T) {
	// cat returns at once on /dev/null; an inherited open pipe would hang.
	bin := fakeCLI(t, `cat; echo "gw=${OPENSHELL_GATEWAY:-} insecure=${OPENSHELL_GATEWAY_INSECURE:-}"; for a in "$@"; do echo "[$a]"; done`)
	t.Setenv("OPENSHELL_GATEWAY", "attacker")
	t.Setenv("OPENSHELL_GATEWAY_INSECURE", "1")
	inv, err := openshell.CLI{Binary: bin, Gateway: "openshell"}.Download("box", "/sandbox/a b", "/tmp/out")
	if err != nil {
		t.Fatal(err)
	}
	cmd, cancel, err := inv.Command(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	defer cancel()
	var out bytes.Buffer
	cmd.Stdout = &out
	start := time.Now()
	if err := cmd.Run(); err != nil || time.Since(start) > 5*time.Second {
		t.Fatalf("Run = %v after %s; stdin must be the null device", err, time.Since(start))
	}
	if lines := strings.Split(strings.TrimSpace(out.String()), "\n"); lines[0] != "gw= insecure=" {
		t.Fatalf("environment leaked: %q", lines[0])
	}
	if !strings.Contains(out.String(), "[/sandbox/a b]") || !strings.Contains(out.String(), "[-g]\n[openshell]") {
		t.Fatalf("argv = %q", out.String())
	}
}

func TestInvocationCommandTimeout(t *testing.T) {
	bin := fakeCLI(t, "exec sleep 30\n")
	cmd, cancel, err := openshell.Invocation{Argv: []string{bin}, Timeout: 200 * time.Millisecond}.Command(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	defer cancel()
	start := time.Now()
	if err := cmd.Run(); err == nil || time.Since(start) > 10*time.Second {
		t.Fatalf("hung command: Run = %v after %s", err, time.Since(start))
	}
	if _, _, err := (openshell.Invocation{}).Command(context.Background()); err == nil {
		t.Fatal("empty invocation accepted")
	}
}

func TestInvocationOutput(t *testing.T) {
	bin := fakeCLI(t, "echo out; echo err >&2; exit 3\n")
	out, err := openshell.Invocation{Argv: []string{bin, "sandbox", "upload"}, Timeout: 10 * time.Second}.Output(context.Background())
	if err == nil || !strings.Contains(err.Error(), "exit status 3") || !strings.Contains(err.Error(), "sandbox upload") || string(out) != "out\nerr\n" {
		t.Fatalf("Output = %q, %v", out, err)
	}
	if _, err := (openshell.Invocation{Argv: []string{bin}, Interactive: true}).Output(context.Background()); err == nil {
		t.Fatal("interactive invocation captured")
	}
}

// daemonCLI writes a stand-in for `openshell forward start --background`:
// it leaves a process holding the inherited stderr, as ssh -f does, and
// that process writes to it after the command exits. It returns a function
// that waits for the daemon's PID; the daemon is killed when the test ends.
func daemonCLI(t *testing.T) (bin string, daemon func() *os.Process) {
	t.Helper()
	pidFile := filepath.Join(t.TempDir(), "daemon.pid")
	bin = fakeCLI(t, `sh -c 'echo $$ > "$1.tmp" && mv "$1.tmp" "$1"; sleep 0.3; echo late >&2; exec sleep 30' daemon "`+pidFile+`" </dev/null >/dev/null &
echo "Forwarding port 18789 to sandbox box in the background" >&2
`)
	daemon = func() *os.Process {
		for deadline := time.Now().Add(5 * time.Second); time.Now().Before(deadline); time.Sleep(10 * time.Millisecond) {
			if data, err := os.ReadFile(pidFile); err == nil {
				pid, err := strconv.Atoi(strings.TrimSpace(string(data)))
				if err != nil {
					t.Fatalf("pid file %q", data)
				}
				p, _ := os.FindProcess(pid)
				return p
			}
		}
		return nil
	}
	t.Cleanup(func() {
		if p := daemon(); p != nil {
			_ = p.Kill()
		}
	})
	return bin, daemon
}

// TestInvocationDetached covers a background forward: neither Command nor
// Output waits on the pipes its daemon keeps, and the daemon survives its
// late writes. A pipe would have held Wait until WaitDelay (5s) and then
// failed with exec.ErrWaitDelay.
func TestInvocationDetached(t *testing.T) {
	bin, _ := daemonCLI(t)
	cmd, cancel, err := openshell.Invocation{Argv: []string{bin}, Detaches: true, Timeout: 20 * time.Second}.Command(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	defer cancel()
	if cmd.Stdout != nil || cmd.Stderr != nil {
		t.Fatalf("detached command has writers %v, %v", cmd.Stdout, cmd.Stderr)
	}
	start := time.Now()
	if err := cmd.Run(); err != nil || time.Since(start) > 3*time.Second {
		t.Fatalf("Run = %v after %s", err, time.Since(start))
	}

	bin, daemon := daemonCLI(t)
	start = time.Now()
	out, err := openshell.Invocation{Argv: []string{bin}, Detaches: true, Timeout: 20 * time.Second}.Output(context.Background())
	if err != nil || time.Since(start) > 3*time.Second || !strings.Contains(string(out), "Forwarding port 18789") {
		t.Fatalf("Output = %q, %v after %s", out, err, time.Since(start))
	}
	p := daemon()
	if p == nil {
		t.Fatal("the background process did not start")
	}
	// The background process writes again after the command has exited
	// and is still running afterwards: its stderr was never closed under
	// it.
	time.Sleep(600 * time.Millisecond)
	if err := p.Signal(syscall.Signal(0)); err != nil {
		t.Fatalf("background process died after its late write: %v", err)
	}
}

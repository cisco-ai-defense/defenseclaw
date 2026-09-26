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
	"strings"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/openshell"
)

func TestCLIArgv(t *testing.T) {
	cli := openshell.CLI{Gateway: "openshell"}
	g := []string{"-g", "openshell", "--workspace", "default"}
	join := func(parts ...[]string) string {
		var all []string
		for _, p := range parts {
			all = append(all, p...)
		}
		return strings.Join(all, " ")
	}
	abs := func(p string) string {
		a, _ := filepath.Abs(p)
		return a
	}
	cases := []struct {
		name        string
		inv         func() (openshell.Invocation, error)
		want        string
		interactive bool
		timeout     time.Duration
	}{
		{
			name: "exec automation",
			inv: func() (openshell.Invocation, error) {
				return cli.Exec("dc-claude-app-7f3a", []string{"git", "-C", "/work/app", "status"}, openshell.CLIExecOptions{
					WorkDir: "/work/app/", Timeout: 1500 * time.Millisecond, Env: map[string]string{"LANG": "C", "A": "b c"}})
			},
			want: join([]string{"openshell", "sandbox", "exec"}, g, []string{"--color", "never", "--name", "dc-claude-app-7f3a",
				"--workdir", "/work/app", "--timeout", "2", "--no-tty", "--no-login-shell", "--env", "A=b c", "--env", "LANG=C",
				"--", "git", "-C", "/work/app", "status"}),
			timeout: 12 * time.Second,
		},
		{
			name: "exec tty",
			inv: func() (openshell.Invocation, error) {
				return cli.Exec("box", []string{"claude", "--dangerously-skip-permissions"}, openshell.CLIExecOptions{TTY: true, LoginShell: true})
			},
			want:        join([]string{"openshell", "sandbox", "exec"}, g, []string{"--name", "box", "--tty", "--", "claude", "--dangerously-skip-permissions"}),
			interactive: true,
		},
		{
			name:        "connect",
			inv:         func() (openshell.Invocation, error) { return cli.Connect("box") },
			want:        join([]string{"openshell", "sandbox", "connect"}, g, []string{"--", "box"}),
			interactive: true,
		},
		{
			name: "upload staged tree",
			inv: func() (openshell.Invocation, error) {
				return cli.Upload("box", "stage", "/sandbox/work/../work", false)
			},
			want: join([]string{"openshell", "sandbox", "upload"}, g, []string{"--color", "never", "--no-git-ignore", "--", "box",
				abs("stage"), "/sandbox/work"}),
			timeout: openshell.DefaultTransferTimeout,
		},
		{
			name:    "upload honouring gitignore",
			inv:     func() (openshell.Invocation, error) { return cli.Upload("box", "/tmp/x", "/sandbox", true) },
			want:    join([]string{"openshell", "sandbox", "upload"}, g, []string{"--color", "never", "--", "box", "/tmp/x", "/sandbox"}),
			timeout: openshell.DefaultTransferTimeout,
		},
		{
			name:    "download",
			inv:     func() (openshell.Invocation, error) { return cli.Download("box", "/sandbox/result.bundle", "/tmp/out") },
			want:    join([]string{"openshell", "sandbox", "download"}, g, []string{"--color", "never", "--", "box", "/sandbox/result.bundle", "/tmp/out"}),
			timeout: openshell.DefaultTransferTimeout,
		},
		{
			name:    "forward start",
			inv:     func() (openshell.Invocation, error) { return cli.ForwardStart("box", 18789, "") },
			want:    join([]string{"openshell", "forward", "start"}, g, []string{"--color", "never", "--background", "--", "127.0.0.1:18789", "box"}),
			timeout: openshell.DefaultForwardTimeout,
		},
		{
			name:    "forward start ipv6 loopback",
			inv:     func() (openshell.Invocation, error) { return cli.ForwardStart("box", 8080, "::1") },
			want:    join([]string{"openshell", "forward", "start"}, g, []string{"--color", "never", "--background", "--", "[::1]:8080", "box"}),
			timeout: openshell.DefaultForwardTimeout,
		},
		{
			name:    "forward stop",
			inv:     func() (openshell.Invocation, error) { return cli.ForwardStop("box", 18789) },
			want:    join([]string{"openshell", "forward", "stop"}, g, []string{"--color", "never", "--", "18789", "box"}),
			timeout: openshell.DefaultForwardTimeout,
		},
		{
			name: "custom binary and workspace",
			inv: func() (openshell.Invocation, error) {
				return openshell.CLI{Binary: "/usr/bin/openshell", Gateway: "work", Workspace: "team_a"}.Connect("box")
			},
			want:        "/usr/bin/openshell sandbox connect -g work --workspace team_a -- box",
			interactive: true,
		},
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
			if inv.Interactive != tc.interactive || inv.Timeout != tc.timeout {
				t.Fatalf("interactive=%v timeout=%s", inv.Interactive, inv.Timeout)
			}
		})
	}
	if v := cli.Version(); strings.Join(v.Argv, " ") != "openshell --version" || v.Interactive {
		t.Fatalf("version = %+v", v)
	}
}

func TestCLIRefusesUnsafeArguments(t *testing.T) {
	cli := openshell.CLI{Gateway: "openshell"}
	for name, fn := range map[string]func() error{
		"no gateway":        func() error { _, err := openshell.CLI{}.Connect("box"); return err },
		"gateway flag":      func() error { _, err := openshell.CLI{Gateway: "--gateway-insecure"}.Connect("box"); return err },
		"bad workspace":     func() error { _, err := openshell.CLI{Gateway: "g", Workspace: "a b"}.Connect("box"); return err },
		"option as sandbox": func() error { _, err := cli.Connect("--editor=vscode"); return err },
		"empty command":     func() error { _, err := cli.Exec("box", nil, openshell.CLIExecOptions{}); return err },
		"relative workdir": func() error {
			_, err := cli.Exec("box", []string{"ls"}, openshell.CLIExecOptions{WorkDir: "work"})
			return err
		},
		"env name": func() error {
			_, err := cli.Exec("box", []string{"ls"}, openshell.CLIExecOptions{Env: map[string]string{"A=B": "c"}})
			return err
		},
		"env newline": func() error {
			_, err := cli.Exec("box", []string{"ls"}, openshell.CLIExecOptions{Env: map[string]string{"A": "b\nc"}})
			return err
		},
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
	if err := cmd.Run(); err != nil {
		t.Fatal(err)
	}
	if time.Since(start) > 5*time.Second {
		t.Fatal("stdin was not the null device")
	}
	lines := strings.Split(strings.TrimSpace(out.String()), "\n")
	if lines[0] != "gw= insecure=" {
		t.Fatalf("environment leaked: %q", lines[0])
	}
	if !strings.Contains(out.String(), "[/sandbox/a b]") || !strings.Contains(out.String(), "[-g]\n[openshell]") {
		t.Fatalf("argv = %q", out.String())
	}
}

func TestInvocationCommandTimeout(t *testing.T) {
	bin := fakeCLI(t, "exec sleep 30\n")
	inv := openshell.Invocation{Argv: []string{bin}, Timeout: 200 * time.Millisecond}
	cmd, cancel, err := inv.Command(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	defer cancel()
	start := time.Now()
	if err := cmd.Run(); err == nil {
		t.Fatal("hung command was not killed")
	}
	if time.Since(start) > 10*time.Second {
		t.Fatalf("timeout took %s", time.Since(start))
	}
	if _, _, err := (openshell.Invocation{}).Command(context.Background()); err == nil {
		t.Fatal("empty invocation accepted")
	}
}

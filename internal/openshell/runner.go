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

package openshell

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"os/signal"
	"runtime"
	"strconv"
	"strings"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/processutil"
)

// Command is an external program invocation made by setup, gateway
// configuration and doctor.
type Command struct {
	Name string
	Args []string
	// Env is appended to the caller's environment (with the gateway
	// selecting OPENSHELL_ variables removed).
	Env []string
	// Unset names further inherited variables to drop.
	Unset []string
	// Timeout bounds captured commands (0: 2 minutes).
	Timeout time.Duration
}

func (c Command) String() string {
	parts := append(append([]string{}, c.Env...), c.Name)
	return strings.Join(append(parts, c.Args...), " ")
}

// Runner runs external commands. Tests substitute a fake; ExecRunner is
// the real implementation.
type Runner interface {
	// Output runs a captured command and returns its combined output.
	Output(ctx context.Context, cmd Command) ([]byte, error)
	// Run runs a command attached to the terminal, for steps that may
	// prompt (sudo in the upstream installer).
	Run(ctx context.Context, cmd Command) error
}

// ExecRunner runs commands with os/exec.
type ExecRunner struct {
	// Stdin, Stdout and Stderr serve Run; they default to the process's
	// own streams.
	Stdin          io.Reader
	Stdout, Stderr io.Writer
}

const defaultCommandTimeout = 2 * time.Minute

func (c Command) environ() []string {
	env := withRuntimeDir(Environ(os.Environ()), userRuntimeDir)
	if len(c.Unset) > 0 {
		kept := env[:0]
		for _, kv := range env {
			name, _, _ := strings.Cut(kv, "=")
			drop := false
			for _, u := range c.Unset {
				if name == u {
					drop = true
					break
				}
			}
			if !drop {
				kept = append(kept, kv)
			}
		}
		env = kept
	}
	return append(env, c.Env...)
}

// withRuntimeDir sets XDG_RUNTIME_DIR to runtimeDir() where env has none:
// a login shell from `su -l` or `sudo -iu` leaves it unset although the
// user manager runs (linger, or another session), and `systemctl --user`
// then fails with "Failed to connect to bus: No medium found".
func withRuntimeDir(env []string, runtimeDir func() string) []string {
	for _, kv := range env {
		if v, ok := strings.CutPrefix(kv, "XDG_RUNTIME_DIR="); ok && v != "" {
			return env
		}
	}
	if dir := runtimeDir(); dir != "" {
		return append(env, "XDG_RUNTIME_DIR="+dir)
	}
	return env
}

// userRuntimeDir is the caller's systemd runtime directory, /run/user/UID,
// when it exists and is the caller's ("" off Linux).
func userRuntimeDir() string {
	if runtime.GOOS != "linux" {
		return ""
	}
	dir := "/run/user/" + strconv.Itoa(os.Geteuid())
	if info, err := os.Lstat(dir); err != nil || !info.IsDir() || !ownedByCaller(info) {
		return ""
	}
	return dir
}

// Output implements Runner.
func (r ExecRunner) Output(ctx context.Context, c Command) ([]byte, error) {
	timeout := c.Timeout
	if timeout <= 0 {
		timeout = defaultCommandTimeout
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	cmd := processutil.CommandContext(ctx, c.Name, c.Args...)
	cmd.Env = c.environ()
	cmd.WaitDelay = 5 * time.Second
	out, err := processutil.CombinedOutputTree(cmd, false)
	if err != nil {
		return out, fmt.Errorf("%s: %w", c.Name, err)
	}
	return out, nil
}

// ErrInterrupted means the user pressed Ctrl-C while a command attached to
// the terminal ran (Runner.Run): it went to that command, which ended.
var ErrInterrupted = errors.New("interrupted")

// Run implements Runner. The command owns the terminal while it runs: a
// Ctrl-C reaches it (the terminal signals its whole process group) but
// does not end this process, which waits for it and returns
// ErrInterrupted, so the caller's cleanup runs and it can say what was
// left undone. A second Ctrl-C ends a command that ignored the first.
func (r ExecRunner) Run(ctx context.Context, c Command) error {
	cmd := exec.CommandContext(ctx, c.Name, c.Args...)
	cmd.Env = c.environ()
	cmd.Stdin, cmd.Stdout, cmd.Stderr = r.Stdin, r.Stdout, r.Stderr
	if cmd.Stdin == nil {
		cmd.Stdin = os.Stdin
	}
	if cmd.Stdout == nil {
		cmd.Stdout = os.Stdout
	}
	if cmd.Stderr == nil {
		cmd.Stderr = os.Stderr
	}
	sig := make(chan os.Signal, 2)
	signal.Notify(sig, os.Interrupt)
	defer signal.Stop(sig)
	if err := cmd.Start(); err != nil {
		return fmt.Errorf("%s: %w", c.Name, err)
	}
	done := make(chan error, 1)
	go func() { done <- cmd.Wait() }()
	interrupted := false
	for {
		select {
		case err := <-done:
			if interrupted {
				return fmt.Errorf("%s: %w", c.Name, ErrInterrupted)
			}
			if err != nil {
				return fmt.Errorf("%s: %w", c.Name, err)
			}
			return nil
		case <-sig:
			if interrupted {
				_ = cmd.Process.Kill()
			}
			interrupted = true
		}
	}
}

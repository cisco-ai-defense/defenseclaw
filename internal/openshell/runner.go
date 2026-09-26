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
	"fmt"
	"io"
	"os"
	"os/exec"
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
	env := Environ(os.Environ())
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

// Run implements Runner.
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
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("%s: %w", c.Name, err)
	}
	return nil
}

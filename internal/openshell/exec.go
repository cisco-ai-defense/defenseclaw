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
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"strconv"
	"time"

	v1 "github.com/NVIDIA/OpenShell/sdk/go/openshell/v1"
)

// Exec defaults.
//
// Ending an exec stream does not stop the command in OpenShell 0.1.1:
// neither a cancelled client stream nor the request's execution_timeout
// (which only makes the gateway report exit status 124) signals it. A
// retried attempt would therefore run alongside the first. So Exec wraps
// every command in coreutils timeout(1) inside the sandbox, which stops it
// at ExecOptions.Timeout, and retries only attempts whose stream never
// opened.
const (
	DefaultExecTimeout = 60 * time.Second
	// DefaultExecAttempts is one attempt: the retry of an attempt that
	// never started is opt-in.
	DefaultExecAttempts   = 1
	DefaultExecRetryDelay = time.Second
	// DefaultExecMaxOutput caps each of stdout and stderr in ExecResult.
	DefaultExecMaxOutput = 16 << 20
	// DefaultExecGrace is how long past ExecOptions.Timeout the client
	// waits for the sandbox to report the end of a stopped command: the
	// SIGTERM-to-SIGKILL window plus gateway latency.
	DefaultExecGrace = 15 * time.Second
	// ExecKillAfter is how long the sandbox waits after SIGTERM before it
	// sends SIGKILL to a command that outlived its timeout.
	ExecKillAfter = 5 * time.Second
)

// Exit statuses of coreutils timeout(1) and the shell.
const (
	exitTimedOut = 124 // the command was stopped with SIGTERM
	exitKilled   = 137 // 128+SIGKILL: it ignored SIGTERM
	exitNotFound = 127
)

var (
	// ErrExecTimeout reports a command that did not finish in time. The
	// sandbox stops the command itself at its timeout; see ExecOptions.
	ErrExecTimeout = errors.New("openshell: exec timed out")
	// ErrNoSandboxTimeout reports a sandbox image without timeout(1)
	// (coreutils or busybox), which Exec needs to bound commands.
	ErrNoSandboxTimeout = errors.New("openshell: the sandbox image has no timeout(1) command")
)

// ExecOptions tune Client.Exec.
type ExecOptions struct {
	// Env sets non-secret variables for the command. Secrets belong in
	// providers, never here.
	Env     map[string]string
	WorkDir string
	// LoginShell sources the sandbox user's profile first. The default
	// (false) gives automation a predictable environment.
	LoginShell bool
	// Timeout bounds the command (default DefaultExecTimeout). The sandbox
	// sends it SIGTERM when the timeout expires and SIGKILL ExecKillAfter
	// later; the call then fails with ErrExecTimeout. OpenShell's seccomp
	// filter forbids process-group signals, so only the command itself is
	// signalled: children that outlive it (a `sh -c` script's current
	// step, a daemon) keep running until they finish, and while they hold
	// its output open the client gives up ClientOptions.ExecGrace after
	// the timeout instead.
	Timeout time.Duration
	// Attempts is the total number of tries (default DefaultExecAttempts).
	// Only an attempt whose stream could not be opened because the
	// gateway was unavailable is retried: that command never started. A
	// timeout, or a stream lost after it opened, is never retried, because
	// the command may have run.
	Attempts int
	// RetryDelay is the first backoff; it doubles per retry.
	RetryDelay time.Duration
	// MaxOutputBytes caps each captured stream (default
	// DefaultExecMaxOutput); ExecResult.Truncated reports overflow.
	MaxOutputBytes int
	// Stdout and Stderr, when set, receive output as it streams in, in
	// addition to the capture.
	Stdout io.Writer
	Stderr io.Writer
}

func (o ExecOptions) withDefaults() ExecOptions {
	if o.Timeout <= 0 {
		o.Timeout = DefaultExecTimeout
	}
	if o.Attempts <= 0 {
		o.Attempts = DefaultExecAttempts
	}
	if o.RetryDelay <= 0 {
		o.RetryDelay = DefaultExecRetryDelay
	}
	if o.MaxOutputBytes <= 0 {
		o.MaxOutputBytes = DefaultExecMaxOutput
	}
	return o
}

// ExecResult is a finished command.
type ExecResult struct {
	ExitCode  int
	Stdout    []byte
	Stderr    []byte
	Truncated bool
	// Attempts is how many tries the result took.
	Attempts int
}

// SandboxTimeoutArgv wraps argv in the timeout(1) invocation Client.Exec
// sends: `timeout -k <ExecKillAfter> <timeout> argv...`, durations in
// seconds.
func SandboxTimeoutArgv(argv []string, timeout time.Duration) []string {
	return append([]string{"timeout", "-k", formatSeconds(ExecKillAfter), formatSeconds(timeout)}, argv...)
}

// ParseSandboxTimeoutArgv undoes SandboxTimeoutArgv, for fakes and logs.
func ParseSandboxTimeoutArgv(argv []string) (command []string, timeout time.Duration, ok bool) {
	if len(argv) < 5 || argv[0] != "timeout" || argv[1] != "-k" || argv[2] != formatSeconds(ExecKillAfter) {
		return argv, 0, false
	}
	secs, err := strconv.ParseFloat(argv[3], 64)
	if err != nil || secs <= 0 {
		return argv, 0, false
	}
	return argv[4:], time.Duration(secs * float64(time.Second)).Round(time.Millisecond), true
}

// formatSeconds renders d, rounded up to a millisecond, as timeout(1)
// seconds.
func formatSeconds(d time.Duration) string {
	ms := (d + time.Millisecond - 1) / time.Millisecond
	if ms%1000 == 0 {
		return strconv.FormatInt(int64(ms/1000), 10)
	}
	return strconv.FormatFloat(float64(ms)/1000, 'f', -1, 64)
}

func (c *client) Exec(ctx context.Context, sandbox string, argv []string, opts ExecOptions) (*ExecResult, error) {
	if err := checkSandboxName(sandbox); err != nil {
		return nil, err
	}
	if len(argv) == 0 || argv[0] == "" {
		return nil, errors.New("openshell: exec needs a command")
	}
	opts = opts.withDefaults()
	wrapped := SandboxTimeoutArgv(argv, opts.Timeout)
	delay := opts.RetryDelay
	var lastErr error
	for attempt := 1; attempt <= opts.Attempts; attempt++ {
		res, opened, err := c.execOnce(ctx, sandbox, wrapped, opts)
		if err == nil {
			res.Attempts = attempt
			return res, nil
		}
		lastErr = err
		if opened || !IsUnavailable(err) || ctx.Err() != nil || attempt == opts.Attempts {
			break
		}
		if err := c.sleep(ctx, delay); err != nil {
			break
		}
		delay *= 2
	}
	return nil, fmt.Errorf("openshell: exec %q in %q: %w", argv[0], sandbox, lastErr)
}

// execOnce runs one attempt and reports whether its stream opened, after
// which the command may be running and a retry is unsafe.
func (c *client) execOnce(parent context.Context, sandbox string, argv []string, opts ExecOptions) (*ExecResult, bool, error) {
	wait := opts.Timeout + c.opts.ExecGrace
	ctx, cancel := context.WithTimeout(parent, wait)
	defer cancel()
	start := time.Now()
	stream, err := c.sdk.Exec().Stream(ctx, c.opts.Workspace, sandbox, argv, v1.ExecOptions{
		Env:          opts.Env,
		WorkDir:      opts.WorkDir,
		NoLoginShell: !opts.LoginShell,
	})
	if err != nil {
		return nil, false, attemptError(parent, ctx, err, wait)
	}
	defer stream.Close()

	res := &ExecResult{}
	for {
		chunk, err := stream.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return nil, true, attemptError(parent, ctx, err, wait)
		}
		if chunk == nil || len(chunk.Data) == 0 {
			continue
		}
		switch chunk.Stream {
		case v1.StreamStderr:
			res.Stderr = appendCapped(res.Stderr, chunk.Data, opts.MaxOutputBytes, &res.Truncated)
			tee(opts.Stderr, chunk.Data)
		default:
			res.Stdout = appendCapped(res.Stdout, chunk.Data, opts.MaxOutputBytes, &res.Truncated)
			tee(opts.Stdout, chunk.Data)
		}
	}
	code, err := stream.ExitCode()
	if err != nil {
		return nil, true, attemptError(parent, ctx, err, wait)
	}
	switch {
	case (code == exitTimedOut || code == exitKilled) && time.Since(start) >= opts.Timeout:
		return nil, true, fmt.Errorf("%w after %s: the sandbox stopped the command (exit status %d)", ErrExecTimeout, opts.Timeout, code)
	case code == exitNotFound && missingTimeoutCommand(res.Stderr):
		return nil, true, fmt.Errorf("%w: %s", ErrNoSandboxTimeout, bytes.TrimSpace(res.Stderr))
	}
	res.ExitCode = code
	return res, true, nil
}

// missingTimeoutCommand recognizes the shell's complaint (bash, dash or
// busybox) that timeout(1) itself is missing. A missing user command is
// reported by timeout(1) as "failed to run command" instead.
func missingTimeoutCommand(stderr []byte) bool {
	return bytes.Contains(stderr, []byte("timeout: command not found")) || bytes.Contains(stderr, []byte("timeout: not found"))
}

// attemptError distinguishes the attempt's own deadline (the gateway never
// reported the command's end) from the caller's cancellation.
func attemptError(parent, attempt context.Context, err error, wait time.Duration) error {
	if parent.Err() == nil && errors.Is(attempt.Err(), context.DeadlineExceeded) {
		return fmt.Errorf("%w: no exit status from the gateway within %s: %w", ErrExecTimeout, wait, err)
	}
	return err
}

func appendCapped(dst, data []byte, limit int, truncated *bool) []byte {
	room := limit - len(dst)
	if room <= 0 {
		*truncated = true
		return dst
	}
	if len(data) > room {
		*truncated = true
		data = data[:room]
	}
	return append(dst, data...)
}

func tee(w io.Writer, data []byte) {
	if w != nil {
		_, _ = w.Write(data)
	}
}

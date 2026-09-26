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
	"time"

	v1 "github.com/NVIDIA/OpenShell/sdk/go/openshell/v1"
)

// Exec defaults. OpenShell 0.1.1 occasionally leaves the first exec after
// sandbox creation hanging without output; a bounded attempt plus a retry
// recovers it.
const (
	DefaultExecTimeout    = 60 * time.Second
	DefaultExecAttempts   = 3
	DefaultExecRetryDelay = time.Second
	// DefaultExecMaxOutput caps each of stdout and stderr in ExecResult.
	DefaultExecMaxOutput = 16 << 20
)

// ErrExecTimeout reports an exec attempt that exceeded its timeout.
var ErrExecTimeout = errors.New("openshell: exec timed out")

// ExecOptions tune Client.Exec.
type ExecOptions struct {
	// Env sets non-secret variables for the command. Secrets belong in
	// providers, never here.
	Env     map[string]string
	WorkDir string
	// LoginShell sources the sandbox user's profile first. The default
	// (false) gives automation a predictable environment.
	LoginShell bool
	// Timeout bounds each attempt (default DefaultExecTimeout).
	Timeout time.Duration
	// Attempts is the total number of tries (default DefaultExecAttempts;
	// 1 disables retries). Only attempts that fail before any output was
	// received are retried: a transport error, or a timeout with no bytes
	// seen. Commands that are not safe to run twice should set 1.
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

func (c *client) Exec(ctx context.Context, sandbox string, argv []string, opts ExecOptions) (*ExecResult, error) {
	if err := checkSandboxName(sandbox); err != nil {
		return nil, err
	}
	if len(argv) == 0 || argv[0] == "" {
		return nil, errors.New("openshell: exec needs a command")
	}
	opts = opts.withDefaults()
	delay := opts.RetryDelay
	var lastErr error
	for attempt := 1; attempt <= opts.Attempts; attempt++ {
		res, sawOutput, err := c.execOnce(ctx, sandbox, argv, opts)
		if err == nil {
			res.Attempts = attempt
			return res, nil
		}
		lastErr = err
		if ctx.Err() != nil || sawOutput || !retryableExec(err) || attempt == opts.Attempts {
			break
		}
		if err := c.sleep(ctx, delay); err != nil {
			break
		}
		delay *= 2
	}
	return nil, fmt.Errorf("openshell: exec %q in %q: %w", argv[0], sandbox, lastErr)
}

func retryableExec(err error) bool {
	return errors.Is(err, ErrExecTimeout) || IsUnavailable(err)
}

// execOnce runs one attempt and reports whether any output arrived, which
// makes a retry unsafe.
func (c *client) execOnce(parent context.Context, sandbox string, argv []string, opts ExecOptions) (*ExecResult, bool, error) {
	ctx, cancel := context.WithTimeout(parent, opts.Timeout)
	defer cancel()
	stream, err := c.sdk.Exec().Stream(ctx, c.opts.Workspace, sandbox, argv, v1.ExecOptions{
		Env:          opts.Env,
		WorkDir:      opts.WorkDir,
		NoLoginShell: !opts.LoginShell,
	})
	if err != nil {
		return nil, false, attemptError(parent, ctx, err, opts.Timeout)
	}
	defer stream.Close()

	res := &ExecResult{}
	saw := false
	for {
		chunk, err := stream.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return nil, saw, attemptError(parent, ctx, err, opts.Timeout)
		}
		if chunk == nil || len(chunk.Data) == 0 {
			continue
		}
		saw = true
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
		return nil, saw, attemptError(parent, ctx, err, opts.Timeout)
	}
	res.ExitCode = code
	return res, saw, nil
}

// attemptError distinguishes an attempt timeout (retryable) from the
// caller's own cancellation (not).
func attemptError(parent, attempt context.Context, err error, timeout time.Duration) error {
	if parent.Err() == nil && errors.Is(attempt.Err(), context.DeadlineExceeded) {
		return fmt.Errorf("%w after %s: %w", ErrExecTimeout, timeout, err)
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

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

package workspace

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/openshell"
)

// ExecRequest is one non-interactive command inside a sandbox. Stdin is
// always empty: OpenShell's exec hangs on an open non-TTY stdin.
type ExecRequest struct {
	Argv    []string
	Workdir string
	// Env holds non-secret variables only (they are visible in process
	// listings); credentials go through OpenShell providers.
	Env map[string]string
	// Timeout bounds the command; zero uses the implementation's default.
	// The sandbox stops the command when it expires, as
	// openshell.Client.Exec does (coreutils timeout(1)), and the call then
	// fails with an error wrapping openshell.ErrExecTimeout.
	Timeout time.Duration
	// Idempotent marks a command that is safe to run twice. Only such a
	// command is ever tried again, and only after an attempt that printed
	// nothing at all (the OpenShell 0.1.1 exec that hangs or fails
	// silently right after a sandbox starts). Any other command runs at
	// most once: OpenShell does not stop a command when its client gives
	// up, so a second run could overlap the first.
	Idempotent bool
	// Stdout, when set, receives the command's standard output as it
	// arrives, and ExecResult.Stdout stays empty. The first write error
	// stops the command and is returned, so a writer can bound what it
	// accepts.
	Stdout io.Writer
}

// ExecResult is a finished command. A non-zero ExitCode is not an error.
type ExecResult struct {
	ExitCode int
	Stdout   []byte
	Stderr   []byte
}

// Execer runs commands inside a sandbox.
type Execer interface {
	Exec(ctx context.Context, sandbox string, req ExecRequest) (*ExecResult, error)
}

// Uploader copies host files into a sandbox. localPath (a file or a
// directory) lands at remoteDir/<basename(localPath)>, keeping modes and
// symlinks; remoteDir is created when missing. Nothing is filtered by
// .gitignore.
type Uploader interface {
	Upload(ctx context.Context, sandbox, localPath, remoteDir string) error
}

// Downloader copies a sandbox file or directory remotePath into the
// existing local directory localDir, as localDir/<basename(remotePath)>.
type Downloader interface {
	Download(ctx context.Context, sandbox, remotePath, localDir string) error
}

// Transport is everything copy mode needs from OpenShell.
type Transport interface {
	Execer
	Uploader
	Downloader
}

// CLI implements Transport with the upstream `openshell` binary, through
// the invocations openshell.CLI builds. Every call names a validated
// gateway and workspace explicitly, puts "--" before its positionals,
// reads stdin from /dev/null, and runs without the OPENSHELL_ variables
// that could point the binary at another gateway (openshell.Environ): a
// copy of the project is uploaded to, and results are read from, only the
// gateway the caller chose.
type CLI struct {
	// Binary is the openshell executable (openshell.DefaultBinary on PATH
	// by default).
	Binary string
	// Gateway is the registered gateway name (-g), normally the one
	// openshell.Discover validated. Required: without it the binary would
	// use whatever gateway the environment or `gateway select` made
	// active.
	Gateway string
	// Workspace is the OpenShell workspace (--workspace), by default
	// openshell.DefaultWorkspace.
	Workspace string
	// TransferTimeout bounds each upload or download (default 10 min).
	TransferTimeout time.Duration
	// ExecTimeout is used when a request sets none (default 2 min).
	ExecTimeout time.Duration
	// Attempts bounds the tries of an Idempotent exec (default
	// openshell.DefaultIdempotentExecAttempts); see ExecRequest.Idempotent.
	Attempts int

	// run is the process seam used by tests; attemptLimit, when set,
	// replaces the local deadline of an exec attempt.
	run          func(ctx context.Context, argv []string, stdout io.Writer) (stderr []byte, code int, err error)
	attemptLimit time.Duration
}

const (
	defaultTransferTimeout = 10 * time.Minute
	defaultExecTimeout     = 2 * time.Minute
	maxExecOutput          = 16 << 20
	// cliExecSlack is how long after the sandbox's timeout(1) has sent
	// SIGKILL the binary's own --timeout fires. That timeout only makes
	// OpenShell 0.1.1 report status 124 and leaves the command running, so
	// it must never beat timeout(1), which actually stops it.
	cliExecSlack = 5 * time.Second
)

// upstream is the openshell package's argv builder for c. It refuses an
// empty or invalid gateway, workspace or sandbox name.
func (c *CLI) upstream() openshell.CLI {
	return openshell.CLI{Binary: c.Binary, Gateway: c.Gateway, Workspace: c.Workspace}
}

// UploadArgv is `openshell sandbox upload` of localPath into remoteDir,
// without .gitignore filtering: a staged copy must arrive whole.
func (c *CLI) UploadArgv(sandbox, localPath, remoteDir string) ([]string, error) {
	inv, err := c.upstream().Upload(sandbox, localPath, remoteDir, false)
	if err != nil {
		return nil, fmt.Errorf("workspace: %w", err)
	}
	return inv.Argv, nil
}

// DownloadArgv is `openshell sandbox download` of remotePath into localDir.
func (c *CLI) DownloadArgv(sandbox, remotePath, localDir string) ([]string, error) {
	inv, err := c.upstream().Download(sandbox, remotePath, localDir)
	if err != nil {
		return nil, fmt.Errorf("workspace: %w", err)
	}
	return inv.Argv, nil
}

// ExecArgv is `openshell sandbox exec` without a TTY or login shell. The
// command is wrapped in openshell.SandboxTimeoutArgv, so the sandbox stops
// it at the request's timeout.
func (c *CLI) ExecArgv(sandbox string, req ExecRequest) ([]string, error) {
	inv, err := c.execInvocation(sandbox, req)
	if err != nil {
		return nil, err
	}
	return inv.Argv, nil
}

// execInvocation prepares one exec. Its Timeout is the local deadline of
// an attempt: the binary's --timeout plus openshell's grace.
func (c *CLI) execInvocation(sandbox string, req ExecRequest) (openshell.Invocation, error) {
	if len(req.Argv) == 0 || req.Argv[0] == "" {
		return openshell.Invocation{}, errors.New("workspace: exec needs a command")
	}
	timeout := c.execTimeout(req)
	inv, err := c.upstream().Exec(sandbox, openshell.SandboxTimeoutArgv(req.Argv, timeout), openshell.CLIExecOptions{
		WorkDir: req.Workdir, Timeout: timeout + openshell.ExecKillAfter + cliExecSlack, Env: req.Env,
	})
	if err != nil {
		return openshell.Invocation{}, fmt.Errorf("workspace: %w", err)
	}
	return inv, nil
}

func (c *CLI) execTimeout(req ExecRequest) time.Duration {
	if req.Timeout > 0 {
		return req.Timeout
	}
	if c.ExecTimeout > 0 {
		return c.ExecTimeout
	}
	return defaultExecTimeout
}

func (c *CLI) transferTimeout() time.Duration {
	if c.TransferTimeout > 0 {
		return c.TransferTimeout
	}
	return defaultTransferTimeout
}

// Upload implements Uploader.
func (c *CLI) Upload(ctx context.Context, sandbox, localPath, remoteDir string) error {
	argv, err := c.UploadArgv(sandbox, localPath, remoteDir)
	if err != nil {
		return err
	}
	return c.transfer(ctx, "upload", argv)
}

// Download implements Downloader.
func (c *CLI) Download(ctx context.Context, sandbox, remotePath, localDir string) error {
	argv, err := c.DownloadArgv(sandbox, remotePath, localDir)
	if err != nil {
		return err
	}
	return c.transfer(ctx, "download", argv)
}

func (c *CLI) transfer(ctx context.Context, what string, argv []string) error {
	ctx, cancel := context.WithTimeout(ctx, c.transferTimeout())
	defer cancel()
	stderr, code, err := c.exec(ctx, argv, io.Discard)
	if err != nil {
		return fmt.Errorf("workspace: openshell %s: %w", what, err)
	}
	if code != 0 {
		return fmt.Errorf("workspace: openshell %s failed (exit %d): %s", what, code, lastLines(stderr, 5))
	}
	return nil
}

// Exec implements Execer with the semantics of openshell.Client.Exec: the
// sandbox stops the command at its timeout (the call then fails with an
// error wrapping openshell.ErrExecTimeout), and a command runs at most
// once unless the request is Idempotent. An Idempotent command is tried
// again (up to Attempts) only after an attempt that printed nothing, and
// when every attempt completed silently the last exit status is returned:
// "test -e" failing quietly is an answer.
func (c *CLI) Exec(ctx context.Context, sandbox string, req ExecRequest) (*ExecResult, error) {
	inv, err := c.execInvocation(sandbox, req)
	if err != nil {
		return nil, err
	}
	attempts := 1
	if req.Idempotent {
		attempts = c.Attempts
		if attempts <= 0 {
			attempts = openshell.DefaultIdempotentExecAttempts
		}
	}
	for i := 1; ; i++ {
		res, silent, err := c.execOnce(ctx, sandbox, inv, c.execTimeout(req), req.Stdout)
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		if !silent || !req.Idempotent || i >= attempts {
			return res, err
		}
	}
}

// execOnce runs one attempt. silent reports an attempt that printed
// nothing and was not stopped by the sandbox's timeout(1): it either
// exited with a status or never answered by the local deadline, by which
// time the sandbox has stopped the command if it ever started.
func (c *CLI) execOnce(ctx context.Context, sandbox string, inv openshell.Invocation, timeout time.Duration, stream io.Writer) (*ExecResult, bool, error) {
	limit := inv.Timeout
	if c.attemptLimit > 0 {
		limit = c.attemptLimit
	}
	attemptCtx, cancel := context.WithTimeout(ctx, limit)
	defer cancel()
	captured := &limitedBuffer{limit: maxExecOutput}
	out := &streamWriter{w: captured, cancel: cancel}
	if stream != nil {
		out.w = stream
	}
	start := time.Now()
	stderr, code, err := c.exec(attemptCtx, inv.Argv, out)
	elapsed := time.Since(start)
	if out.err != nil {
		return nil, false, out.err
	}
	silent := out.n == 0 && len(stderr) == 0
	if err != nil {
		if ctx.Err() == nil && errors.Is(attemptCtx.Err(), context.DeadlineExceeded) {
			return nil, silent, fmt.Errorf("workspace: exec in sandbox %s: %w: openshell reported no exit status within %s", sandbox, openshell.ErrExecTimeout, limit)
		}
		// The binary did not run at all: retrying will not help.
		return nil, false, fmt.Errorf("workspace: openshell exec: %w", err)
	}
	if err := openshell.SandboxExitError(code, stderr, elapsed, timeout); err != nil {
		return nil, false, fmt.Errorf("workspace: exec in sandbox %s: %w", sandbox, err)
	}
	res := &ExecResult{ExitCode: code, Stderr: stderr}
	if stream == nil {
		res.Stdout = captured.Bytes()
	}
	return res, silent && code != 0, nil
}

func (c *CLI) exec(ctx context.Context, argv []string, stdout io.Writer) ([]byte, int, error) {
	if c.run != nil {
		return c.run(ctx, argv, stdout)
	}
	return runProcess(ctx, argv, stdout)
}

// streamWriter passes a command's stdout on to w and counts it. The first
// write error stops the command (cancel) and is kept for the caller.
type streamWriter struct {
	w      io.Writer
	cancel context.CancelFunc
	n      int64
	err    error
}

func (s *streamWriter) Write(p []byte) (int, error) {
	if s.err != nil {
		return 0, s.err
	}
	n, err := s.w.Write(p)
	s.n += int64(n)
	if err == nil && n < len(p) {
		err = io.ErrShortWrite
	}
	if err != nil {
		s.err = err
		s.cancel()
	}
	return n, err
}

// runProcess runs argv as openshell.Invocation.Command prepares it: stdin
// from the null device, a bounded wait for inherited pipes, and the
// environment without the gateway-selecting OPENSHELL_ variables. Output
// is bounded.
func runProcess(ctx context.Context, argv []string, stdout io.Writer) ([]byte, int, error) {
	cmd, cancel, err := openshell.Invocation{Argv: argv}.Command(ctx)
	if err != nil {
		return nil, -1, err
	}
	defer cancel()
	stderr := limitedBuffer{limit: 1 << 20}
	cmd.Stdout = stdout
	cmd.Stderr = &stderr
	err = cmd.Run()
	var exitErr *exec.ExitError
	if errors.As(err, &exitErr) && ctx.Err() == nil {
		if ws, ok := exitErr.Sys().(syscall.WaitStatus); ok && ws.Signaled() && ws.Signal() == syscall.SIGINT {
			// A Ctrl-C reached the command (the terminal signals the whole
			// foreground process group): the user interrupted the step,
			// which read as its failure with "exit -1" and no cause
			// (GAP-0368).
			return stderr.Bytes(), -1, fmt.Errorf("%s: %w", filepath.Base(argv[0]), openshell.ErrInterrupted)
		}
		return stderr.Bytes(), exitErr.ExitCode(), nil
	}
	if err != nil {
		return stderr.Bytes(), -1, err
	}
	return stderr.Bytes(), 0, nil
}

// limitedBuffer keeps the first limit bytes and discards the rest.
type limitedBuffer struct {
	bytes.Buffer
	limit int
}

func (b *limitedBuffer) Write(p []byte) (int, error) {
	if room := b.limit - b.Len(); room > 0 {
		if len(p) > room {
			b.Buffer.Write(p[:room])
		} else {
			b.Buffer.Write(p)
		}
	}
	return len(p), nil
}

var _ io.Writer = (*limitedBuffer)(nil)

func lastLines(b []byte, n int) string {
	lines := strings.Split(strings.TrimSpace(string(b)), "\n")
	if len(lines) > n {
		lines = lines[len(lines)-n:]
	}
	return strings.Join(lines, " | ")
}

// shellQuote quotes s for a POSIX shell.
func shellQuote(s string) string {
	return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'"
}

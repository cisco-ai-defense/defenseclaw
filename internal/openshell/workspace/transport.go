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
	"os"
	"os/exec"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/processutil"
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
	Timeout time.Duration
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

// CLI implements Transport with the upstream `openshell` binary. Every
// call names the gateway and workspace explicitly and reads stdin from
// /dev/null.
type CLI struct {
	// Binary is the openshell executable ("openshell" on PATH by default).
	Binary string
	// Gateway is the registered gateway name (-g); "" uses the CLI's
	// active gateway.
	Gateway string
	// Workspace is the OpenShell workspace (--workspace); "" is the CLI
	// default.
	Workspace string
	// TransferTimeout bounds each upload or download (default 10 min).
	TransferTimeout time.Duration
	// ExecTimeout is used when a request sets none (default 2 min).
	ExecTimeout time.Duration
	// Attempts is how often an exec that produced no output at all (a
	// known OpenShell 0.1.1 flake right after create) is tried (default 2).
	Attempts int

	// run is the process seam used by tests.
	run func(ctx context.Context, argv []string) (stdout, stderr []byte, code int, err error)
}

const (
	defaultTransferTimeout = 10 * time.Minute
	defaultExecTimeout     = 2 * time.Minute
	maxExecOutput          = 16 << 20
)

var envKeyRE = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*$`)

func (c *CLI) binary() string {
	if c.Binary != "" {
		return c.Binary
	}
	return "openshell"
}

func (c *CLI) scope() []string {
	var out []string
	if c.Gateway != "" {
		out = append(out, "-g", c.Gateway)
	}
	if c.Workspace != "" {
		out = append(out, "--workspace", c.Workspace)
	}
	return out
}

// UploadArgv is `openshell sandbox upload` for localPath into remoteDir.
func (c *CLI) UploadArgv(sandbox, localPath, remoteDir string) []string {
	argv := []string{c.binary(), "sandbox", "upload"}
	argv = append(argv, c.scope()...)
	return append(argv, "--no-git-ignore", sandbox, localPath, remoteDir)
}

// DownloadArgv is `openshell sandbox download` for remotePath into localDir.
func (c *CLI) DownloadArgv(sandbox, remotePath, localDir string) []string {
	argv := []string{c.binary(), "sandbox", "download"}
	argv = append(argv, c.scope()...)
	return append(argv, sandbox, remotePath, localDir)
}

// ExecArgv is `openshell sandbox exec` without a TTY or login shell.
func (c *CLI) ExecArgv(sandbox string, req ExecRequest) ([]string, error) {
	if len(req.Argv) == 0 {
		return nil, errors.New("workspace: exec needs a command")
	}
	argv := []string{c.binary(), "sandbox", "exec"}
	argv = append(argv, c.scope()...)
	argv = append(argv, "-n", sandbox, "--no-tty", "--no-login-shell")
	if req.Workdir != "" {
		argv = append(argv, "--workdir", req.Workdir)
	}
	if t := c.execTimeout(req); t > 0 {
		argv = append(argv, "--timeout", strconv.Itoa(int((t+time.Second-1)/time.Second)))
	}
	keys := make([]string, 0, len(req.Env))
	for k := range req.Env {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		v := req.Env[k]
		if !envKeyRE.MatchString(k) || strings.ContainsAny(v, "\x00\n") {
			return nil, fmt.Errorf("workspace: invalid exec environment entry %q", k)
		}
		argv = append(argv, "--env", k+"="+v)
	}
	argv = append(argv, "--")
	return append(argv, req.Argv...), nil
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
	return c.transfer(ctx, "upload", c.UploadArgv(sandbox, localPath, remoteDir))
}

// Download implements Downloader.
func (c *CLI) Download(ctx context.Context, sandbox, remotePath, localDir string) error {
	return c.transfer(ctx, "download", c.DownloadArgv(sandbox, remotePath, localDir))
}

func (c *CLI) transfer(ctx context.Context, what string, argv []string) error {
	ctx, cancel := context.WithTimeout(ctx, c.transferTimeout())
	defer cancel()
	_, stderr, code, err := c.exec(ctx, argv)
	if err != nil {
		return fmt.Errorf("workspace: openshell %s: %w", what, err)
	}
	if code != 0 {
		return fmt.Errorf("workspace: openshell %s failed (exit %d): %s", what, code, lastLines(stderr, 5))
	}
	return nil
}

// Exec implements Execer. A run that hangs, or fails without printing
// anything, is retried (the OpenShell 0.1.1 post-create flake), so commands
// must be idempotent. When every attempt completed silently the last exit
// code is returned: "test -e" failing quietly is an answer.
func (c *CLI) Exec(ctx context.Context, sandbox string, req ExecRequest) (*ExecResult, error) {
	argv, err := c.ExecArgv(sandbox, req)
	if err != nil {
		return nil, err
	}
	attempts := c.Attempts
	if attempts <= 0 {
		attempts = 2
	}
	// The CLI enforces the remote timeout; the local one is a little longer
	// so a wedged client cannot hang the caller.
	limit := c.execTimeout(req) + 15*time.Second
	var lastErr error
	var last *ExecResult
	for i := 0; i < attempts; i++ {
		attemptCtx, cancel := context.WithTimeout(ctx, limit)
		stdout, stderr, code, err := c.exec(attemptCtx, argv)
		timedOut := errors.Is(attemptCtx.Err(), context.DeadlineExceeded)
		cancel()
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		if err == nil {
			last = &ExecResult{ExitCode: code, Stdout: stdout, Stderr: stderr}
			if code == 0 || len(stdout) > 0 || len(stderr) > 0 {
				return last, nil
			}
			continue
		}
		if timedOut {
			lastErr = fmt.Errorf("workspace: openshell exec timed out after %s", limit)
		} else {
			lastErr = fmt.Errorf("workspace: openshell exec: %w", err)
		}
	}
	if last != nil {
		return last, nil
	}
	return nil, lastErr
}

func (c *CLI) exec(ctx context.Context, argv []string) ([]byte, []byte, int, error) {
	if c.run != nil {
		return c.run(ctx, argv)
	}
	return runProcess(ctx, argv)
}

// runProcess runs argv with stdin from /dev/null and bounded output.
func runProcess(ctx context.Context, argv []string) ([]byte, []byte, int, error) {
	devnull, err := os.Open(os.DevNull)
	if err != nil {
		return nil, nil, -1, err
	}
	defer devnull.Close()
	cmd := processutil.CommandContext(ctx, argv[0], argv[1:]...)
	cmd.Stdin = devnull
	var stdout, stderr limitedBuffer
	stdout.limit, stderr.limit = maxExecOutput, 1<<20
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	cmd.WaitDelay = 5 * time.Second
	err = cmd.Run()
	var exitErr *exec.ExitError
	if errors.As(err, &exitErr) && ctx.Err() == nil {
		return stdout.Bytes(), stderr.Bytes(), exitErr.ExitCode(), nil
	}
	if err != nil {
		return stdout.Bytes(), stderr.Bytes(), -1, err
	}
	return stdout.Bytes(), stderr.Bytes(), 0, nil
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

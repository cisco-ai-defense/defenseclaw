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
	"math"
	"net"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/processutil"
)

// DefaultBinary is the upstream CLI's name on PATH.
const DefaultBinary = "openshell"

// CLI builds argv for the upstream openshell binary, which DefenseClaw
// uses only where the SDK has no transport: terminal attach, file
// transfer and port forwarding. Every invocation names the gateway and
// workspace explicitly, so an operator's OPENSHELL_GATEWAY or last-used
// sandbox can never redirect it.
type CLI struct {
	// Binary defaults to DefaultBinary.
	Binary string
	// Gateway is the registration name passed as -g. Required.
	Gateway string
	// Workspace defaults to DefaultWorkspace.
	Workspace string
}

// Invocation is a prepared openshell command.
type Invocation struct {
	// Argv starts with the binary.
	Argv []string
	// Interactive commands inherit the caller's terminal. All others read
	// stdin from /dev/null: 0.1.1 `sandbox exec` and `upload` hang on an
	// open non-terminal stdin.
	Interactive bool
	// Timeout bounds non-interactive commands (0: none).
	Timeout time.Duration
}

// CLIExecOptions tune `sandbox exec`.
type CLIExecOptions struct {
	// TTY allocates a pseudo-terminal and makes the invocation
	// interactive. Otherwise --no-tty is passed.
	TTY     bool
	WorkDir string
	// Timeout is passed as --timeout (whole seconds, rounded up) and
	// bounds the local process a little longer.
	Timeout time.Duration
	// Env sets non-secret variables (--env K=V).
	Env map[string]string
	// LoginShell sources profile files first; the default passes
	// --no-login-shell for predictable automation.
	LoginShell bool
}

// Default timeouts for transfers and forwards.
const (
	DefaultTransferTimeout = 30 * time.Minute
	DefaultForwardTimeout  = time.Minute
	// cliGrace is added to a command's own --timeout before the local
	// process is killed.
	cliGrace = 10 * time.Second
)

var envKeyPattern = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*$`)

func (c CLI) base(verbs ...string) ([]string, error) {
	if !ValidGatewayName(c.Gateway) {
		return nil, fmt.Errorf("openshell: CLI needs a valid gateway name, got %q", c.Gateway)
	}
	bin := c.Binary
	if bin == "" {
		bin = DefaultBinary
	}
	ws := c.Workspace
	if ws == "" {
		ws = DefaultWorkspace
	}
	if !ValidGatewayName(ws) {
		return nil, fmt.Errorf("openshell: invalid workspace %q", ws)
	}
	argv := append([]string{bin}, verbs...)
	return append(argv, "-g", c.Gateway, "--workspace", ws), nil
}

// Version is `openshell --version`.
func (c CLI) Version() Invocation {
	bin := c.Binary
	if bin == "" {
		bin = DefaultBinary
	}
	return Invocation{Argv: []string{bin, "--version"}, Timeout: 30 * time.Second}
}

// Exec runs command in a sandbox through the CLI. Use Client.Exec for
// non-interactive automation; this is for --tty sessions and for parity
// with what the operator would type.
func (c CLI) Exec(sandbox string, command []string, o CLIExecOptions) (Invocation, error) {
	if err := checkSandboxName(sandbox); err != nil {
		return Invocation{}, err
	}
	if len(command) == 0 || command[0] == "" {
		return Invocation{}, errors.New("openshell: exec needs a command")
	}
	argv, err := c.base("sandbox", "exec")
	if err != nil {
		return Invocation{}, err
	}
	inv := Invocation{Interactive: o.TTY}
	if !o.TTY {
		argv = append(argv, "--color", "never")
	}
	argv = append(argv, "--name", sandbox)
	if o.WorkDir != "" {
		if !path.IsAbs(o.WorkDir) {
			return Invocation{}, fmt.Errorf("openshell: exec workdir must be absolute, got %q", o.WorkDir)
		}
		argv = append(argv, "--workdir", path.Clean(o.WorkDir))
	}
	if o.Timeout > 0 {
		secs := int(math.Ceil(o.Timeout.Seconds()))
		argv = append(argv, "--timeout", strconv.Itoa(secs))
		if !o.TTY {
			inv.Timeout = time.Duration(secs)*time.Second + cliGrace
		}
	}
	if o.TTY {
		argv = append(argv, "--tty")
	} else {
		argv = append(argv, "--no-tty")
	}
	if !o.LoginShell {
		argv = append(argv, "--no-login-shell")
	}
	keys := make([]string, 0, len(o.Env))
	for k, v := range o.Env {
		if !envKeyPattern.MatchString(k) {
			return Invocation{}, fmt.Errorf("openshell: invalid env name %q", k)
		}
		if strings.ContainsAny(v, "\x00\n\r") {
			return Invocation{}, fmt.Errorf("openshell: env %s contains a control character", k)
		}
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		argv = append(argv, "--env", k+"="+o.Env[k])
	}
	inv.Argv = append(append(argv, "--"), command...)
	return inv, nil
}

// Connect attaches the caller's terminal to the sandbox's main session.
func (c CLI) Connect(sandbox string) (Invocation, error) {
	if err := checkSandboxName(sandbox); err != nil {
		return Invocation{}, err
	}
	argv, err := c.base("sandbox", "connect")
	if err != nil {
		return Invocation{}, err
	}
	return Invocation{Argv: append(argv, "--", sandbox), Interactive: true}, nil
}

// Upload copies a local file or directory into the sandbox. gitIgnore
// keeps the CLI's .gitignore filtering; pass false for a staged tree that
// must arrive whole.
func (c CLI) Upload(sandbox, localPath, dest string, gitIgnore bool) (Invocation, error) {
	if err := checkSandboxName(sandbox); err != nil {
		return Invocation{}, err
	}
	local, err := absLocal(localPath)
	if err != nil {
		return Invocation{}, err
	}
	remote, err := absRemote(dest)
	if err != nil {
		return Invocation{}, err
	}
	argv, err := c.base("sandbox", "upload")
	if err != nil {
		return Invocation{}, err
	}
	argv = append(argv, "--color", "never")
	if !gitIgnore {
		argv = append(argv, "--no-git-ignore")
	}
	return Invocation{Argv: append(argv, "--", sandbox, local, remote), Timeout: DefaultTransferTimeout}, nil
}

// Download copies a sandbox path to a local destination. OpenShell 0.1.1
// only downloads from inside the sandbox workspace (the container's
// working directory, /sandbox by default); anything else fails with
// "outside the sandbox workspace".
func (c CLI) Download(sandbox, remotePath, localDest string) (Invocation, error) {
	if err := checkSandboxName(sandbox); err != nil {
		return Invocation{}, err
	}
	remote, err := absRemote(remotePath)
	if err != nil {
		return Invocation{}, err
	}
	local, err := absLocal(localDest)
	if err != nil {
		return Invocation{}, err
	}
	argv, err := c.base("sandbox", "download")
	if err != nil {
		return Invocation{}, err
	}
	argv = append(argv, "--color", "never")
	return Invocation{Argv: append(argv, "--", sandbox, remote, local), Timeout: DefaultTransferTimeout}, nil
}

// ForwardStart forwards a host loopback port to the same port in the
// sandbox, in the background. bind must be a loopback address (empty means
// 127.0.0.1): DefenseClaw never exposes a sandbox port beyond the host.
func (c CLI) ForwardStart(sandbox string, port int, bind string) (Invocation, error) {
	if err := checkSandboxName(sandbox); err != nil {
		return Invocation{}, err
	}
	if port < 1 || port > 65535 {
		return Invocation{}, fmt.Errorf("openshell: invalid port %d", port)
	}
	if bind == "" {
		bind = "127.0.0.1"
	}
	ip := net.ParseIP(bind)
	if ip == nil || !ip.IsLoopback() {
		return Invocation{}, fmt.Errorf("openshell: forwards bind to loopback only, got %q", bind)
	}
	argv, err := c.base("forward", "start")
	if err != nil {
		return Invocation{}, err
	}
	spec := net.JoinHostPort(ip.String(), strconv.Itoa(port))
	return Invocation{Argv: append(argv, "--color", "never", "--background", "--", spec, sandbox), Timeout: DefaultForwardTimeout}, nil
}

// ForwardStop stops a background forward.
func (c CLI) ForwardStop(sandbox string, port int) (Invocation, error) {
	if err := checkSandboxName(sandbox); err != nil {
		return Invocation{}, err
	}
	if port < 1 || port > 65535 {
		return Invocation{}, fmt.Errorf("openshell: invalid port %d", port)
	}
	argv, err := c.base("forward", "stop")
	if err != nil {
		return Invocation{}, err
	}
	return Invocation{Argv: append(argv, "--color", "never", "--", strconv.Itoa(port), sandbox), Timeout: DefaultForwardTimeout}, nil
}

func absLocal(p string) (string, error) {
	if p == "" {
		return "", errors.New("openshell: empty local path")
	}
	abs, err := filepath.Abs(p)
	if err != nil {
		return "", fmt.Errorf("openshell: resolve %q: %w", p, err)
	}
	return abs, nil
}

func absRemote(p string) (string, error) {
	if !path.IsAbs(p) || strings.ContainsAny(p, "\x00\n\r") {
		return "", fmt.Errorf("openshell: sandbox path must be absolute, got %q", p)
	}
	return path.Clean(p), nil
}

// scrubbedEnv drops the variables that would let the environment override
// the explicit gateway, workspace or TLS verification of an invocation.
var scrubbedEnv = []string{"OPENSHELL_GATEWAY", "OPENSHELL_GATEWAY_ENDPOINT", "OPENSHELL_GATEWAY_INSECURE", "OPENSHELL_WORKSPACE"}

// Environ returns env without the gateway-selecting OPENSHELL_ variables.
func Environ(env []string) []string {
	out := make([]string, 0, len(env))
	for _, kv := range env {
		name, _, _ := strings.Cut(kv, "=")
		drop := false
		for _, s := range scrubbedEnv {
			if name == s {
				drop = true
				break
			}
		}
		if !drop {
			out = append(out, kv)
		}
	}
	return out
}

// Command prepares the invocation. Non-interactive commands get stdin from
// /dev/null, a timeout and a bounded wait for inherited pipes; the caller
// attaches Stdout/Stderr. Interactive commands inherit the terminal. The
// returned cancel must be called once the command is done.
func (inv Invocation) Command(ctx context.Context) (*exec.Cmd, context.CancelFunc, error) {
	if len(inv.Argv) == 0 {
		return nil, nil, errors.New("openshell: empty invocation")
	}
	cancel := context.CancelFunc(func() {})
	if !inv.Interactive && inv.Timeout > 0 {
		ctx, cancel = context.WithTimeout(ctx, inv.Timeout)
	}
	var cmd *exec.Cmd
	if inv.Interactive {
		cmd = exec.CommandContext(ctx, inv.Argv[0], inv.Argv[1:]...)
		cmd.Stdin, cmd.Stdout, cmd.Stderr = os.Stdin, os.Stdout, os.Stderr
	} else {
		cmd = processutil.CommandContext(ctx, inv.Argv[0], inv.Argv[1:]...)
		cmd.Stdin = nil // os/exec connects nil stdin to the null device
		cmd.WaitDelay = 5 * time.Second
	}
	cmd.Env = Environ(os.Environ())
	return cmd, cancel, nil
}

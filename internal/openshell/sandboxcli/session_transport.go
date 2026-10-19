// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package sandboxcli

import (
	"context"
	"errors"
	"io"
	"slices"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/openshell"
)

// SessionExecRequest describes literal argv inside an already owned session.
// It contains no runtime selector, target override, shell text or authority.
// Prepare must snapshot the arguments rather than retain caller-owned slices.
type SessionExecRequest struct {
	Argv     []string
	WorkDir  string
	Timeout  time.Duration
	Terminal bool
}

// SessionStreams separates workload output from transport diagnostics. Nil
// workload streams mean inherited terminal for an interactive execution and
// discarded output otherwise. An adapter must refuse unsupported redirection.
type SessionStreams struct {
	Stdin          io.Reader
	Stdout, Stderr io.Writer
	Diagnostics    io.Writer
}

// SessionTransport is bound by its constructor to one owned session target.
// Prepare only validates/prepares command transport; it grants no policy,
// credential, runtime admission or launch authorization. Implementations must
// never render argv as shell text, change target or fall back to another runtime.
type SessionTransport interface {
	Prepare(SessionExecRequest) (SessionExecution, error)
}

// SessionExecution runs the prepared literal command. Each Run must retain
// the transport's owned target and honor context cancellation. Preparation is
// reusable for readiness retries, never a reusable authority/launch grant.
type SessionExecution interface {
	Run(context.Context, SessionStreams) (int, error)
}

var errMissingSessionTransport = errors.New("sandbox session has no bound execution transport")

type openShellSessionTransport struct {
	app     *App
	cli     openshell.CLI
	sandbox string
}

func (a *App) openShellSessionTransport(cli openshell.CLI, sandbox string) SessionTransport {
	return &openShellSessionTransport{app: a, cli: cli, sandbox: sandbox}
}

func (t *openShellSessionTransport) Prepare(request SessionExecRequest) (SessionExecution, error) {
	inv, err := t.cli.Exec(t.sandbox, slices.Clone(request.Argv), openshell.CLIExecOptions{
		TTY: request.Terminal, WorkDir: request.WorkDir, Timeout: request.Timeout,
	})
	if err != nil {
		return nil, err
	}
	return &openShellSessionExecution{app: t.app, invocation: inv}, nil
}

type openShellSessionExecution struct {
	app        *App
	invocation openshell.Invocation
}

func (e *openShellSessionExecution) Run(ctx context.Context, streams SessionStreams) (int, error) {
	inv := e.invocation
	inv.Argv = slices.Clone(inv.Argv)
	if inv.Interactive {
		if streams.Stdin != nil || streams.Stdout != nil || streams.Stderr != nil {
			return -1, errors.New("OpenShell session transport requires the inherited interactive terminal")
		}
		if e.app.Terminal == nil {
			return -1, errors.New("OpenShell session transport has no terminal runner")
		}
		inv.Stderr = streams.Diagnostics
		return e.app.Terminal.Run(ctx, inv)
	}
	if streams.Stdin != nil || streams.Diagnostics != nil {
		return -1, errors.New("OpenShell session transport does not support redirected stdin or separate streaming diagnostics")
	}
	if e.app.Streamer == nil {
		return -1, errors.New("OpenShell session transport has no stream runner")
	}
	out, errOut := streams.Stdout, streams.Stderr
	if out == nil {
		out = io.Discard
	}
	if errOut == nil {
		errOut = io.Discard
	}
	return e.app.Streamer.Stream(ctx, inv, out, errOut)
}

func (s *session) prepareExec(request SessionExecRequest) (SessionExecution, error) {
	if s.transport == nil {
		return nil, errMissingSessionTransport
	}
	request.Argv = slices.Clone(request.Argv)
	return s.transport.Prepare(request)
}

// Existing fixed Unix shell recipes belong to OpenShell's image contract.
// Another adapter needs its own qualified platform operations; it must not
// silently inherit these recipes or fall back to the OpenShell CLI.
func (s *session) prepareOpenShellRecipe(request SessionExecRequest) (SessionExecution, error) {
	if s.transport == nil {
		return nil, errMissingSessionTransport
	}
	legacy, ok := s.transport.(*openShellSessionTransport)
	if !ok || legacy == nil {
		return nil, errors.New("sandbox session transport does not support this OpenShell shell recipe")
	}
	return s.prepareExec(request)
}

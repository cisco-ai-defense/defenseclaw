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

package openshelltest

import (
	"context"
	"errors"
	"io"
	"maps"
	"slices"
	"time"

	v1 "github.com/NVIDIA/OpenShell/sdk/go/openshell/v1"
	"github.com/NVIDIA/OpenShell/sdk/go/openshell/v1/types"

	"github.com/defenseclaw/defenseclaw/internal/openshell"
)

// ExecCall is one command the fake was asked to run.
type ExecCall struct {
	Workspace string
	Sandbox   string
	// Command is the caller's argv. openshell.Client.Exec wraps it in
	// timeout(1); the fake strips that wrapper and reports its limit in
	// Timeout.
	Command []string
	// Timeout is the in-sandbox limit of the command (0: unwrapped).
	Timeout time.Duration
	// Argv is the argv as sent, wrapper included.
	Argv         []string
	Env          map[string]string
	WorkDir      string
	NoLoginShell bool
}

// ExecResponse scripts the outcome of an ExecCall.
type ExecResponse struct {
	Stdout   []byte
	Stderr   []byte
	ExitCode int
	// Err fails the stream after any output.
	Err error
	// Hang blocks the stream after any scripted Stdout and Stderr until
	// its context ends: a gateway that never reports the command's end.
	Hang bool
	// Duration is how long the command runs before it exits. Like the real
	// gateway, the fake does not stop a command whose client went away.
	// When Duration exceeds the call's Timeout, the in-sandbox timeout
	// stops it instead: the stream reports exit status 124 after Timeout,
	// without the scripted output.
	Duration time.Duration
}

// ExecHandler decides the response to a call. It runs when the caller
// first reads the stream.
type ExecHandler func(ctx context.Context, call ExecCall) ExecResponse

// HandleExec installs the exec handler. Without one every command exits 0
// with no output.
func (f *Fake) HandleExec(h ExecHandler) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.execHandler = h
}

// ExecCalls returns the commands run so far.
func (f *Fake) ExecCalls() []ExecCall {
	f.mu.Lock()
	defer f.mu.Unlock()
	return slices.Clone(f.execCalls)
}

type execClient struct{ f *Fake }

var _ v1.ExecInterface = (*execClient)(nil)

func (e *execClient) Stream(ctx context.Context, workspace, sandboxName string, command []string, opts ...types.ExecOptions) (v1.ExecStream, error) {
	if err := e.f.enter(MethodExec); err != nil {
		return nil, err
	}
	if sandboxName == "" {
		return nil, statusErr(types.ErrorInvalidArgument, "sandbox name must not be empty")
	}
	// Like the SDK, resolve the sandbox before opening the stream.
	if _, err := e.f.sdk.Sandboxes().Get(ctx, workspace, sandboxName); err != nil {
		return nil, err
	}
	call := ExecCall{Workspace: workspace, Sandbox: sandboxName, Argv: slices.Clone(command)}
	cmd, timeout, _ := openshell.ParseSandboxTimeoutArgv(command)
	call.Command, call.Timeout = slices.Clone(cmd), timeout
	if len(opts) > 0 {
		call.Env = maps.Clone(opts[0].Env)
		call.WorkDir = opts[0].WorkDir
		call.NoLoginShell = opts[0].NoLoginShell
	}
	e.f.mu.Lock()
	e.f.execCalls = append(e.f.execCalls, call)
	handler := e.f.execHandler
	e.f.mu.Unlock()
	return &execStream{ctx: ctx, call: call, handler: handler}, nil
}

func (e *execClient) Run(ctx context.Context, workspace, sandboxName string, command []string, opts ...types.ExecOptions) (*types.ExecResult, error) {
	stream, err := e.Stream(ctx, workspace, sandboxName, command, opts...)
	if err != nil {
		return nil, err
	}
	defer stream.Close()
	res := &types.ExecResult{}
	for {
		chunk, err := stream.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return nil, err
		}
		if chunk.Stream == types.StreamStderr {
			res.Stderr = append(res.Stderr, chunk.Data...)
		} else {
			res.Stdout = append(res.Stdout, chunk.Data...)
		}
	}
	code, err := stream.ExitCode()
	if err != nil {
		return nil, err
	}
	res.ExitCode = code
	return res, nil
}

func (e *execClient) Interactive(context.Context, string, string, []string, uint32, uint32, ...types.ExecOptions) (v1.InteractiveSession, error) {
	return nil, statusErr(types.ErrorUnimplemented, "interactive exec is not supported by openshelltest; use the openshell CLI for TTY sessions")
}

type execStream struct {
	ctx     context.Context
	call    ExecCall
	handler ExecHandler

	started bool
	pending []*types.ExecChunk
	resp    ExecResponse
	done    bool
	err     error
}

func (s *execStream) start() {
	s.started = true
	if s.handler != nil {
		s.resp = s.handler(s.ctx, s.call)
	}
	if s.resp.Duration > 0 {
		run, stopped := s.resp.Duration, false
		if s.call.Timeout > 0 && run > s.call.Timeout {
			run, stopped = s.call.Timeout, true
		}
		t := time.NewTimer(run)
		defer t.Stop()
		select {
		case <-s.ctx.Done():
			s.err = contextStatus(s.ctx.Err())
			return
		case <-t.C:
		}
		if stopped {
			s.resp = ExecResponse{ExitCode: 124}
			return
		}
	}
	if len(s.resp.Stdout) > 0 {
		s.pending = append(s.pending, &types.ExecChunk{Stream: types.StreamStdout, Data: s.resp.Stdout})
	}
	if len(s.resp.Stderr) > 0 {
		s.pending = append(s.pending, &types.ExecChunk{Stream: types.StreamStderr, Data: s.resp.Stderr})
	}
}

func (s *execStream) Next() (*types.ExecChunk, error) {
	if !s.started {
		s.start()
	}
	if s.err != nil {
		return nil, s.err
	}
	if len(s.pending) > 0 {
		chunk := s.pending[0]
		s.pending = s.pending[1:]
		return chunk, nil
	}
	if s.resp.Err != nil {
		s.err = s.resp.Err
		return nil, s.err
	}
	if s.resp.Hang {
		<-s.ctx.Done()
	}
	if err := s.ctx.Err(); err != nil {
		s.err = contextStatus(err)
		return nil, s.err
	}
	s.done = true
	return nil, io.EOF
}

func (s *execStream) ExitCode() (int, error) {
	for !s.done {
		if _, err := s.Next(); err != nil && !errors.Is(err, io.EOF) {
			return -1, err
		}
	}
	return s.resp.ExitCode, nil
}

func (s *execStream) Close() error { return nil }

func contextStatus(err error) error {
	if errors.Is(err, context.DeadlineExceeded) {
		return &types.StatusError{Code: types.ErrorDeadlineExceeded, Message: err.Error(), Cause: err}
	}
	return &types.StatusError{Code: types.ErrorCancelled, Message: err.Error(), Cause: err}
}

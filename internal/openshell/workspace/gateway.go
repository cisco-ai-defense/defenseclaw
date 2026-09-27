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
	"context"
	"fmt"

	"github.com/defenseclaw/defenseclaw/internal/openshell"
)

// OpenShellClient is the part of openshell.Client that GatewayClient
// drives; an openshell.Client satisfies it.
type OpenShellClient interface {
	ListSandboxes(ctx context.Context, selector map[string]string) ([]*openshell.Sandbox, error)
	Exec(ctx context.Context, sandbox string, argv []string, opts openshell.ExecOptions) (*openshell.ExecResult, error)
}

// GatewayClient adapts an openshell.Client to SandboxLister, for resume
// detection, and to Execer, so copy mode can run its commands through the
// gateway API. Its Exec is openshell.Client.Exec: the sandbox stops a
// command at its timeout, and only an Idempotent request is ever retried.
type GatewayClient struct {
	Client OpenShellClient
}

var (
	_ OpenShellClient = openshell.Client(nil)
	_ SandboxLister   = GatewayClient{}
	_ Execer          = GatewayClient{}
)

// FindSandboxes implements SandboxLister with a label-selector list call.
// A sandbox that is being deleted reports the Deleting phase whatever its
// status says, so resume detection skips it.
func (g GatewayClient) FindSandboxes(ctx context.Context, labels map[string]string) ([]SandboxInfo, error) {
	boxes, err := g.Client.ListSandboxes(ctx, labels)
	if err != nil {
		return nil, fmt.Errorf("workspace: %w", err)
	}
	out := make([]SandboxInfo, 0, len(boxes))
	for _, b := range boxes {
		if b == nil {
			continue
		}
		phase := string(b.Status.Phase)
		if b.DeletionTimestamp != nil {
			phase = string(openshell.PhaseDeleting)
		}
		out = append(out, SandboxInfo{Name: b.Name, Labels: b.Labels, Phase: phase, CreatedAt: b.CreatedAt})
	}
	return out, nil
}

// Exec implements Execer. A request's Stdout receives the stream as it
// arrives; the first write error ends the call.
func (g GatewayClient) Exec(ctx context.Context, sandbox string, req ExecRequest) (*ExecResult, error) {
	opts := openshell.ExecOptions{Env: req.Env, WorkDir: req.Workdir, Timeout: req.Timeout, Idempotent: req.Idempotent}
	var stream *streamWriter
	if req.Stdout != nil {
		// The client ignores tee errors, so the writer cancels the call
		// itself; the capture keeps only a token byte.
		var cancel context.CancelFunc
		ctx, cancel = context.WithCancel(ctx)
		defer cancel()
		stream = &streamWriter{w: req.Stdout, cancel: cancel}
		opts.Stdout, opts.MaxOutputBytes = stream, 1
	}
	res, err := g.Client.Exec(ctx, sandbox, req.Argv, opts)
	if stream != nil && stream.err != nil {
		return nil, stream.err
	}
	if err != nil {
		return nil, fmt.Errorf("workspace: %w", err)
	}
	out := &ExecResult{ExitCode: res.ExitCode, Stdout: res.Stdout, Stderr: res.Stderr}
	if stream != nil {
		out.Stdout = nil
	}
	return out, nil
}

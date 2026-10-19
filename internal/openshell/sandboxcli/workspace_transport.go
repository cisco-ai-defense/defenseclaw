// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package sandboxcli

import (
	"context"
	"errors"
	"maps"
	"slices"

	"github.com/defenseclaw/defenseclaw/internal/openshell"
	"github.com/defenseclaw/defenseclaw/internal/openshell/workspace"
)

var errMissingWorkspaceTransport = errors.New("sandbox session has no bound workspace transport")

// boundWorkspaceTransport retains the target chosen by the owning caller.
// The name on workspace's existing interface is checked, never a new selector.
// Binding transport grants no runtime, workspace policy or launch authority.
type boundWorkspaceTransport struct {
	sandbox  string
	delegate workspace.Transport
}

func bindWorkspaceTransport(sandbox string, delegate workspace.Transport) workspace.Transport {
	return &boundWorkspaceTransport{sandbox: sandbox, delegate: delegate}
}

// openShellWorkspaceTransport is the current copy workflow's explicit provider.
// Its guest operations require the OpenShell image's POSIX paths, shell, git
// and utilities. Native Windows needs typed guest operations plus qualified
// host staging with private ACLs, reparse-point protection and locking; this
// wrapper does not make that workflow supported on another execution OS.
func (a *App) openShellWorkspaceTransport(cli openshell.CLI, sandbox string) workspace.Transport {
	return bindWorkspaceTransport(sandbox, &workspace.CLI{
		Binary: cli.Binary, Gateway: cli.Gateway, Workspace: cli.Workspace,
	})
}

func (t *boundWorkspaceTransport) check(sandbox string) error {
	if t == nil || t.delegate == nil {
		return errMissingWorkspaceTransport
	}
	if err := workspace.ValidateName(t.sandbox); err != nil {
		return errors.New("workspace transport has no valid bound sandbox")
	}
	if sandbox != t.sandbox {
		return errors.New("workspace transport target differs from its bound sandbox")
	}
	return nil
}

func (t *boundWorkspaceTransport) Upload(ctx context.Context, sandbox, localPath, remoteDir string) error {
	if err := t.check(sandbox); err != nil {
		return err
	}
	return t.delegate.Upload(ctx, t.sandbox, localPath, remoteDir)
}

func (t *boundWorkspaceTransport) Download(ctx context.Context, sandbox, remotePath, localDir string) error {
	if err := t.check(sandbox); err != nil {
		return err
	}
	return t.delegate.Download(ctx, t.sandbox, remotePath, localDir)
}

func (t *boundWorkspaceTransport) Exec(ctx context.Context, sandbox string, req workspace.ExecRequest) (*workspace.ExecResult, error) {
	if err := t.check(sandbox); err != nil {
		return nil, err
	}
	req.Argv = slices.Clone(req.Argv)
	req.Env = maps.Clone(req.Env)
	return t.delegate.Exec(ctx, t.sandbox, req)
}

func (s *session) copyTransport() (workspace.Transport, error) {
	if s.workspaceTransport == nil {
		return nil, errMissingWorkspaceTransport
	}
	return s.workspaceTransport, nil
}

var _ workspace.Transport = (*boundWorkspaceTransport)(nil)

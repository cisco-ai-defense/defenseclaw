// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package sandboxcli

import (
	"context"
	"errors"
	"io"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/openshell"
	"github.com/defenseclaw/defenseclaw/internal/openshell/sandboxapi"
	"github.com/defenseclaw/defenseclaw/internal/openshell/workspace"
)

type workspaceTransportFixture struct {
	upload   func(context.Context, string, string, string) error
	download func(context.Context, string, string, string) error
	exec     func(context.Context, string, workspace.ExecRequest) (*workspace.ExecResult, error)
}

func (f workspaceTransportFixture) Upload(ctx context.Context, name, local, remote string) error {
	return f.upload(ctx, name, local, remote)
}

func (f workspaceTransportFixture) Download(ctx context.Context, name, remote, local string) error {
	return f.download(ctx, name, remote, local)
}

func (f workspaceTransportFixture) Exec(ctx context.Context, name string, req workspace.ExecRequest) (*workspace.ExecResult, error) {
	return f.exec(ctx, name, req)
}

func TestWorkspaceTransportBindingRefusesTargetChangesBeforeDelegate(t *testing.T) {
	delegate := workspaceTransportFixture{
		upload: func(context.Context, string, string, string) error {
			t.Fatal("refused upload reached delegate")
			return nil
		},
		download: func(context.Context, string, string, string) error {
			t.Fatal("refused download reached delegate")
			return nil
		},
		exec: func(context.Context, string, workspace.ExecRequest) (*workspace.ExecResult, error) {
			t.Fatal("refused exec reached delegate")
			return nil, nil
		},
	}
	for _, tc := range []struct {
		name, target, requested string
		delegate                workspace.Transport
	}{
		{"different", "owned-target", "other-target", delegate},
		{"missing requested target", "owned-target", "", delegate},
		{"invalid bound target", "../other", "../other", delegate},
		{"missing bound target", "", "", delegate},
		{"missing delegate", "owned-target", "owned-target", nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			transport := bindWorkspaceTransport(tc.target, tc.delegate)
			ctx := context.Background()
			if err := transport.Upload(ctx, tc.requested, "local", "remote"); err == nil {
				t.Fatal("upload accepted an unbound target")
			}
			if err := transport.Download(ctx, tc.requested, "remote", "local"); err == nil {
				t.Fatal("download accepted an unbound target")
			}
			if _, err := transport.Exec(ctx, tc.requested, workspace.ExecRequest{Argv: []string{"fixed"}}); err == nil {
				t.Fatal("exec accepted an unbound target")
			}
		})
	}
}

type workspaceErrorWriter struct{ err error }

func (w workspaceErrorWriter) Write([]byte) (int, error) { return 0, w.err }

func TestWorkspaceTransportBindingPreservesRequestsAndStreamFailure(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	writeErr := errors.New("fixed bounded stream refusal")
	sink := workspaceErrorWriter{err: writeErr}
	request := workspace.ExecRequest{
		Argv: []string{"/fixed/agent", "", `$(literal);'\"*`, "雪"}, Workdir: "/fixed/work",
		Env: map[string]string{"FIXED": "nonsecret"}, Timeout: 2 * time.Minute, Idempotent: true, Stdout: sink,
	}
	transfers := 0
	transport := bindWorkspaceTransport("owned-target", workspaceTransportFixture{
		upload: func(got context.Context, name, local, remote string) error {
			if got != ctx || name != "owned-target" || local != "local path" || remote != "/fixed/remote" {
				t.Fatal("upload changed its context, target or paths")
			}
			transfers++
			return nil
		},
		download: func(got context.Context, name, remote, local string) error {
			if got != ctx || name != "owned-target" || remote != "/fixed/remote" || local != "local path" {
				t.Fatal("download changed its context, target or paths")
			}
			transfers++
			return nil
		},
		exec: func(got context.Context, name string, req workspace.ExecRequest) (*workspace.ExecResult, error) {
			if got != ctx || name != "owned-target" || !reflect.DeepEqual(req, request) {
				t.Fatalf("exec changed its context, target or request: %+v", req)
			}
			req.Argv[0] = "delegate-mutated-copy"
			req.Env["FIXED"] = "delegate-mutated-copy"
			_, err := req.Stdout.Write([]byte("fixed bounded output"))
			return nil, err
		},
	})
	if err := transport.Upload(ctx, "owned-target", "local path", "/fixed/remote"); err != nil {
		t.Fatal(err)
	}
	if err := transport.Download(ctx, "owned-target", "/fixed/remote", "local path"); err != nil {
		t.Fatal(err)
	}
	for range 2 {
		if _, err := transport.Exec(ctx, "owned-target", request); !errors.Is(err, writeErr) {
			t.Fatalf("stream failure changed: %v", err)
		}
	}
	if transfers != 2 || request.Argv[0] != "/fixed/agent" || request.Env["FIXED"] != "nonsecret" {
		t.Fatal("transport lost a transfer or retained caller-owned argv/environment")
	}
}

func TestWorkspaceTransportOpenShellConstructorPreservesCLIContract(t *testing.T) {
	cli := openshell.CLI{Binary: "/fixed/openshell", Gateway: "owned-gateway", Workspace: "owned-workspace"}
	transport := (&App{}).openShellWorkspaceTransport(cli, "owned-target").(*boundWorkspaceTransport)
	delegate, ok := transport.delegate.(*workspace.CLI)
	if !ok || transport.sandbox != "owned-target" || delegate.Binary != cli.Binary || delegate.Gateway != cli.Gateway || delegate.Workspace != cli.Workspace {
		t.Fatal("OpenShell constructor changed provider scope")
	}
	// The existing CLI remains responsible for explicit --gateway/workspace,
	// timeout(1), retry, output bounds and OpenShell environment handling.
	request := workspace.ExecRequest{Argv: []string{"/fixed/agent", "literal arg"}, Workdir: "/fixed/work", Timeout: time.Minute}
	want, err := (&workspace.CLI{Binary: cli.Binary, Gateway: cli.Gateway, Workspace: cli.Workspace}).ExecArgv("owned-target", request)
	if err != nil {
		t.Fatal(err)
	}
	got, err := delegate.ExecArgv(transport.sandbox, request)
	if err != nil || !reflect.DeepEqual(got, want) {
		t.Fatalf("OpenShell exec invocation changed: %q, %v", got, err)
	}
}

type workspaceCopyFlowFixture struct {
	CopyWorkspace
	check func(string, workspace.Uploader, workspace.Execer)
}

func (f workspaceCopyFlowFixture) Upload(_ context.Context, _, name string, up workspace.Uploader, ex workspace.Execer) (*workspace.CopyRecord, error) {
	f.check("upload", up, ex)
	return &workspace.CopyRecord{Name: name}, nil
}

func (f workspaceCopyFlowFixture) Baseline(_ context.Context, _, name string, ex workspace.Execer) (*workspace.CopyRecord, error) {
	f.check("baseline", nil, ex)
	return &workspace.CopyRecord{Name: name}, nil
}

func (f workspaceCopyFlowFixture) Refresh(_ context.Context, opts workspace.RefreshOptions) (*workspace.CopyRecord, error) {
	f.check("refresh", opts.Upload, opts.Exec)
	return &workspace.CopyRecord{Name: opts.Stage.Name}, nil
}

func (f workspaceCopyFlowFixture) Pull(_ context.Context, opts workspace.PullOptions) (*workspace.PullResult, error) {
	f.check("pull", nil, opts.Exec)
	return &workspace.PullResult{Name: opts.Name}, nil
}

type workspaceFlowAPI struct{ API }

func (workspaceFlowAPI) ReportWorkspace(context.Context, string, sandboxapi.WorkspaceReport) error {
	return nil
}

func (workspaceFlowAPI) Explain(context.Context, sandboxapi.ExplainRequest) (*sandboxapi.Explain, error) {
	return &sandboxapi.Explain{}, nil
}

func TestWorkspaceTransportCopyOrchestrationUsesInjectedBinding(t *testing.T) {
	t.Setenv("DEFENSECLAW_DEPLOYMENT_MODE", "")
	t.Setenv("DEFENSECLAW_ENTERPRISE_PROFILE", "")
	root := t.TempDir()
	transport := bindWorkspaceTransport("owned-target", workspaceTransportFixture{})
	var steps []string
	app := &App{
		Cfg: &config.Config{DataDir: root}, API: workspaceFlowAPI{},
		IO:   IO{In: strings.NewReader(""), Out: io.Discard, Err: io.Discard},
		Home: func() (string, error) { return root, nil },
		Workspace: workspaceCopyFlowFixture{check: func(step string, up workspace.Uploader, ex workspace.Execer) {
			if ex != transport || (up != nil && up != transport) {
				t.Fatal("copy operation replaced its injected target binding")
			}
			steps = append(steps, step)
		}},
	}
	sb := &sandboxapi.Sandbox{Name: "owned-target", Harness: "claude", Project: root}
	s := &session{app: app, api: app.API, sb: sb, workspaceTransport: transport,
		cli: openshell.CLI{Gateway: "must-not-be-used"}}
	if err := s.uploadCopy(context.Background(), &workspace.CopyRecord{}); err != nil {
		t.Fatal(err)
	}
	if err := app.refreshCopy(context.Background(), s); err != nil {
		t.Fatal(err)
	}
	if _, err := app.pull(context.Background(), app.API, s.workspaceTransport, sb, false); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(steps, []string{"upload", "baseline", "refresh", "pull"}) {
		t.Fatalf("copy orchestration steps = %q", steps)
	}
}

func TestWorkspaceTransportMissingBindingRefusesBeforeCopyOperations(t *testing.T) {
	app := &App{Workspace: workspaceCopyFlowFixture{check: func(string, workspace.Uploader, workspace.Execer) {
		t.Fatal("missing workspace binding reached a copy operation")
	}}}
	s := &session{app: app, cli: openshell.CLI{Gateway: "must-not-fall-back"}, sb: &sandboxapi.Sandbox{Name: "owned-target"}}
	if err := s.uploadCopy(context.Background(), &workspace.CopyRecord{}); !errors.Is(err, errMissingWorkspaceTransport) {
		t.Fatalf("missing upload binding = %v", err)
	}
	if err := app.refreshCopy(context.Background(), s); !errors.Is(err, errMissingWorkspaceTransport) {
		t.Fatalf("missing refresh binding = %v", err)
	}
	if _, err := app.pull(context.Background(), nil, nil, s.sb, false); !errors.Is(err, errMissingWorkspaceTransport) {
		t.Fatalf("missing pull binding = %v", err)
	}
}

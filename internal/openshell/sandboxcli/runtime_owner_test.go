// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package sandboxcli

import (
	"context"
	"errors"
	"io"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/openshell/sandboxapi"
)

// Any unexpected API or copy-workspace call panics through the nil interface.
// The client must select the recorded owner before legacy transport preflight.
type runtimeOwnerAPI struct {
	API
	sb             sandboxapi.Sandbox
	stops, deletes int
	getErr         error
}

func (f *runtimeOwnerAPI) Get(context.Context, string) (*sandboxapi.Sandbox, error) {
	if f.getErr != nil {
		return nil, f.getErr
	}
	sb := f.sb
	return &sb, nil
}

func (f *runtimeOwnerAPI) Stop(context.Context, string) (*sandboxapi.Sandbox, error) {
	f.stops++
	sb := f.sb
	sb.Phase = "stopped"
	return &sb, nil
}

func (f *runtimeOwnerAPI) Delete(_ context.Context, name string, _ sandboxapi.DeleteRequest) (*sandboxapi.DeleteResponse, error) {
	f.deletes++
	return &sandboxapi.DeleteResponse{Name: name}, nil
}

type forbiddenOwnerWorkspace struct{ CopyWorkspace }

func runtimeOwnerApp(t *testing.T, runtime, phase string) (*App, *runtimeOwnerAPI) {
	t.Helper()
	api := &runtimeOwnerAPI{sb: sandboxapi.Sandbox{
		Name: "owned-box", Runtime: runtime, ID: "immutable-session", Phase: phase,
		Harness: "claudecode", WorkdirMode: config.OpenShellWorkdirCopy,
	}}
	app := &App{
		API: api, Cfg: &config.Config{DataDir: t.TempDir()},
		IO: IO{Out: io.Discard, Err: io.Discard}, Workspace: forbiddenOwnerWorkspace{},
		LookPath:     func(string) (string, error) { t.Fatal("legacy binary lookup"); return "", nil },
		OpenShellCLI: func() string { t.Fatal("legacy CLI selection"); return "" },
	}
	return app, api
}

func TestSandboxRuntimeOwnerRefusesLegacyOperations(t *testing.T) {
	operations := map[string]func(*App) error{
		"connect": func(a *App) error {
			return a.Connect(context.Background(), ConnectOptions{Name: "owned-box", Prompt: "hello"})
		},
		"exec": func(a *App) error {
			return a.Exec(context.Background(), ExecOptions{Name: "owned-box", Command: []string{"fixed"}})
		},
		"start": func(a *App) error { return a.Start(context.Background(), "owned-box", StartOptions{}) },
		"logs":  func(a *App) error { return a.Logs(context.Background(), LogsOptions{Name: "owned-box"}) },
		"pull":  func(a *App) error { return a.Pull(context.Background(), PullOptions{Name: "owned-box", Apply: true}) },
		"review": func(a *App) error {
			return a.Review(context.Background(), ReviewOptions{Name: "owned-box", Diff: true})
		},
		"undo": func(a *App) error { return a.Undo(context.Background(), UndoOptions{Name: "owned-box", Yes: true}) },
	}
	for _, runtime := range []string{"axis", "future-provider"} {
		for _, phase := range []string{"ready", "stopped"} {
			for name, operation := range operations {
				t.Run(runtime+"/"+phase+"/"+name, func(t *testing.T) {
					app, api := runtimeOwnerApp(t, runtime, phase)
					var unavailable *sandboxapi.Error
					if err := operation(app); !errors.As(err, &unavailable) || unavailable.Code != sandboxapi.CodeUnavailable {
						t.Fatalf("operation did not refuse owner: %v", err)
					}
					if api.stops != 0 || api.deletes != 0 {
						t.Fatal("refused operation mutated session")
					}
				})
			}
		}
	}
}

func TestSandboxRuntimeOwnerLifecycleUsesAPIWithoutLegacyPreflight(t *testing.T) {
	for _, phase := range []string{"ready", "stopped"} {
		t.Run(phase, func(t *testing.T) {
			app, api := runtimeOwnerApp(t, "axis", phase)
			if err := app.Stop(context.Background(), StopOptions{Name: "owned-box", Yes: true}); err != nil {
				t.Fatal(err)
			}
			if err := app.Delete(context.Background(), DeleteOptions{Names: []string{"owned-box"}, Yes: true}); err != nil {
				t.Fatal(err)
			}
			if api.stops != 1 || api.deletes != 1 {
				t.Fatalf("owner calls: stop=%d delete=%d", api.stops, api.deletes)
			}
			// Teardown also calls this helper: it must not inspect an old copy
			// that happens to have the same display name as the native session.
			if app.unhandedWork(context.Background(), &api.sb) != "" {
				t.Fatal("native session used legacy copy state")
			}
		})
	}
	app, api := runtimeOwnerApp(t, "future-provider", "ready")
	for _, err := range []error{
		app.Stop(context.Background(), StopOptions{Name: "owned-box", Yes: true}),
		app.Delete(context.Background(), DeleteOptions{Names: []string{"owned-box"}, Yes: true}),
	} {
		var unavailable *sandboxapi.Error
		if !errors.As(err, &unavailable) || unavailable.Code != sandboxapi.CodeUnavailable {
			t.Fatalf("unknown lifecycle owner did not refuse: %v", err)
		}
	}
	if api.stops != 0 || api.deletes != 0 {
		t.Fatal("unknown runtime reached lifecycle API")
	}
}

func TestSandboxRuntimeOwnerAcceptsLegacyResponses(t *testing.T) {
	for _, runtime := range []string{"", "openshell"} {
		sb := &sandboxapi.Sandbox{Runtime: runtime}
		if err := requireOpenShellOperation(sb, "connect"); err != nil {
			t.Fatal(err)
		}
		if err := requireLifecycleRuntime(sb, "stop"); err != nil {
			t.Fatal(err)
		}
	}
}

func TestSandboxRuntimeOwnerDeleteWithoutGetDoesNotCleanLegacyState(t *testing.T) {
	app, api := runtimeOwnerApp(t, "axis", "ready")
	api.getErr = errors.New("owner lookup unavailable")
	if err := app.Delete(context.Background(), DeleteOptions{Names: []string{"owned-box"}, Yes: true}); err != nil {
		t.Fatal(err)
	}
	if api.deletes != 1 {
		t.Fatal("delete did not reach the server owner")
	}
}

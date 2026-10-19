// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package sandboxcli

import (
	"bytes"
	"context"
	"errors"
	"io"
	"reflect"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/openshell"
	"github.com/defenseclaw/defenseclaw/internal/openshell/sandboxapi"
)

type sessionTerminalFunc func(context.Context, openshell.Invocation) (int, error)

func (f sessionTerminalFunc) Run(ctx context.Context, invocation openshell.Invocation) (int, error) {
	return f(ctx, invocation)
}

type sessionStreamerFunc func(context.Context, openshell.Invocation, io.Writer, io.Writer) (int, error)

func (f sessionStreamerFunc) Stream(ctx context.Context, invocation openshell.Invocation, out, errOut io.Writer) (int, error) {
	return f(ctx, invocation, out, errOut)
}

type sessionTransportFunc func(SessionExecRequest) (SessionExecution, error)

func (f sessionTransportFunc) Prepare(request SessionExecRequest) (SessionExecution, error) {
	return f(request)
}

type sessionExecutionFunc func(context.Context, SessionStreams) (int, error)

func (f sessionExecutionFunc) Run(ctx context.Context, streams SessionStreams) (int, error) {
	return f(ctx, streams)
}

func TestSessionTransportOpenShellInvocationParityAndDiagnosticCustody(t *testing.T) {
	for _, terminal := range []bool{false, true} {
		t.Run(map[bool]string{false: "stream", true: "terminal"}[terminal], func(t *testing.T) {
			cli := openshell.CLI{Binary: "/fixed/openshell", Gateway: "owned-gateway", Workspace: "owned-workspace"}
			argv := []string{"/fixed/agent", "", "literal spaces", `$(no-expansion);'"*?`, "unicode-λ-雪"}
			request := SessionExecRequest{Argv: slices.Clone(argv), WorkDir: "/workspace/a b", Timeout: 1500 * time.Millisecond, Terminal: terminal}
			want, err := cli.Exec("owned-target", argv, openshell.CLIExecOptions{TTY: terminal, WorkDir: request.WorkDir, Timeout: request.Timeout})
			if err != nil {
				t.Fatal(err)
			}
			var out, errOut, visible bytes.Buffer
			app := &App{IO: IO{Err: &visible}}
			s := &session{app: app}
			diagnostics := s.holdTransportErr()
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			check := func(gotCtx context.Context, invocation openshell.Invocation) {
				t.Helper()
				if gotCtx != ctx {
					t.Fatal("execution lost its cancellation context")
				}
				if !reflect.DeepEqual(invocation, want) {
					t.Fatalf("invocation changed: got %+v, want %+v", invocation, want)
				}
				invocation.Argv[0] = "runner-mutated-copy"
			}
			app.Terminal = sessionTerminalFunc(func(gotCtx context.Context, invocation openshell.Invocation) (int, error) {
				if !terminal {
					t.Fatal("stream command used the terminal")
				}
				check(gotCtx, invocation)
				_, _ = io.WriteString(invocation.Stderr, "fixed transport diagnostic\n")
				return 23, nil
			})
			app.Streamer = sessionStreamerFunc(func(gotCtx context.Context, invocation openshell.Invocation, stdout, stderr io.Writer) (int, error) {
				if terminal || stdout != &out || stderr != &errOut {
					t.Fatal("stream command changed mode or workload streams")
				}
				check(gotCtx, invocation)
				_, _ = io.WriteString(stdout, "fixed workload output\n")
				return 23, nil
			})
			execution, err := app.openShellSessionTransport(cli, "owned-target").Prepare(request)
			if err != nil {
				t.Fatal(err)
			}
			request.Argv[0] = "caller-mutated-after-prepare"
			streams := SessionStreams{Stdout: &out, Stderr: &errOut}
			if terminal {
				streams = SessionStreams{Diagnostics: diagnostics}
				want.Stderr = diagnostics
			}
			// Readiness may execute a prepared command again. Neither caller nor
			// runner may mutate the target or invocation of the later attempt.
			for range 2 {
				if code, err := execution.Run(ctx, streams); err != nil || code != 23 {
					t.Fatalf("Run = %d, %v", code, err)
				}
			}
			if visible.Len() != 0 {
				t.Fatal("transport diagnostics escaped onto the session screen")
			}
			if terminal {
				s.printCLIErr(false)
				if strings.Count(visible.String(), "fixed transport diagnostic") != 2 || out.Len() != 0 {
					t.Fatal("held diagnostics or workload custody changed")
				}
			} else if strings.Count(out.String(), "fixed workload output") != 2 {
				t.Fatal("workload output was lost")
			}
		})
	}
}

func TestSessionTransportOpenShellRefusesUnsupportedStreamsBeforeRun(t *testing.T) {
	for _, tc := range []struct {
		name     string
		terminal bool
		streams  SessionStreams
	}{
		{"terminal input", true, SessionStreams{Stdin: strings.NewReader("fixed")}},
		{"terminal output", true, SessionStreams{Stdout: io.Discard}},
		{"terminal error", true, SessionStreams{Stderr: io.Discard}},
		{"stream input", false, SessionStreams{Stdin: strings.NewReader("fixed")}},
		{"stream diagnostics", false, SessionStreams{Diagnostics: io.Discard}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			app := &App{
				Terminal: sessionTerminalFunc(func(context.Context, openshell.Invocation) (int, error) {
					t.Fatal("unsupported streams reached the terminal")
					return 0, nil
				}),
				Streamer: sessionStreamerFunc(func(context.Context, openshell.Invocation, io.Writer, io.Writer) (int, error) {
					t.Fatal("unsupported streams reached the streamer")
					return 0, nil
				}),
			}
			execution, err := app.openShellSessionTransport(openshell.CLI{Gateway: "gateway"}, "owned-target").Prepare(
				SessionExecRequest{Argv: []string{"/fixed/agent"}, Terminal: tc.terminal})
			if err != nil {
				t.Fatal(err)
			}
			if code, err := execution.Run(context.Background(), tc.streams); err == nil || code != -1 {
				t.Fatalf("unsupported Run = %d, %v", code, err)
			}
		})
	}
}

func TestSessionTransportProbeUsesOnlyExplicitBindingAndPreservesRetries(t *testing.T) {
	var requests []SessionExecRequest
	attempts, sleeps := 0, 0
	s := &session{
		app: &App{Sleep: func(context.Context, time.Duration) error { sleeps++; return nil }},
		sb:  &sandboxapi.Sandbox{Name: "metadata-is-not-a-transport-target"},
		cli: openshell.CLI{Gateway: "must-not-fall-back"},
		transport: sessionTransportFunc(func(request SessionExecRequest) (SessionExecution, error) {
			requests = append(requests, request)
			return sessionExecutionFunc(func(_ context.Context, streams SessionStreams) (int, error) {
				attempts++
				if streams.Stdout == nil || streams.Stdout != streams.Stderr || streams.Diagnostics != nil {
					t.Fatal("probe lost its shared output capture")
				}
				if attempts == 1 {
					_, _ = io.WriteString(streams.Stdout, "fixed retry refusal")
					return 1, nil
				}
				return 0, nil
			}), nil
		}),
	}
	if err := s.probe(context.Background(), "/fixed/workspace"); err != nil {
		t.Fatal(err)
	}
	want := SessionExecRequest{Argv: []string{"true"}, WorkDir: "/fixed/workspace", Timeout: probeTimeout}
	if attempts != 2 || sleeps != 1 || !reflect.DeepEqual(requests, []SessionExecRequest{want}) {
		t.Fatalf("probe requests=%+v attempts=%d sleeps=%d", requests, attempts, sleeps)
	}
}

func TestSessionTransportMissingAndOpenShellRecipeRefusalDoNotFallback(t *testing.T) {
	s := &session{sb: &sandboxapi.Sandbox{Name: "box"}, cli: openshell.CLI{Gateway: "valid-legacy-gateway"}}
	if err := s.probe(context.Background(), ""); !errors.Is(err, errMissingSessionTransport) {
		t.Fatalf("missing transport = %v", err)
	}
	if s.answers(context.Background()) {
		t.Fatal("missing execution transport counted as an answer")
	}
	s.transport = sessionTransportFunc(func(SessionExecRequest) (SessionExecution, error) {
		t.Fatal("alternate transport received an OpenShell-specific recipe")
		return nil, nil
	})
	if _, err := s.prepareOpenShellRecipe(SessionExecRequest{Argv: loginShell}); err == nil {
		t.Fatal("alternate transport accepted the OpenShell login shell")
	}
	if resolves, listed, known := s.localhostState(context.Background()); resolves || listed || known {
		t.Fatal("unsupported transport reported OpenShell localhost evidence")
	}
	s.transport = sessionTransportFunc(func(SessionExecRequest) (SessionExecution, error) {
		return nil, errors.New("fixed unsupported operation")
	})
	if s.answers(context.Background()) {
		t.Fatal("alternate transport preparation refusal counted as readiness")
	}
	// Retain OpenShell's existing unknown-phase behavior on CLI preparation
	// errors, without applying it to a different runtime's refusal.
	s.transport = (&App{}).openShellSessionTransport(openshell.CLI{}, "box")
	if !s.answers(context.Background()) {
		t.Fatal("legacy CLI preparation error changed its phase semantics")
	}
}

func TestSessionTransportProbeCancellationPreservesContextError(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	s := &session{sb: &sandboxapi.Sandbox{Name: "box"}, transport: sessionTransportFunc(func(SessionExecRequest) (SessionExecution, error) {
		return sessionExecutionFunc(func(run context.Context, _ SessionStreams) (int, error) {
			if run != ctx {
				t.Fatal("probe changed its cancellation context")
			}
			cancel()
			return -1, run.Err()
		}), nil
	})}
	if err := s.probe(ctx, ""); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancelled probe = %v", err)
	}
}

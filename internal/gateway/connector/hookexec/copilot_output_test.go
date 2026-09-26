// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package hookexec

import (
	"bytes"
	"context"
	"io"
	"net/http"
	"strings"
	"testing"
)

type copilotRoundTripper func(*http.Request) (*http.Response, error)

func (fn copilotRoundTripper) RoundTrip(req *http.Request) (*http.Response, error) { return fn(req) }

func managedCopilotOptions(t *testing.T) (Options, *bytes.Buffer, *bytes.Buffer) {
	t.Helper()
	out := &bytes.Buffer{}
	errOut := &bytes.Buffer{}
	token := "scoped-token"
	return Options{
		Connector: "copilot", Event: "preToolUse", HookContractID: managedCopilotHookContractID,
		ManagedEnterprise: true, Home: t.TempDir(), APIAddr: "127.0.0.1:18970",
		AuthenticatedManagedToken: &token, Stdin: strings.NewReader(`{"toolName":"shell","toolArgs":{"command":"echo ok"}}`),
		Stdout: out, Stderr: errOut,
	}, out, errOut
}

func TestManagedCopilotInfrastructureFailureIsNoop(t *testing.T) {
	opts, out, _ := managedCopilotOptions(t)
	opts.ManagedRuntimeFailure = "enterprise_managed_runtime_state_invalid"
	opts.StrictAvailability = true
	opts.FailMode = "closed"
	if code := Run(context.Background(), opts); code != 0 {
		t.Fatalf("exit=%d want 0", code)
	}
	if out.Len() != 0 {
		t.Fatalf("infrastructure failure emitted deny JSON: %q", out.String())
	}
}

func TestManagedCopilotBindsHeadersAndEmitsOneJSON(t *testing.T) {
	opts, out, _ := managedCopilotOptions(t)
	opts.HTTPClient = &http.Client{Transport: copilotRoundTripper(func(req *http.Request) (*http.Response, error) {
		if got := req.Header.Get("X-DefenseClaw-Hook-Event"); got != "preToolUse" {
			t.Fatalf("event header=%q", got)
		}
		if got := req.Header.Get("X-DefenseClaw-Hook-Contract"); got != managedCopilotHookContractID {
			t.Fatalf("contract header=%q", got)
		}
		if got := req.Header.Get("X-DefenseClaw-Managed-Enterprise"); got != "true" {
			t.Fatalf("managed header=%q", got)
		}
		return &http.Response{
			StatusCode: http.StatusOK,
			Body:       io.NopCloser(strings.NewReader(`{"action":"block","hook_output":{"permissionDecision":"deny","permissionDecisionReason":"DefenseClaw blocked this tool call."}}`)),
			Header:     make(http.Header),
		}, nil
	})}
	if code := Run(context.Background(), opts); code != 0 {
		t.Fatalf("exit=%d want 0", code)
	}
	lines := strings.Split(strings.TrimSpace(out.String()), "\n")
	if len(lines) != 1 || lines[0] != `{"permissionDecision":"deny","permissionDecisionReason":"DefenseClaw blocked this tool call."}` {
		t.Fatalf("stdout=%q want exactly one JSON object", out.String())
	}
}

func TestManagedCopilotPayloadEventMismatchIsNoop(t *testing.T) {
	opts, out, _ := managedCopilotOptions(t)
	opts.Stdin = strings.NewReader(`{"hookEventName":"postToolUse","toolName":"shell"}`)
	opts.HTTPClient = &http.Client{Transport: copilotRoundTripper(func(*http.Request) (*http.Response, error) {
		t.Fatal("mismatched payload reached gateway")
		return nil, nil
	})}
	if code := Run(context.Background(), opts); code != 0 || out.Len() != 0 {
		t.Fatalf("exit/stdout=%d/%q want no-op", code, out.String())
	}
}

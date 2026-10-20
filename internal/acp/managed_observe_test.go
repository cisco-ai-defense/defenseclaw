// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package acp

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"strings"
	"testing"
)

// rel-1-0-3 GAP-0037: a standalone managed guard in observe mode refuses a
// frame it could not evaluate, as action mode does, instead of delivering
// it unchecked. An administrator who switched ACP checking off is an answer,
// and that frame still goes through. A per-user observe guard keeps
// delivering.
func TestManagedObserveGuardRefusesAFrameItCouldNotEvaluate(t *testing.T) {
	prompt := `{"jsonrpc":"2.0","id":7,"method":"session/prompt","params":{"sessionId":"s","prompt":[]}}` + "\n"
	for _, tc := range []struct {
		name      string
		managed   bool
		err       error
		delivered bool
	}{
		{name: "managed, gateway did not answer", managed: true, err: errors.New("offline"), delivered: false},
		{name: "managed, gateway not ready", managed: true, err: fmt.Errorf("503: %w", ErrGatewayNotReady), delivered: false},
		{name: "managed, checking switched off", managed: true, err: ErrACPDisabled, delivered: true},
		{name: "per-user, gateway did not answer", managed: false, err: errors.New("offline"), delivered: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var forwarded, client bytes.Buffer
			state := &proxyState{pendingClient: map[string]string{}, pendingAgent: map[string]string{}, peerProtocolFixes: true}
			opts := ProxyOptions{Mode: ModeObserve, Evaluator: &recordingEvaluator{err: tc.err}, Managed: tc.managed, Stderr: io.Discard}
			if err := copyFrames(context.Background(), opts, state, ClientToAgent, strings.NewReader(prompt), &forwarded, &client); err != nil {
				t.Fatal(err)
			}
			if delivered := strings.Contains(forwarded.String(), `"id":7`); delivered != tc.delivered {
				t.Fatalf("delivered = %v, want %v: agent=%q client=%q", delivered, tc.delivered, forwarded.String(), client.String())
			}
			if !tc.delivered && !strings.Contains(client.String(), "not delivered") {
				t.Fatalf("the editor was not told why: %q", client.String())
			}
		})
	}
}

// sequenceEvaluator answers each Evaluate with the next verdict and error.
type sequenceEvaluator struct {
	verdicts []Verdict
	errs     []error
	calls    int
}

func (e *sequenceEvaluator) Evaluate(context.Context, Evaluation) (Verdict, error) {
	i := e.calls
	e.calls++
	return e.verdicts[i], e.errs[i]
}

// Owner decision 2026-10-20: the administrator chooses with the profile's
// fail_mode. After an authenticated verdict said the profile's fail_mode is
// explicitly open, a standalone managed observe guard delivers a frame it
// could not evaluate; without that (unset) it keeps refusing it.
func TestManagedObserveGuardFollowsAnExplicitOpenFailMode(t *testing.T) {
	frames := `{"jsonrpc":"2.0","id":7,"method":"session/prompt","params":{"sessionId":"s","prompt":[]}}` + "\n" +
		`{"jsonrpc":"2.0","id":8,"method":"session/prompt","params":{"sessionId":"s","prompt":[]}}` + "\n"
	for _, tc := range []struct {
		name      string
		failMode  string
		delivered bool
	}{
		{name: "fail_mode open", failMode: "open", delivered: true},
		{name: "fail_mode unset", failMode: "", delivered: false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var forwarded, client bytes.Buffer
			state := &proxyState{pendingClient: map[string]string{}, pendingAgent: map[string]string{}, peerProtocolFixes: true}
			evaluator := &sequenceEvaluator{
				verdicts: []Verdict{{Action: "allow", FailMode: tc.failMode}, {}},
				errs:     []error{nil, errors.New("offline")},
			}
			opts := ProxyOptions{Mode: ModeObserve, Evaluator: evaluator, Managed: true, Stderr: io.Discard}
			if err := copyFrames(context.Background(), opts, state, ClientToAgent, strings.NewReader(frames), &forwarded, &client); err != nil {
				t.Fatal(err)
			}
			if !strings.Contains(forwarded.String(), `"id":7`) {
				t.Fatalf("the evaluated frame was not delivered: %q", forwarded.String())
			}
			if delivered := strings.Contains(forwarded.String(), `"id":8`); delivered != tc.delivered {
				t.Fatalf("unevaluated frame delivered = %v, want %v: agent=%q client=%q", delivered, tc.delivered, forwarded.String(), client.String())
			}
		})
	}
}

// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package acp

import (
	"bytes"
	"context"
	"testing"
)

type enforcedBlockEvaluator struct{ enforced bool }

func (e enforcedBlockEvaluator) Evaluate(_ context.Context, in Evaluation) (Verdict, error) {
	if in.Surface == SurfacePrompt {
		return Verdict{Action: "block", RawAction: "block", Reason: "DefenseClaw refused this request: the account holder is unconfirmed", Enforced: e.enforced}, nil
	}
	return Verdict{Action: "allow"}, nil
}

// GAP-2103: a managed observe-mode guard forwarded a frame the gateway
// refused for an unconfirmed account holder (identity uncertainty refuses in
// every mode), and the agent answered it. A block the gateway marks enforced
// is refused in observe mode too; an ordinary observe finding still passes
// on as a would-block (no over-tightening).
func TestObserveGuardRefusesAFrameTheGatewayEnforces(t *testing.T) {
	frame := `{"jsonrpc":"2.0","id":7,"method":"session/prompt","params":{"sessionId":"s","prompt":[]}}` + "\n"
	for _, tc := range []struct {
		name     string
		enforced bool
	}{
		{"identity refusal (enforced)", true},
		{"observe finding (would block)", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var forwarded, rejected, stderr bytes.Buffer
			state := &proxyState{pendingClient: map[string]string{}, pendingAgent: map[string]string{}}
			err := copyFrames(context.Background(), ProxyOptions{Mode: ModeObserve, Evaluator: enforcedBlockEvaluator{tc.enforced}, Stderr: &stderr},
				state, ClientToAgent, bytes.NewBufferString(frame), &forwarded, &rejected)
			if err != nil {
				t.Fatal(err)
			}
			if tc.enforced {
				if forwarded.Len() != 0 {
					t.Fatalf("observe guard forwarded a frame the gateway refused: %s", forwarded.String())
				}
				if !bytes.Contains(rejected.Bytes(), []byte("account holder is unconfirmed")) {
					t.Fatalf("the editor did not get the refusal: %s", rejected.String())
				}
				return
			}
			if forwarded.Len() == 0 || rejected.Len() != 0 {
				t.Fatalf("observe finding not passed on: forwarded=%q rejected=%q", forwarded.String(), rejected.String())
			}
			if !bytes.Contains(stderr.Bytes(), []byte("would block")) {
				t.Fatalf("missing observation: %s", stderr.String())
			}
		})
	}
}

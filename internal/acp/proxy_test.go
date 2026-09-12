// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package acp

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"testing"
)

type blockingEvaluator struct{}

func (blockingEvaluator) Evaluate(_ context.Context, in Evaluation) (Verdict, error) {
	if in.Surface == SurfacePrompt {
		return Verdict{Action: "block", Reason: "test policy"}, nil
	}
	return Verdict{Action: "allow"}, nil
}

type methodBlockingEvaluator string

func (method methodBlockingEvaluator) Evaluate(_ context.Context, in Evaluation) (Verdict, error) {
	if in.Method == string(method) {
		return Verdict{Action: "block", Reason: "test policy"}, nil
	}
	return Verdict{Action: "allow"}, nil
}

func TestCopyFramesActionSynthesizesBlockResponse(t *testing.T) {
	input := bytes.NewBufferString(`{"jsonrpc":"2.0","id":7,"method":"session/prompt","params":{"prompt":[]}}` + "\n")
	var forwarded, rejected bytes.Buffer
	state := &proxyState{pendingClient: map[string]string{}, pendingAgent: map[string]string{}}
	err := copyFrames(context.Background(), ProxyOptions{Mode: ModeAction, Evaluator: blockingEvaluator{}}, state, ClientToAgent, input, &forwarded, &rejected)
	if err != nil {
		t.Fatal(err)
	}
	if forwarded.Len() != 0 {
		t.Fatalf("blocked request forwarded: %s", forwarded.String())
	}
	if !bytes.Contains(rejected.Bytes(), []byte(`"code":-32001`)) {
		t.Fatalf("missing block response: %s", rejected.String())
	}
	if len(state.pendingClient) != 0 {
		t.Fatal("blocked ID remained pending")
	}
}

func TestCopyFramesObserveForwardsWouldBlock(t *testing.T) {
	input := bytes.NewBufferString(`{"jsonrpc":"2.0","id":7,"method":"session/prompt","params":{"prompt":[]}}` + "\n")
	var forwarded, rejected, stderr bytes.Buffer
	state := &proxyState{pendingClient: map[string]string{}, pendingAgent: map[string]string{}}
	err := copyFrames(context.Background(), ProxyOptions{Mode: ModeObserve, Evaluator: blockingEvaluator{}, Stderr: &stderr}, state, ClientToAgent, input, &forwarded, &rejected)
	if err != nil {
		t.Fatal(err)
	}
	if forwarded.Len() == 0 || rejected.Len() != 0 {
		t.Fatalf("observe did not preserve request")
	}
	if !bytes.Contains(stderr.Bytes(), []byte("would block")) {
		t.Fatalf("missing observation: %s", stderr.String())
	}
}

type modeMismatchEvaluator struct{}

func (modeMismatchEvaluator) Evaluate(context.Context, Evaluation) (Verdict, error) {
	return Verdict{}, ErrModeMismatch
}

func TestCopyFramesObserveFailsClosedOnRuntimeModeMismatch(t *testing.T) {
	frame := "{\"jsonrpc\":\"2.0\",\"method\":\"initialized\"}\n"
	var forwarded, rejected, stderr bytes.Buffer
	state := &proxyState{pendingClient: map[string]string{}, pendingAgent: map[string]string{}}
	err := copyFrames(context.Background(), ProxyOptions{
		Mode: ModeObserve, Evaluator: modeMismatchEvaluator{}, Stderr: &stderr,
	}, state, ClientToAgent, bytes.NewBufferString(frame), &forwarded, &rejected)
	if !errors.Is(err, ErrModeMismatch) || forwarded.Len() != 0 {
		t.Fatalf("mode mismatch did not fail closed: err=%v forwarded=%q", err, forwarded.String())
	}
}

func TestCopyFramesActionBuffersOutputUntilPromptResponse(t *testing.T) {
	state := &proxyState{pendingClient: map[string]string{}, pendingAgent: map[string]string{}}
	var agentInput, clientOutput bytes.Buffer
	prompt := bytes.NewBufferString(`{"jsonrpc":"2.0","id":7,"method":"session/prompt","params":{"prompt":[]}}` + "\n")
	if err := copyFrames(context.Background(), ProxyOptions{Mode: ModeAction, Evaluator: AllowEvaluator{}}, state, ClientToAgent, prompt, &agentInput, &clientOutput); err != nil {
		t.Fatal(err)
	}
	updates := bytes.NewBufferString(
		`{"jsonrpc":"2.0","method":"session/update","params":{"sessionId":"s","update":{"sessionUpdate":"agent_message_chunk","content":{"type":"text","text":"secret"}}}}` + "\n",
	)
	if err := copyFrames(context.Background(), ProxyOptions{Mode: ModeAction, Evaluator: AllowEvaluator{}}, state, AgentToClient, updates, &clientOutput, &agentInput); err != nil {
		t.Fatal(err)
	}
	if clientOutput.Len() != 0 {
		t.Fatalf("turn output leaked before terminal response: %s", clientOutput.String())
	}
	terminal := bytes.NewBufferString(`{"jsonrpc":"2.0","id":7,"result":{"stopReason":"end_turn"}}` + "\n")
	if err := copyFrames(context.Background(), ProxyOptions{Mode: ModeAction, Evaluator: AllowEvaluator{}}, state, AgentToClient, terminal, &clientOutput, &agentInput); err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(clientOutput.Bytes(), []byte("secret")) || !bytes.Contains(clientOutput.Bytes(), []byte("stopReason")) {
		t.Fatalf("buffered turn did not flush atomically: %s", clientOutput.String())
	}
}

func TestCopyFramesActionPassesInspectedAgentRequestWithoutDeadlock(t *testing.T) {
	state := &proxyState{pendingClient: map[string]string{}, pendingAgent: map[string]string{}}
	_, _ = state.track(Message{JSONRPC: "2.0", ID: json.RawMessage("7"), Method: "session/prompt"}, ClientToAgent, ModeAction)
	request := bytes.NewBufferString(`{"jsonrpc":"2.0","id":9,"method":"fs/read_text_file","params":{"path":"README.md"}}` + "\n")
	var clientOutput, agentInput bytes.Buffer
	if err := copyFrames(context.Background(), ProxyOptions{Mode: ModeAction, Evaluator: AllowEvaluator{}}, state, AgentToClient, request, &clientOutput, &agentInput); err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(clientOutput.Bytes(), []byte("fs/read_text_file")) {
		t.Fatalf("evaluated agent request was buffered: %s", clientOutput.String())
	}
}

func TestCopyFramesActionDiscardsBufferedOutputOnBlockedAgentRequest(t *testing.T) {
	state := &proxyState{pendingClient: map[string]string{}, pendingAgent: map[string]string{}}
	_, _ = state.track(Message{JSONRPC: "2.0", ID: json.RawMessage("7"), Method: "session/prompt"}, ClientToAgent, ModeAction)
	var clientOutput, agentInput bytes.Buffer
	updates := bytes.NewBufferString(`{"jsonrpc":"2.0","method":"session/update","params":{"text":"must-not-leak"}}` + "\n")
	if err := copyFrames(context.Background(), ProxyOptions{Mode: ModeAction, Evaluator: AllowEvaluator{}}, state, AgentToClient, updates, &clientOutput, &agentInput); err != nil {
		t.Fatal(err)
	}
	request := bytes.NewBufferString(`{"jsonrpc":"2.0","id":9,"method":"fs/write_text_file","params":{"path":"x","content":"x"}}` + "\n")
	if err := copyFrames(context.Background(), ProxyOptions{Mode: ModeAction, Evaluator: methodBlockingEvaluator("fs/write_text_file")}, state, AgentToClient, request, &clientOutput, &agentInput); err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(clientOutput.Bytes(), []byte("must-not-leak")) || !bytes.Contains(clientOutput.Bytes(), []byte(`"id":7`)) {
		t.Fatalf("blocked turn leaked output or omitted prompt error: %s", clientOutput.String())
	}
	if !bytes.Contains(agentInput.Bytes(), []byte(`"id":9`)) {
		t.Fatalf("agent did not receive the blocked request error: %s", agentInput.String())
	}
}

func TestProxyStateRejectsDuplicateAndExcessPendingIDs(t *testing.T) {
	state := &proxyState{pendingClient: map[string]string{}, pendingAgent: map[string]string{}}
	first := Message{JSONRPC: "2.0", ID: json.RawMessage("1"), Method: "initialize"}
	if _, err := state.track(first, ClientToAgent, ModeAction); err != nil {
		t.Fatal(err)
	}
	if _, err := state.track(first, ClientToAgent, ModeAction); err == nil || err.Error() != "duplicate pending ACP request ID" {
		t.Fatalf("duplicate pending ID error = %v", err)
	}
	for id := 2; id <= MaxPendingIDs; id++ {
		msg := Message{JSONRPC: "2.0", ID: json.RawMessage(fmt.Sprint(id)), Method: "session/new"}
		if _, err := state.track(msg, ClientToAgent, ModeAction); err != nil {
			t.Fatalf("track pending ID %d: %v", id, err)
		}
	}
	overflow := Message{JSONRPC: "2.0", ID: json.RawMessage("999"), Method: "session/new"}
	if _, err := state.track(overflow, ClientToAgent, ModeAction); err == nil || err.Error() != "too many pending ACP request IDs" {
		t.Fatalf("pending ID overflow error = %v", err)
	}
}

type recordingEvaluator struct {
	seen []Evaluation
	err  error
}

func (e *recordingEvaluator) Evaluate(_ context.Context, in Evaluation) (Verdict, error) {
	e.seen = append(e.seen, in)
	return Verdict{Action: "allow"}, e.err
}

func TestCopyFramesForwardsCancellationAsProtocolTraffic(t *testing.T) {
	evaluator := &recordingEvaluator{}
	frame := `{"jsonrpc":"2.0","method":"session/cancel","params":{"sessionId":"s"}}` + "\n"
	input := bytes.NewBufferString(frame)
	var forwarded, rejected bytes.Buffer
	state := &proxyState{pendingClient: map[string]string{}, pendingAgent: map[string]string{}}
	if err := copyFrames(context.Background(), ProxyOptions{Mode: ModeAction, Evaluator: evaluator}, state, ClientToAgent, input, &forwarded, &rejected); err != nil {
		t.Fatal(err)
	}
	if forwarded.String() != frame || rejected.Len() != 0 {
		t.Fatalf("cancel frame was not preserved: forwarded=%q rejected=%q", forwarded.String(), rejected.String())
	}
	if len(evaluator.seen) != 1 || evaluator.seen[0].Surface != SurfaceProtocol || evaluator.seen[0].Method != "session/cancel" {
		t.Fatalf("cancel evaluation = %+v", evaluator.seen)
	}
}

func TestCopyFramesEvaluatorFailureIsClosedOnlyInActionMode(t *testing.T) {
	for _, mode := range []Mode{ModeAction, ModeObserve} {
		evaluator := &recordingEvaluator{err: errors.New("offline")}
		frame := `{"jsonrpc":"2.0","method":"initialized"}` + "\n"
		input := bytes.NewBufferString(frame)
		var forwarded, rejected, stderr bytes.Buffer
		state := &proxyState{pendingClient: map[string]string{}, pendingAgent: map[string]string{}}
		err := copyFrames(context.Background(), ProxyOptions{Mode: mode, Evaluator: evaluator, Stderr: &stderr}, state, ClientToAgent, input, &forwarded, &rejected)
		if mode == ModeAction && (err == nil || forwarded.Len() != 0) {
			t.Fatalf("action mode did not fail closed: err=%v forwarded=%q", err, forwarded.String())
		}
		if mode == ModeObserve && (err != nil || forwarded.String() != frame) {
			t.Fatalf("observe mode did not fail open: err=%v forwarded=%q", err, forwarded.String())
		}
	}
}

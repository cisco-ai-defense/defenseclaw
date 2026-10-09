// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package acp

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"path/filepath"
	"strings"
	"testing"
	"time"
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

type contentBlockingEvaluator string

func (needle contentBlockingEvaluator) Evaluate(_ context.Context, in Evaluation) (Verdict, error) {
	if bytes.Contains(in.Payload, []byte(needle)) {
		return Verdict{Action: "block", Reason: "test content policy"}, nil
	}
	return Verdict{Action: "allow"}, nil
}

func TestRunActionModeRequiresEvaluatorBeforeAgentLaunch(t *testing.T) {
	err := Run(context.Background(), ProxyOptions{
		Mode: ModeAction, Command: filepath.Join(t.TempDir(), "must-not-launch"),
		Stdin: bytes.NewReader(nil), Stdout: io.Discard, Stderr: io.Discard,
	})
	if err == nil || !strings.Contains(err.Error(), "requires an evaluator") {
		t.Fatalf("Run error = %v, want missing-evaluator refusal", err)
	}
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
	// The user is told what changed and which command to run, not "re-run
	// managed setup" (GAP-0355).
	state.peerProtocolFixes = true
	err = copyFrames(context.Background(), ProxyOptions{
		Mode: ModeObserve, Profile: "p", Evaluator: modeMismatchEvaluator{}, Stderr: &stderr, Managed: true,
		SetupCommand: "/opt/defenseclaw/bin/defenseclaw-gateway enterprise acp setup --client zed --agent kiro --profile p",
	}, state, ClientToAgent, bytes.NewBufferString(frame), &forwarded, &rejected)
	// An entry set up without --activate is not told that the administrator
	// changed the mode (GAP-0924).
	if !errors.Is(err, ErrModeMismatch) || !strings.Contains(err.Error(), "profile p is in action mode, but this editor entry is set up for observe mode") ||
		!strings.Contains(err.Error(), "set up without --activate") ||
		!strings.Contains(err.Error(), "enterprise acp setup --client zed --agent kiro --profile p --activate") {
		t.Fatalf("mode drift message = %v", err)
	}
}

// chanWriter hands every write to the test.
type chanWriter chan []byte

func (w chanWriter) Write(p []byte) (int, error) {
	w <- append([]byte(nil), p...)
	return len(p), nil
}

// A prompt the agent does not answer gets a notice, once: Hermes waiting for
// its first-run questions on a terminal left the thread on a spinner with no
// text (GAP-0870). Any agent frame cancels it.
func TestSilentAgentPromptGetsAWaitNotice(t *testing.T) {
	previous := agentSilenceNotice
	agentSilenceNotice = 20 * time.Millisecond
	t.Cleanup(func() { agentSilenceNotice = previous })
	client := make(chanWriter, 4)
	state := &proxyState{peerProtocolFixes: true}
	state.armSilenceNotice(ProxyOptions{AgentID: "hermes"}, "s1", client)
	select {
	case frame := <-client:
		if !strings.Contains(string(frame), `"sessionId":"s1"`) || !strings.Contains(string(frame), "run hermes once in a terminal") {
			t.Fatalf("notice = %s", frame)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("no notice for a silent agent")
	}
	state.armSilenceNotice(ProxyOptions{AgentID: "hermes"}, "s2", client)
	state.agentSpoke()
	select {
	case frame := <-client:
		t.Fatalf("a notice after the agent answered: %s", frame)
	case <-time.After(100 * time.Millisecond):
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

func TestCopyFramesActionInspectsStringsAcrossBufferedFrameBoundaries(t *testing.T) {
	state := &proxyState{pendingClient: map[string]string{}, pendingAgent: map[string]string{}}
	var agentInput, clientOutput bytes.Buffer
	prompt := bytes.NewBufferString(`{"jsonrpc":"2.0","id":7,"method":"session/prompt","params":{"prompt":[]}}` + "\n")
	if err := copyFrames(context.Background(), ProxyOptions{Mode: ModeAction, Evaluator: AllowEvaluator{}}, state, ClientToAgent, prompt, &agentInput, &clientOutput); err != nil {
		t.Fatal(err)
	}
	updates := bytes.NewBufferString(
		`{"jsonrpc":"2.0","method":"session/update","params":{"sessionId":"s","update":{"sessionUpdate":"agent_message_chunk","content":{"type":"text","text":"split-"}}}}` + "\n" +
			`{"jsonrpc":"2.0","method":"session/update","params":{"sessionId":"s","update":{"sessionUpdate":"agent_message_chunk","content":{"type":"text","text":"secret"}}}}` + "\n" +
			`{"jsonrpc":"2.0","id":7,"result":{"stopReason":"end_turn"}}` + "\n",
	)
	if err := copyFrames(context.Background(), ProxyOptions{
		Mode: ModeAction, Evaluator: contentBlockingEvaluator("split-secret"),
	}, state, AgentToClient, updates, &clientOutput, &agentInput); err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(clientOutput.Bytes(), []byte("split-")) || bytes.Contains(clientOutput.Bytes(), []byte("secret")) {
		t.Fatalf("split blocked content escaped the completed-turn buffer: %s", clientOutput.String())
	}
	if !bytes.Contains(clientOutput.Bytes(), []byte(`"id":7`)) || !bytes.Contains(clientOutput.Bytes(), []byte(`"code":-32001`)) {
		t.Fatalf("completed-turn block omitted terminal prompt error: %s", clientOutput.String())
	}
}

func TestCopyFramesActionRepliesWhenClientResponseIsBlocked(t *testing.T) {
	state := &proxyState{pendingClient: map[string]string{}, pendingAgent: map[string]string{}}
	request := Message{JSONRPC: "2.0", ID: json.RawMessage("9"), Method: "fs/read_text_file"}
	if _, err := state.track(request, AgentToClient, ModeAction); err != nil {
		t.Fatal(err)
	}
	response := bytes.NewBufferString(`{"jsonrpc":"2.0","id":9,"result":{"content":"blocked-secret"}}` + "\n")
	var agentInput, clientOutput bytes.Buffer
	if err := copyFrames(context.Background(), ProxyOptions{
		Mode: ModeAction, Evaluator: contentBlockingEvaluator("blocked-secret"),
	}, state, ClientToAgent, response, &agentInput, &clientOutput); err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(agentInput.Bytes(), []byte("blocked-secret")) {
		t.Fatalf("blocked client response reached the agent: %s", agentInput.String())
	}
	if !bytes.Contains(agentInput.Bytes(), []byte(`"id":9`)) || !bytes.Contains(agentInput.Bytes(), []byte(`"code":-32001`)) {
		t.Fatalf("agent did not receive a terminal block response: %s", agentInput.String())
	}
	if clientOutput.Len() != 0 || len(state.pendingAgent) != 0 {
		t.Fatalf("blocked response left peer output or pending state: client=%q pending=%v", clientOutput.String(), state.pendingAgent)
	}
}

func TestTurnEvaluationPayloadRejectsTamperedStreams(t *testing.T) {
	frames := []json.RawMessage{
		json.RawMessage(`{"jsonrpc":"2.0","method":"session/update","params":{"sessionId":"s","update":{"sessionUpdate":"agent_message_chunk","content":{"text":"left"}}}}`),
		json.RawMessage(`{"jsonrpc":"2.0","method":"session/update","params":{"sessionId":"s","update":{"sessionUpdate":"agent_message_chunk","content":{"text":"right"}}}}`),
	}
	payload, err := BuildTurnEvaluationPayload(frames)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(payload, []byte("leftright")) {
		t.Fatalf("completed-turn stream did not join matching paths: %s", payload)
	}
	if err := ValidateTurnEvaluationPayload(payload); err != nil {
		t.Fatalf("canonical completed-turn payload was rejected: %v", err)
	}
	tampered := bytes.Replace(payload, []byte("leftright"), []byte("leftxxxxx"), 1)
	if err := ValidateTurnEvaluationPayload(tampered); err == nil {
		t.Fatal("tampered completed-turn stream was accepted")
	}
}

func TestTurnEvaluationPathsDoNotCollideWithDottedObjectKeys(t *testing.T) {
	frames := []json.RawMessage{
		json.RawMessage(`{"jsonrpc":"2.0","method":"session/update","params":{"sessionId":"s","update":{"sessionUpdate":"agent_message_chunk","content":{"text":"split-"}}}}`),
		json.RawMessage(`{"jsonrpc":"2.0","method":"session/update","params":{"update.content.text":"ignored-junk"}}`),
		json.RawMessage(`{"jsonrpc":"2.0","method":"session/update","params":{"sessionId":"s","update":{"sessionUpdate":"agent_message_chunk","content":{"text":"secret"}}}}`),
	}
	payload, err := BuildTurnEvaluationPayload(frames)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(payload, []byte("split-secret")) {
		t.Fatalf("a colliding metadata key disrupted the semantic content stream: %s", payload)
	}
}

func TestTurnEvaluationHighCardinalityToolCallsFitBoundedPayload(t *testing.T) {
	frames := make([]json.RawMessage, 0, 40_000)
	total := 0
	for index := 0; ; index++ {
		frame := json.RawMessage(fmt.Sprintf(
			`{"jsonrpc":"2.0","method":"session/update","params":{"sessionId":"s","update":{"sessionUpdate":"","toolCallId":"%d"}}}`,
			index,
		))
		if total+len(frame)+1 > MaxTurnBuffer {
			break
		}
		frames = append(frames, frame)
		total += len(frame) + 1
	}
	payload, err := BuildTurnEvaluationPayload(frames)
	if err != nil {
		t.Fatalf("high-cardinality bounded turn was not evaluable: %v", err)
	}
	if len(payload) > MaxTurnEvaluationBytes {
		t.Fatalf("payload size = %d, bound = %d", len(payload), MaxTurnEvaluationBytes)
	}
}

func TestTurnEvaluationManyArrayStringsAggregateIntoOneStream(t *testing.T) {
	const itemCount = 32_768
	items := make([]string, itemCount)
	for index := range items {
		items[index] = "x"
	}
	frame, err := json.Marshal(map[string]any{
		"jsonrpc": "2.0",
		"method":  "session/update",
		"params": map[string]any{
			"sessionId": "s",
			"update": map[string]any{
				"sessionUpdate": "agent_message_chunk",
				"content":       items,
			},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	payload, err := BuildTurnEvaluationPayload([]json.RawMessage{frame})
	if err != nil {
		t.Fatal(err)
	}
	var decoded turnEvaluationPayload
	if err := json.Unmarshal(payload, &decoded); err != nil {
		t.Fatal(err)
	}
	want := strings.Repeat("x", itemCount)
	found := false
	for _, stream := range decoded.Streams {
		if stream == want {
			found = true
			break
		}
	}
	if !found {
		t.Fatal("array string leaves were not aggregated into one completed-turn stream")
	}
}

func TestTurnEvaluationRejectsFramesBeyondBufferedTurnBound(t *testing.T) {
	frame := json.RawMessage(`{"jsonrpc":"2.0","method":"session/update","params":{"text":"` +
		strings.Repeat("a", MaxTurnBuffer) + `"}}`)
	if _, err := BuildTurnEvaluationPayload([]json.RawMessage{frame}); err == nil ||
		!strings.Contains(err.Error(), "frames exceeded their size bound") {
		t.Fatalf("oversized completed turn error = %v", err)
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
		// Action mode refuses the frame, not the whole session (GAP-1834).
		if mode == ModeAction && (err != nil || forwarded.Len() != 0) {
			t.Fatalf("action mode did not fail closed for the frame only: err=%v forwarded=%q", err, forwarded.String())
		}
		if mode == ModeObserve && (err != nil || forwarded.String() != frame) {
			t.Fatalf("observe mode did not fail open: err=%v forwarded=%q", err, forwarded.String())
		}
	}
}

func TestCopyFramesActionBlockedPromptDoesNotWedgeNextPrompt(t *testing.T) {
	input := bytes.NewBufferString(
		`{"jsonrpc":"2.0","id":1,"method":"session/prompt","params":{"sessionId":"s","prompt":[]}}` + "\n" +
			`{"jsonrpc":"2.0","id":2,"method":"session/prompt","params":{"sessionId":"s","prompt":[]}}` + "\n")
	var forwarded, rejected bytes.Buffer
	state := &proxyState{pendingClient: map[string]string{}, pendingAgent: map[string]string{}}
	evaluator := contentBlockingEvaluator(`"id":1,`)
	err := copyFrames(context.Background(), ProxyOptions{Mode: ModeAction, Evaluator: evaluator}, state, ClientToAgent, input, &forwarded, &rejected)
	if err != nil {
		t.Fatalf("second prompt after a block was refused: %v", err)
	}
	if !strings.Contains(forwarded.String(), `"id":2`) {
		t.Fatalf("second prompt was not forwarded: %s", forwarded.String())
	}
	text, stop := blockedTurn(t, rejected.Bytes(), "1")
	if text != "DefenseClaw blocked this request: test content policy" || stop != "end_turn" {
		t.Fatalf("blocked turn = %q / %q: %s", text, stop, rejected.String())
	}
}

// blockedTurn decodes the two frames that end a refused prompt turn: the
// agent_message_chunk text and the prompt result's stopReason.
func blockedTurn(t *testing.T, out []byte, id string) (string, string) {
	t.Helper()
	lines := strings.Split(strings.TrimSpace(string(out)), "\n")
	if len(lines) != 2 {
		t.Fatalf("blocked turn frames = %q, want a session/update and a result", out)
	}
	var update struct {
		Method string `json:"method"`
		Params struct {
			Update struct {
				SessionUpdate string `json:"sessionUpdate"`
				Content       struct {
					Text string `json:"text"`
				} `json:"content"`
			} `json:"update"`
		} `json:"params"`
	}
	var result struct {
		ID     json.RawMessage `json:"id"`
		Error  json.RawMessage `json:"error"`
		Result struct {
			StopReason string `json:"stopReason"`
		} `json:"result"`
	}
	if json.Unmarshal([]byte(lines[0]), &update) != nil || json.Unmarshal([]byte(lines[1]), &result) != nil {
		t.Fatalf("blocked turn frames are not JSON: %q", out)
	}
	if update.Method != "session/update" || update.Params.Update.SessionUpdate != "agent_message_chunk" ||
		string(result.ID) != id || len(result.Error) != 0 {
		t.Fatalf("blocked turn frames = %q", out)
	}
	return update.Params.Update.Content.Text, result.Result.StopReason
}

// A blocked prompt ends the turn with the reason as agent text, not a
// JSON-RPC error that Toad reports as "Agent failed to run" (GAP-1394), and
// a gateway-worded reason is not prefixed twice (GAP-1793).
func TestCopyFramesActionBlockedPromptEndsTurnWithReason(t *testing.T) {
	const reason = "DefenseClaw policy blocked this action (rule SEC-AWS-KEY: AWS access key). Do not retry it in another form."
	input := bytes.NewBufferString(`{"jsonrpc":"2.0","id":3,"method":"session/prompt","params":{"sessionId":"s1","prompt":[]}}` + "\n")
	var forwarded, rejected bytes.Buffer
	state := &proxyState{pendingClient: map[string]string{}, pendingAgent: map[string]string{}}
	evaluator := staticEvaluator{Action: "block", Reason: reason}
	if err := copyFrames(context.Background(), ProxyOptions{Mode: ModeAction, Evaluator: evaluator}, state, ClientToAgent, input, &forwarded, &rejected); err != nil {
		t.Fatal(err)
	}
	if forwarded.Len() != 0 {
		t.Fatalf("blocked prompt reached the agent: %s", forwarded.String())
	}
	if text, stop := blockedTurn(t, rejected.Bytes(), "3"); text != reason || stop != "end_turn" {
		t.Fatalf("blocked turn = %q / %q", text, stop)
	}
	var resp struct {
		Error struct {
			Message string `json:"message"`
			Data    struct {
				Details string `json:"details"`
			} `json:"data"`
		} `json:"error"`
	}
	if err := json.Unmarshal(blockResponse(json.RawMessage("4"), reason), &resp); err != nil ||
		resp.Error.Message != reason || resp.Error.Data.Details != reason {
		t.Fatalf("block response wording = %+v (%v)", resp, err)
	}
}

type staticEvaluator Verdict

func (v staticEvaluator) Evaluate(context.Context, Evaluation) (Verdict, error) {
	return Verdict(v), nil
}

// failingEvaluator fails the first `failures` evaluations, then allows.
type failingEvaluator struct{ failures, calls int }

func (e *failingEvaluator) Evaluate(context.Context, Evaluation) (Verdict, error) {
	e.calls++
	if e.calls <= e.failures {
		return Verdict{}, errors.New("context deadline exceeded (Client.Timeout exceeded while awaiting headers)")
	}
	return Verdict{Action: "allow"}, nil
}

// One slow gateway answer must not end the agent session: the guard retries
// once, then refuses only that prompt and keeps proxying (GAP-1834).
func TestCopyFramesActionEvaluationTimeoutRefusesOnlyThatFrame(t *testing.T) {
	prompt := func(id int) string {
		return fmt.Sprintf(`{"jsonrpc":"2.0","id":%d,"method":"session/prompt","params":{"sessionId":"s","prompt":[]}}`+"\n", id)
	}
	retried := &failingEvaluator{failures: 1}
	var forwarded, rejected bytes.Buffer
	state := &proxyState{pendingClient: map[string]string{}, pendingAgent: map[string]string{}}
	if err := copyFrames(context.Background(), ProxyOptions{Mode: ModeAction, Evaluator: retried}, state, ClientToAgent, bytes.NewBufferString(prompt(3)), &forwarded, &rejected); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(forwarded.String(), `"id":3`) || rejected.Len() != 0 || retried.calls != 2 {
		t.Fatalf("one failed evaluation was not retried: calls=%d forwarded=%q rejected=%q", retried.calls, forwarded.String(), rejected.String())
	}

	failing := &failingEvaluator{failures: 2}
	forwarded.Reset()
	var stderr bytes.Buffer
	state = &proxyState{pendingClient: map[string]string{}, pendingAgent: map[string]string{}}
	err := copyFrames(context.Background(), ProxyOptions{Mode: ModeAction, Evaluator: failing, Stderr: &stderr}, state, ClientToAgent,
		bytes.NewBufferString(prompt(3)+prompt(4)), &forwarded, &rejected)
	if err != nil {
		t.Fatalf("evaluation timeout ended the session: %v", err)
	}
	if strings.Contains(forwarded.String(), `"id":3`) || !strings.Contains(forwarded.String(), `"id":4`) {
		t.Fatalf("forwarded = %q, want only the prompt evaluated after the gateway answered", forwarded.String())
	}
	if text, stop := blockedTurn(t, rejected.Bytes(), "3"); text != evaluationUnavailableReason || stop != "end_turn" {
		t.Fatalf("refused turn = %q / %q", text, stop)
	}
	if !strings.Contains(stderr.String(), "evaluation unavailable") {
		t.Fatalf("stderr = %q", stderr.String())
	}
}

// Agent output refused mid-turn ends the turn for the editor and cancels it
// in the agent; the agent's late output and answer are dropped instead of
// ending the proxy as an unmatched response.
func TestCopyFramesActionAbortedTurnDropsLateAgentAnswer(t *testing.T) {
	state := &proxyState{pendingClient: map[string]string{}, pendingAgent: map[string]string{}}
	var agentInput, clientOutput bytes.Buffer
	opts := ProxyOptions{Mode: ModeAction, Evaluator: contentBlockingEvaluator("blocked-text")}
	if err := copyFrames(context.Background(), opts, state, ClientToAgent,
		bytes.NewBufferString(`{"jsonrpc":"2.0","id":5,"method":"session/prompt","params":{"sessionId":"s","prompt":[]}}`+"\n"), &agentInput, &clientOutput); err != nil {
		t.Fatal(err)
	}
	agentInput.Reset()
	chunk := func(text string) string {
		return `{"jsonrpc":"2.0","method":"session/update","params":{"sessionId":"s","update":{"sessionUpdate":"agent_message_chunk","content":{"type":"text","text":"` + text + `"}}}}` + "\n"
	}
	agentOut := chunk("blocked-text") + chunk("late") + `{"jsonrpc":"2.0","id":5,"result":{"stopReason":"cancelled"}}` + "\n"
	if err := copyFrames(context.Background(), opts, state, AgentToClient, bytes.NewBufferString(agentOut), &clientOutput, &agentInput); err != nil {
		t.Fatalf("late answer of an aborted turn ended the proxy: %v", err)
	}
	if text, stop := blockedTurn(t, clientOutput.Bytes(), "5"); text != "DefenseClaw blocked this request: test content policy" || stop != "end_turn" {
		t.Fatalf("aborted turn = %q / %q", text, stop)
	}
	if !strings.Contains(agentInput.String(), `"method":"session/cancel"`) {
		t.Fatalf("agent was not asked to cancel: %q", agentInput.String())
	}
	if len(state.abortedPrompts) != 0 || len(state.mutedSessions) != 0 {
		t.Fatalf("aborted turn state left behind: %v %v", state.abortedPrompts, state.mutedSessions)
	}
}

// notReadyEvaluator answers HTTP 503 (ErrGatewayNotReady) `failures` times.
type notReadyEvaluator struct{ failures, calls int }

func (e *notReadyEvaluator) Evaluate(context.Context, Evaluation) (Verdict, error) {
	e.calls++
	if e.calls <= e.failures {
		return Verdict{}, fmt.Errorf("%w: ACP evaluator returned HTTP 503", ErrGatewayNotReady)
	}
	return Verdict{Action: "allow"}, nil
}

// Right after acp setup turned the guard on, the gateway answered 503 until
// it reloaded the config, and the editor was told it "did not answer"
// (GAP-2135). The guard now waits before its one retry, and a refusal names
// the real cause.
func TestCopyFramesActionGatewayNotReadyRetriesAfterAPauseAndNamesTheCause(t *testing.T) {
	saved := gatewayNotReadyRetryDelay
	gatewayNotReadyRetryDelay = 20 * time.Millisecond
	t.Cleanup(func() { gatewayNotReadyRetryDelay = saved })
	prompt := `{"jsonrpc":"2.0","id":3,"method":"session/prompt","params":{"sessionId":"s","prompt":[]}}` + "\n"

	loading := &notReadyEvaluator{failures: 1}
	var forwarded, rejected bytes.Buffer
	state := &proxyState{pendingClient: map[string]string{}, pendingAgent: map[string]string{}}
	started := time.Now()
	if err := copyFrames(context.Background(), ProxyOptions{Mode: ModeAction, Evaluator: loading}, state, ClientToAgent, bytes.NewBufferString(prompt), &forwarded, &rejected); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(forwarded.String(), `"id":3`) || rejected.Len() != 0 || loading.calls != 2 {
		t.Fatalf("a 503 was not retried: calls=%d forwarded=%q rejected=%q", loading.calls, forwarded.String(), rejected.String())
	}
	if elapsed := time.Since(started); elapsed < gatewayNotReadyRetryDelay {
		t.Fatalf("retried after %v, want a pause of at least %v", elapsed, gatewayNotReadyRetryDelay)
	}

	notReady := &notReadyEvaluator{failures: 2}
	forwarded.Reset()
	state = &proxyState{pendingClient: map[string]string{}, pendingAgent: map[string]string{}}
	if err := copyFrames(context.Background(), ProxyOptions{Mode: ModeAction, Evaluator: notReady, Stderr: io.Discard}, state, ClientToAgent, bytes.NewBufferString(prompt), &forwarded, &rejected); err != nil {
		t.Fatal(err)
	}
	if text, _ := blockedTurn(t, rejected.Bytes(), "3"); text != gatewayNotReadyReason || strings.Contains(text, "did not answer") {
		t.Fatalf("refused turn = %q", text)
	}
}

// An error response with a null id is valid JSON-RPC 2.0: an editor answers
// an agent notification it could not parse that way. Action mode forwards it
// and the session goes on (GAP-0351).
func TestCopyFramesActionForwardsANullIDErrorResponse(t *testing.T) {
	nullID := `{"jsonrpc":"2.0","id":null,"error":{"code":-32601,"message":"Method not found"}}`
	input := bytes.NewBufferString(nullID + "\n" + `{"jsonrpc":"2.0","id":8,"method":"session/prompt","params":{"prompt":[]}}` + "\n")
	var forwarded, rejected bytes.Buffer
	state := &proxyState{pendingClient: map[string]string{}, pendingAgent: map[string]string{}, peerProtocolFixes: true}
	err := copyFrames(context.Background(), ProxyOptions{Mode: ModeAction, Evaluator: AllowEvaluator{}}, state, ClientToAgent, input, &forwarded, &rejected)
	if err != nil {
		t.Fatalf("a null-id error response ended the session: %v", err)
	}
	if !strings.Contains(forwarded.String(), nullID) || !strings.Contains(forwarded.String(), `"id":8`) {
		t.Fatalf("frames were not forwarded: %s", forwarded.String())
	}
}

type profileMovedEvaluator struct{}

func (profileMovedEvaluator) Evaluate(context.Context, Evaluation) (Verdict, error) {
	return Verdict{}, &BindingRefusedError{Code: RefusalProfileChanged, Profile: "act", Mode: "action",
		Message: "ACP profile does not match the configured binding for this client and agent; re-run acp setup"}
}

// A profile the administrator moved the pair away from ends the session,
// in observe mode too, and the editor is told the new profile and the
// command; it ran unchecked (GAP-0723).
func TestCopyFramesProfileMovedEndsTheSessionAndSaysWhy(t *testing.T) {
	prompt := `{"jsonrpc":"2.0","id":3,"method":"session/prompt","params":{"sessionId":"s1","prompt":[]}}` + "\n"
	var forwarded, client bytes.Buffer
	state := &proxyState{pendingClient: map[string]string{}, pendingAgent: map[string]string{}, peerProtocolFixes: true}
	err := copyFrames(context.Background(), ProxyOptions{
		Mode: ModeObserve, ClientID: "zed", AgentID: "hermes", Profile: "obs", Evaluator: profileMovedEvaluator{},
		Managed: true, Stderr: io.Discard,
		SetupCommandFor: func(profile string, mode Mode) string { return "setup --profile " + profile + " " + string(mode) },
	}, state, ClientToAgent, strings.NewReader(prompt), &forwarded, &client)
	if !errors.Is(err, ErrBindingRefused) || forwarded.Len() != 0 {
		t.Fatalf("err = %v, forwarded = %q; want the session ended before the prompt reached the agent", err, forwarded.String())
	}
	for _, text := range []string{err.Error(), client.String()} {
		if !strings.Contains(text, "from ACP profile obs to act") || !strings.Contains(text, "setup --profile act action") ||
			strings.Contains(text, "did not answer") {
			t.Fatalf("the user is not told what changed and what to run: %s", text)
		}
	}
}

// An oversized or broken frame ends an action session in words, without Go
// package or decoder text, and an observe session passes the oversized frame
// on (GAP-0685).
func TestCopyFramesOversizedAndBrokenFramesSayWhy(t *testing.T) {
	huge := `{"jsonrpc":"2.0","method":"x","params":{"pad":"` + strings.Repeat("a", MaxFrameBytes) + `"}}` + "\n"
	newState := func() *proxyState {
		return &proxyState{pendingClient: map[string]string{}, pendingAgent: map[string]string{}, peerProtocolFixes: true}
	}
	for input, want := range map[string]string{
		huge: "larger than the 1 MiB ACP frame limit",
		"{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":true}\n": "not valid ACP JSON-RPC",
		"{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":7}\n":    `"method" field has the wrong type`,
		"{\"jsonrpc\":hello}\n":                            "it is not valid JSON",
	} {
		err := copyFrames(context.Background(), ProxyOptions{Mode: ModeAction, Evaluator: AllowEvaluator{}, Stderr: io.Discard},
			newState(), ClientToAgent, strings.NewReader(input), io.Discard, io.Discard)
		if err == nil || !strings.Contains(err.Error(), want) || strings.Contains(err.Error(), "bufio") ||
			strings.Contains(err.Error(), "Go struct") || strings.Contains(err.Error(), "invalid character") {
			t.Errorf("action mode, %.40q: err = %v, want %q", input, err, want)
		}
	}
	var forwarded bytes.Buffer
	next := `{"jsonrpc":"2.0","method":"initialized"}` + "\n"
	if err := copyFrames(context.Background(), ProxyOptions{Mode: ModeObserve, Evaluator: AllowEvaluator{}, Stderr: io.Discard},
		newState(), ClientToAgent, strings.NewReader(huge+next), &forwarded, io.Discard); err != nil ||
		forwarded.String() != huge+next {
		t.Fatalf("observe mode did not pass the oversized frame on: err=%v forwarded %d bytes", err, forwarded.Len())
	}
}

type rejectingEvaluator struct{}

func (rejectingEvaluator) Evaluate(context.Context, Evaluation) (Verdict, error) {
	return Verdict{}, ErrCredentialRejected
}

// A revoked credential says so and points a managed user at the
// administrator, not at a gateway that "did not answer" and a command the
// host lacks; observe mode tells the user once that nothing is checked
// (GAP-0354).
func TestCopyFramesRejectedCredentialNamesTheRevocation(t *testing.T) {
	prompt := `{"jsonrpc":"2.0","id":3,"method":"session/prompt","params":{"sessionId":"s1","prompt":[]}}`
	for _, mode := range []Mode{ModeAction, ModeObserve} {
		var forwarded, client bytes.Buffer
		state := &proxyState{pendingClient: map[string]string{}, pendingAgent: map[string]string{}, peerProtocolFixes: true}
		opts := ProxyOptions{Mode: mode, Evaluator: rejectingEvaluator{}, Managed: true, Stderr: io.Discard}
		input := strings.NewReader(prompt + "\n" + strings.Replace(prompt, `"id":3`, `"id":4`, 1) + "\n")
		if err := copyFrames(context.Background(), opts, state, ClientToAgent, input, &forwarded, &client); err != nil {
			t.Fatal(err)
		}
		text := client.String()
		if !strings.Contains(text, "revoked") || !strings.Contains(text, "administrator") ||
			strings.Contains(text, "defenseclaw status") || strings.Contains(text, "did not answer") {
			t.Fatalf("%s mode: the editor was not told the credential was refused: %s", mode, text)
		}
		if mode == ModeObserve && (strings.Count(text, "not checking this session") != 1 || strings.Count(forwarded.String(), "session/prompt") != 2) {
			t.Fatalf("observe mode: want one notice and both prompts forwarded: client=%s agent=%s", text, forwarded.String())
		}
		if mode == ModeObserve {
			// A new thread of the same running guard is told too (Zed keeps
			// one guard for every thread).
			client.Reset()
			other := strings.NewReader(strings.Replace(strings.Replace(prompt, `"s1"`, `"s2"`, 1), `"id":3`, `"id":5`, 1) + "\n")
			if err := copyFrames(context.Background(), opts, state, ClientToAgent, other, &forwarded, &client); err != nil {
				t.Fatal(err)
			}
			if !strings.Contains(client.String(), "not checking this session") {
				t.Fatalf("a new thread was not told: %s", client.String())
			}
		}
	}
}

// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package acp

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"maps"
	"os/exec"
	"slices"
	"strings"
	"sync"
)

type Mode string

const (
	ModeObserve Mode = "observe"
	ModeAction  Mode = "action"
)

type ProxyOptions struct {
	AgentID   string
	ClientID  string
	Profile   string
	Mode      Mode
	Command   string
	Args      []string
	Stdin     io.Reader
	Stdout    io.Writer
	Stderr    io.Writer
	Evaluator Evaluator
}

// Run starts an ACP agent without a shell and mediates every NDJSON frame in
// both directions. In action mode malformed frames and evaluator failures are
// fail-closed. Observe mode records evaluations but preserves traffic.
func Run(ctx context.Context, opts ProxyOptions) error {
	if opts.Command == "" || opts.Stdin == nil || opts.Stdout == nil || opts.Stderr == nil {
		return errors.New("ACP proxy requires command, stdin, stdout, and stderr")
	}
	if opts.Mode == "" {
		opts.Mode = ModeObserve
	}
	if opts.Mode != ModeObserve && opts.Mode != ModeAction {
		return errors.New("ACP mode must be observe or action")
	}
	if opts.Evaluator == nil {
		if opts.Mode == ModeAction {
			return errors.New("ACP action mode requires an evaluator")
		}
		opts.Evaluator = AllowEvaluator{}
	}
	cmd := exec.CommandContext(ctx, opts.Command, opts.Args...)
	agentIn, err := cmd.StdinPipe()
	if err != nil {
		return err
	}
	agentOut, err := cmd.StdoutPipe()
	if err != nil {
		return err
	}
	cmd.Stderr = opts.Stderr
	if err := cmd.Start(); err != nil {
		return fmt.Errorf("start ACP agent: %w", err)
	}

	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	state := &proxyState{pendingClient: make(map[string]string), pendingAgent: make(map[string]string)}
	clientOut := &lockedWriter{writer: opts.Stdout}
	agentInput := &lockedWriter{writer: agentIn}
	clientDone := make(chan error, 1)
	agentDone := make(chan error, 1)
	go func() {
		clientDone <- copyFrames(ctx, opts, state, ClientToAgent, opts.Stdin, agentInput, clientOut)
		_ = agentIn.Close()
	}()
	go func() { agentDone <- copyFrames(ctx, opts, state, AgentToClient, agentOut, clientOut, agentInput) }()
	var copyErr error
	select {
	case copyErr = <-clientDone:
		_ = agentIn.Close()
		if copyErr != nil {
			cancel()
			_ = cmd.Process.Kill()
		} else {
			copyErr = <-agentDone
		}
	case copyErr = <-agentDone:
		// An ACP agent is allowed to exit while its editor keeps stdin open.
		// Do not wait forever for the editor-side scanner in that case.
		cancel()
		_ = agentIn.Close()
		if copyErr != nil {
			_ = cmd.Process.Kill()
		}
	}
	waitErr := cmd.Wait()
	if copyErr != nil {
		return copyErr
	}
	if waitErr != nil {
		return fmt.Errorf("ACP agent exited: %w", waitErr)
	}
	return nil
}

type proxyState struct {
	mu            sync.Mutex
	pendingClient map[string]string
	pendingAgent  map[string]string
	activePrompt  string
	activeSession string
	turnBuffer    []byte
	turnFrames    []json.RawMessage
	// abortedPrompts holds prompts the guard ended for the editor while the
	// agent was still working on them; the agent's late answer is dropped
	// instead of failing the whole proxy as an unmatched response.
	abortedPrompts map[string]string
	// mutedSessions drops the agent's further session/update output for an
	// aborted turn until its late answer arrives or a new prompt starts.
	mutedSessions map[string]struct{}
}

// errAbortedTurnFrame marks a frame of a turn the guard already ended. It is
// dropped quietly.
var errAbortedTurnFrame = errors.New("frame of an ACP turn the guard already ended")

type lockedWriter struct {
	mu     sync.Mutex
	writer io.Writer
}

func (w *lockedWriter) Write(p []byte) (int, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.writer.Write(p)
}

func (s *proxyState) track(msg Message, direction Direction, mode Mode) (string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if msg.IsRequest() {
		pending := s.pendingClient
		if direction == AgentToClient {
			pending = s.pendingAgent
		}
		if len(pending) >= MaxPendingIDs {
			return "", errors.New("too many pending ACP request IDs")
		}
		key := msg.IDKey()
		if _, exists := pending[key]; exists {
			return "", errors.New("duplicate pending ACP request ID")
		}
		pending[key] = msg.Method
		if direction == ClientToAgent && msg.Method == "session/prompt" {
			if mode == ModeAction && s.activePrompt != "" {
				delete(pending, key)
				return "", errors.New("concurrent session/prompt requests are not supported in action mode")
			}
			s.activePrompt = key
			s.activeSession = promptSessionID(msg)
			delete(s.mutedSessions, s.activeSession)
			s.turnBuffer = s.turnBuffer[:0]
			s.turnFrames = s.turnFrames[:0]
		}
		return "", nil
	}
	if msg.Method == "" {
		pending := s.pendingAgent
		if direction == AgentToClient {
			pending = s.pendingClient
		}
		method, exists := pending[msg.IDKey()]
		if !exists {
			if session, aborted := s.abortedPrompts[msg.IDKey()]; aborted && direction == AgentToClient {
				delete(s.abortedPrompts, msg.IDKey())
				delete(s.mutedSessions, session)
				return "", errAbortedTurnFrame
			}
			return "", errors.New("ACP response has no matching request")
		}
		delete(pending, msg.IDKey())
		return method, nil
	}
	if direction == AgentToClient && msg.Method == "session/update" && len(s.mutedSessions) > 0 {
		if _, muted := s.mutedSessions[promptSessionID(msg)]; muted {
			return "", errAbortedTurnFrame
		}
	}
	return "", nil
}

// promptSessionID reads params.sessionId of a session/prompt or
// session/update frame ("" when absent).
func promptSessionID(msg Message) string {
	var params struct {
		SessionID string `json:"sessionId"`
	}
	if len(msg.Params) == 0 || json.Unmarshal(msg.Params, &params) != nil {
		return ""
	}
	return params.SessionID
}

func (s *proxyState) bufferOrFlush(
	msg Message,
	direction Direction,
	matchedMethod string,
	frame []byte,
) ([]byte, json.RawMessage, string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if direction != AgentToClient || s.activePrompt == "" {
		return append(frame, '\n'), nil, "", nil
	}
	// Agent requests must be delivered after evaluation so the editor can
	// answer them; buffering them would deadlock the turn. Non-prompt
	// responses likewise belong to an independently pending client request.
	if msg.IsRequest() || (msg.Method == "" && matchedMethod != "session/prompt") {
		return append(frame, '\n'), nil, "", nil
	}
	if len(s.turnBuffer)+len(frame)+1 > MaxTurnBuffer {
		return nil, nil, "", errors.New("ACP turn output exceeded the bounded action-mode buffer")
	}
	s.turnBuffer = append(s.turnBuffer, frame...)
	s.turnBuffer = append(s.turnBuffer, '\n')
	s.turnFrames = append(s.turnFrames, append(json.RawMessage(nil), msg.Raw...))
	if matchedMethod != "session/prompt" || msg.IDKey() != s.activePrompt {
		return nil, nil, "", nil
	}
	out := append([]byte(nil), s.turnBuffer...)
	aggregate, err := BuildTurnEvaluationPayload(s.turnFrames)
	if err != nil {
		return nil, nil, "", err
	}
	session := s.activeSession
	s.turnBuffer = s.turnBuffer[:0]
	s.turnFrames = s.turnFrames[:0]
	s.activePrompt = ""
	s.activeSession = ""
	return out, aggregate, session, nil
}

// finishIfPromptResponse ends the active turn when msg is the agent's own
// answer to it, so a blocked answer is replaced instead of being recorded as
// an aborted turn whose late answer is still due. It returns the turn's
// session and whether msg was that answer.
func (s *proxyState) finishIfPromptResponse(msg Message) (string, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if msg.Method != "" || s.activePrompt == "" || msg.IDKey() != s.activePrompt {
		return "", false
	}
	session := s.activeSession
	s.activePrompt = ""
	s.activeSession = ""
	s.turnBuffer = s.turnBuffer[:0]
	s.turnFrames = s.turnFrames[:0]
	return session, true
}

// abortPrompt ends the active turn for the editor while the agent is still
// working on it. It returns the prompt ID and session; the agent's late
// answer and further output for that session are dropped (track).
func (s *proxyState) abortPrompt() (json.RawMessage, string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.activePrompt == "" {
		return nil, ""
	}
	id := json.RawMessage(s.activePrompt)
	session := s.activeSession
	delete(s.pendingClient, s.activePrompt)
	if len(s.abortedPrompts) < MaxPendingIDs {
		if s.abortedPrompts == nil {
			s.abortedPrompts = make(map[string]string)
		}
		s.abortedPrompts[s.activePrompt] = session
		if session != "" {
			if s.mutedSessions == nil {
				s.mutedSessions = make(map[string]struct{})
			}
			s.mutedSessions[session] = struct{}{}
		}
	}
	s.activePrompt = ""
	s.activeSession = ""
	s.turnBuffer = s.turnBuffer[:0]
	s.turnFrames = s.turnFrames[:0]
	return id, session
}

type turnEvaluationPayload struct {
	Frames  []json.RawMessage `json:"frames"`
	Streams map[string]string `json:"streams"`
}

// BuildTurnEvaluationPayload produces a bounded, canonical representation of
// one buffered turn. Streams concatenate string leaves at the same normalized
// JSON path, so content split at arbitrary ACP frame boundaries is inspected
// as one value before any buffered byte is released.
func BuildTurnEvaluationPayload(frames []json.RawMessage) (json.RawMessage, error) {
	if len(frames) == 0 {
		return nil, errors.New("ACP completed turn has no frames")
	}
	payload := turnEvaluationPayload{
		Frames:  make([]json.RawMessage, 0, len(frames)),
		Streams: make(map[string]string),
	}
	streamBuilders := make(map[string]*strings.Builder)
	turnBytes := 0
	for _, raw := range frames {
		if len(raw) > MaxTurnBuffer-turnBytes-1 {
			return nil, errors.New("ACP completed-turn frames exceeded their size bound")
		}
		turnBytes += len(raw) + 1
		msg, err := ParseMessage(raw)
		if err != nil {
			return nil, fmt.Errorf("invalid ACP completed-turn frame: %w", err)
		}
		payload.Frames = append(payload.Frames, append(json.RawMessage(nil), msg.Raw...))
		var value any
		if err := json.Unmarshal(msg.Raw, &value); err != nil {
			return nil, fmt.Errorf("decode ACP completed-turn frame: %w", err)
		}
		scopeKey := sha256.Sum256([]byte(turnStreamScope(msg, value)))
		if err := collectTurnStrings(value, scopeKey, streamBuilders); err != nil {
			return nil, err
		}
	}
	for key, builder := range streamBuilders {
		payload.Streams[key] = builder.String()
	}
	out, err := json.Marshal(payload)
	if err != nil {
		return nil, fmt.Errorf("encode ACP completed-turn evaluation: %w", err)
	}
	if len(out) > MaxTurnEvaluationBytes {
		return nil, errors.New("ACP completed-turn evaluation exceeded its size bound")
	}
	return out, nil
}

func turnStreamScope(msg Message, value any) string {
	if msg.Method != "session/update" {
		return "$/m:" + escapeTurnPathSegment(msg.Method)
	}
	root, _ := value.(map[string]any)
	params, _ := root["params"].(map[string]any)
	update, _ := params["update"].(map[string]any)
	sessionID, _ := params["sessionId"].(string)
	variant, _ := update["sessionUpdate"].(string)
	toolCallID, _ := update["toolCallId"].(string)
	return "$/m:session~1update/s:" + escapeTurnPathSegment(sessionID) +
		"/v:" + escapeTurnPathSegment(variant) + "/t:" + escapeTurnPathSegment(toolCallID)
}

func collectTurnStrings(value any, path [sha256.Size]byte, streams map[string]*strings.Builder) error {
	switch item := value.(type) {
	case string:
		key := hex.EncodeToString(path[:])
		builder, ok := streams[key]
		if !ok {
			if len(streams) >= MaxTurnStreams {
				return errors.New("ACP completed-turn stream count exceeded its bound")
			}
			builder = new(strings.Builder)
			streams[key] = builder
		}
		_, _ = builder.WriteString(item)
	case []any:
		childPath := advanceTurnStreamPath(path, "a:*")
		for _, child := range item {
			if err := collectTurnStrings(child, childPath, streams); err != nil {
				return err
			}
		}
	case map[string]any:
		keys := make([]string, 0, len(item))
		for key := range item {
			keys = append(keys, key)
		}
		slices.Sort(keys)
		for _, key := range keys {
			if err := collectTurnStrings(item[key], advanceTurnStreamPath(path, "o:"+key), streams); err != nil {
				return err
			}
		}
	}
	return nil
}

func advanceTurnStreamPath(parent [sha256.Size]byte, segment string) [sha256.Size]byte {
	value := make([]byte, 0, len(parent)+len(segment))
	value = append(value, parent[:]...)
	value = append(value, segment...)
	return sha256.Sum256(value)
}

func escapeTurnPathSegment(value string) string {
	value = strings.ReplaceAll(value, "~", "~0")
	return strings.ReplaceAll(value, "/", "~1")
}

// ValidateTurnEvaluationPayload rejects aggregate metadata that does not
// exactly match its frames. The gateway therefore never trusts caller-supplied
// streams that could omit or rewrite inspected output.
func ValidateTurnEvaluationPayload(raw json.RawMessage) error {
	if len(raw) == 0 || len(raw) > MaxTurnEvaluationBytes {
		return errors.New("ACP completed-turn evaluation has an invalid size")
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	var payload turnEvaluationPayload
	if err := decoder.Decode(&payload); err != nil {
		return errors.New("ACP completed-turn evaluation is malformed")
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return errors.New("ACP completed-turn evaluation has trailing JSON")
	}
	canonical, err := BuildTurnEvaluationPayload(payload.Frames)
	if err != nil {
		return err
	}
	var expected turnEvaluationPayload
	if err := json.Unmarshal(canonical, &expected); err != nil {
		return err
	}
	if !maps.Equal(payload.Streams, expected.Streams) {
		return errors.New("ACP completed-turn streams do not match their frames")
	}
	return nil
}

func (s *proxyState) reject(msg Message, direction Direction) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if direction == AgentToClient {
		delete(s.pendingAgent, msg.IDKey())
		return
	}
	delete(s.pendingClient, msg.IDKey())
	// A blocked session/prompt never reaches the agent, so its turn is over.
	// Leaving it active refused every later prompt as "concurrent".
	if msg.Method == "session/prompt" && s.activePrompt == msg.IDKey() {
		s.activePrompt = ""
		s.activeSession = ""
		s.turnBuffer = s.turnBuffer[:0]
		s.turnFrames = s.turnFrames[:0]
	}
}

// maxBlockReasonBytes bounds the policy reason echoed to the editor.
const maxBlockReasonBytes = 512

// evaluationUnavailableReason is what the editor sees for a frame the guard
// refused because the gateway did not answer its evaluation. Only that frame
// is refused; the session stays usable (GAP-1834).
const evaluationUnavailableReason = "DefenseClaw could not check this step because the gateway did not answer, " +
	"so it was not delivered. Try again; run defenseclaw status if it keeps happening."

func boundedBlockReason(reason string) string {
	reason = strings.TrimSpace(reason)
	if len(reason) > maxBlockReasonBytes {
		reason = strings.ToValidUTF8(reason[:maxBlockReasonBytes], "") + "..."
	}
	return reason
}

// blockMessage is the sentence the user reads for a block. The gateway words
// policy blocks the way the hook connectors do ("DefenseClaw policy blocked
// this action (rule ...). Do not retry it in another form."), so such a
// reason is shown as is instead of behind a second "DefenseClaw blocked"
// prefix (GAP-1793).
func blockMessage(reason string) string {
	reason = boundedBlockReason(reason)
	switch {
	case reason == "":
		return "DefenseClaw blocked this request."
	case strings.HasPrefix(reason, "DefenseClaw"):
		return reason
	}
	return "DefenseClaw blocked this request: " + reason
}

// blockResponse is the JSON-RPC error a peer sees for a blocked request or
// response other than a prompt turn. The policy reason goes in both the
// message (Zed) and data.details (Toad), so the user learns why the request
// was refused instead of a bare failure.
func blockResponse(id json.RawMessage, reason string) []byte {
	message := "blocked by DefenseClaw ACP policy"
	reason = boundedBlockReason(reason)
	if reason == "" {
		return ErrorResponse(id, -32001, message)
	}
	if len(id) == 0 {
		id = json.RawMessage("null")
	}
	payload := struct {
		JSONRPC string          `json:"jsonrpc"`
		ID      json.RawMessage `json:"id"`
		Error   struct {
			Code    int    `json:"code"`
			Message string `json:"message"`
			Data    struct {
				Details string `json:"details"`
			} `json:"data"`
		} `json:"error"`
	}{JSONRPC: "2.0", ID: id}
	payload.Error.Code = -32001
	payload.Error.Message = message + ": " + reason
	if strings.HasPrefix(reason, "DefenseClaw") {
		payload.Error.Message = reason
	}
	payload.Error.Data.Details = blockMessage(reason)
	out, _ := json.Marshal(payload)
	return out
}

// blockedTurnFrames ends a session/prompt turn the guard refused. A JSON-RPC
// error on session/prompt made Toad report "Agent failed to run ... install
// an ACP adapter" under the reason although the session was fine
// (GAP-1394). The turn instead ends normally: one agent_message_chunk with
// the block message, then the prompt's result with stopReason end_turn. The
// "refusal" stop reason is not used because an editor may rewind the user's
// message on it and hide the reason. Without a session ID no session/update
// can be addressed, so the JSON-RPC error remains the fallback.
func blockedTurnFrames(id json.RawMessage, sessionID, reason string) []byte {
	if sessionID == "" {
		return append(blockResponse(id, reason), '\n')
	}
	type textContent struct {
		Type string `json:"type"`
		Text string `json:"text"`
	}
	type update struct {
		SessionUpdate string      `json:"sessionUpdate"`
		Content       textContent `json:"content"`
	}
	notification := struct {
		JSONRPC string `json:"jsonrpc"`
		Method  string `json:"method"`
		Params  struct {
			SessionID string `json:"sessionId"`
			Update    update `json:"update"`
		} `json:"params"`
	}{JSONRPC: "2.0", Method: "session/update"}
	notification.Params.SessionID = sessionID
	notification.Params.Update = update{
		SessionUpdate: "agent_message_chunk",
		Content:       textContent{Type: "text", Text: blockMessage(reason)},
	}
	result := struct {
		JSONRPC string          `json:"jsonrpc"`
		ID      json.RawMessage `json:"id"`
		Result  struct {
			StopReason string `json:"stopReason"`
		} `json:"result"`
	}{JSONRPC: "2.0", ID: id}
	result.Result.StopReason = "end_turn"
	first, _ := json.Marshal(notification)
	second, _ := json.Marshal(result)
	out := append(first, '\n')
	out = append(out, second...)
	return append(out, '\n')
}

// cancelNotification asks the agent to stop a turn the guard ended early.
func cancelNotification(sessionID string) []byte {
	out, _ := json.Marshal(struct {
		JSONRPC string            `json:"jsonrpc"`
		Method  string            `json:"method"`
		Params  map[string]string `json:"params"`
	}{JSONRPC: "2.0", Method: "session/cancel", Params: map[string]string{"sessionId": sessionID}})
	return append(out, '\n')
}

func logf(w io.Writer, format string, args ...any) {
	if w != nil {
		fmt.Fprintf(w, format, args...)
	}
}

// evaluate asks the evaluator once and, in action mode, once more after a
// failure other than a mode mismatch: one slow gateway answer (a client
// timeout on a busy host) ended the whole agent session (GAP-1834).
func evaluate(ctx context.Context, opts ProxyOptions, in Evaluation) (Verdict, error) {
	verdict, err := opts.Evaluator.Evaluate(ctx, in)
	if err == nil || opts.Mode != ModeAction || errors.Is(err, ErrModeMismatch) || ctx.Err() != nil {
		return verdict, err
	}
	return opts.Evaluator.Evaluate(ctx, in)
}

func copyFrames(ctx context.Context, opts ProxyOptions, state *proxyState, direction Direction, src io.Reader, dst, rejectDst io.Writer) error {
	scanner := bufio.NewScanner(src)
	buf := make([]byte, 64<<10)
	scanner.Buffer(buf, MaxFrameBytes+1)
	for scanner.Scan() {
		frame := append([]byte(nil), scanner.Bytes()...)
		msg, err := ParseMessage(frame)
		matchedMethod := ""
		if err == nil {
			matchedMethod, err = state.track(msg, direction, opts.Mode)
		}
		if errors.Is(err, errAbortedTurnFrame) {
			continue
		}
		if err != nil {
			if opts.Mode == ModeAction {
				return fmt.Errorf("ACP protocol blocked: %w", err)
			}
			logf(opts.Stderr, "[defenseclaw-acp] observe protocol finding: %v\n", err)
			if _, writeErr := fmt.Fprintln(dst, string(frame)); writeErr != nil {
				return writeErr
			}
			continue
		}
		verdict, evalErr := evaluate(ctx, opts, Evaluation{
			Profile: opts.Profile, Mode: opts.Mode, AgentID: opts.AgentID, ClientID: opts.ClientID,
			Direction: direction, Surface: Classify(msg, direction), Method: msg.Method, Payload: msg.Raw,
		})
		if evalErr != nil {
			if errors.Is(evalErr, ErrModeMismatch) {
				return fmt.Errorf("ACP evaluation unavailable: %w", evalErr)
			}
			if opts.Mode == ModeAction {
				// Fail closed for this frame only, exactly as for a block.
				logf(opts.Stderr, "[defenseclaw-acp] evaluation unavailable, refused %s %s: %v\n", direction, msg.Method, evalErr)
				verdict = Verdict{Action: "block", Reason: evaluationUnavailableReason}
			} else {
				logf(opts.Stderr, "[defenseclaw-acp] observe evaluation error: %v\n", evalErr)
				verdict = Verdict{Action: "allow"}
			}
		}
		if verdict.Action == "block" || verdict.Action == "confirm" {
			if opts.Mode == ModeAction {
				if err := writeBlock(state, direction, msg, verdict.Reason, dst, rejectDst); err != nil {
					return err
				}
				continue
			}
			logf(opts.Stderr, "[defenseclaw-acp] would block %s %s: %s\n", direction, msg.Method, verdict.Reason)
		}
		if opts.Mode == ModeAction {
			out, aggregate, session, bufferErr := state.bufferOrFlush(msg, direction, matchedMethod, frame)
			if bufferErr != nil {
				return bufferErr
			}
			if len(aggregate) > 0 {
				turnVerdict, turnErr := evaluate(ctx, opts, Evaluation{
					Profile: opts.Profile, Mode: opts.Mode, AgentID: opts.AgentID, ClientID: opts.ClientID,
					Direction: AgentToClient, Surface: SurfaceOutput, Method: "session/update",
					Payload: aggregate, Aggregate: true,
				})
				if turnErr != nil {
					if errors.Is(turnErr, ErrModeMismatch) {
						return fmt.Errorf("ACP completed-turn evaluation unavailable: %w", turnErr)
					}
					logf(opts.Stderr, "[defenseclaw-acp] completed-turn evaluation unavailable, refused the turn: %v\n", turnErr)
					turnVerdict = Verdict{Action: "block", Reason: evaluationUnavailableReason}
				}
				if turnVerdict.Action == "block" || turnVerdict.Action == "confirm" {
					if _, err := dst.Write(blockedTurnFrames(msg.ID, session, turnVerdict.Reason)); err != nil {
						return err
					}
					continue
				}
			}
			if len(out) > 0 {
				if _, err := dst.Write(out); err != nil {
					return err
				}
			}
		} else if _, err := fmt.Fprintln(dst, string(frame)); err != nil {
			return err
		}
	}
	if err := scanner.Err(); err != nil {
		return fmt.Errorf("read ACP frame: %w", err)
	}
	return nil
}

// writeBlock answers a frame refused in action mode. dst is the peer the
// frame was travelling to and rejectDst the peer that sent it.
func writeBlock(state *proxyState, direction Direction, msg Message, reason string, dst, rejectDst io.Writer) error {
	if direction == AgentToClient {
		// The agent's own answer to the prompt: end the turn in its place.
		if session, ok := state.finishIfPromptResponse(msg); ok {
			_, err := dst.Write(blockedTurnFrames(msg.ID, session, reason))
			return err
		}
	}
	switch {
	case msg.IsRequest() && direction == ClientToAgent && msg.Method == "session/prompt":
		state.reject(msg, direction)
		if _, err := rejectDst.Write(blockedTurnFrames(msg.ID, promptSessionID(msg), reason)); err != nil {
			return err
		}
	case msg.IsRequest():
		state.reject(msg, direction)
		if _, err := fmt.Fprintln(rejectDst, string(blockResponse(msg.ID, reason))); err != nil {
			return err
		}
	case msg.Method == "":
		// A response belongs to the peer in the direction it was already
		// travelling. Never drop it silently: return a terminal JSON-RPC
		// error for the same pending ID.
		if _, err := fmt.Fprintln(dst, string(blockResponse(msg.ID, reason))); err != nil {
			return err
		}
	}
	if direction != AgentToClient {
		return nil
	}
	// Agent output was refused mid-turn: end the turn for the editor and ask
	// the agent to stop; its late answer is dropped (track).
	promptID, session := state.abortPrompt()
	if len(promptID) == 0 {
		return nil
	}
	if _, err := dst.Write(blockedTurnFrames(promptID, session, reason)); err != nil {
		return err
	}
	if session != "" {
		if _, err := rejectDst.Write(cancelNotification(session)); err != nil {
			return err
		}
	}
	return nil
}

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
	"time"
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
	// Managed marks the guard of a managed enrollment, whose user has no
	// DefenseClaw command to run and is pointed at the administrator.
	Managed bool
	// SetupCommand writes this editor entry again ("" when unknown).
	SetupCommand string
	// SetupCommandFor is SetupCommand for another profile or mode, nil
	// when unknown.
	SetupCommandFor func(profile string, mode Mode) string
}

// setupCommandFor is the command that sets this editor entry up for profile
// in mode.
func (o ProxyOptions) setupCommandFor(profile string, mode Mode) string {
	if o.SetupCommandFor != nil {
		return o.SetupCommandFor(profile, mode)
	}
	command := strings.TrimSuffix(o.SetupCommand, " --activate")
	if command != "" && profile != o.Profile {
		command = strings.Replace(command, " --profile "+o.Profile, " --profile "+profile, 1)
	}
	if command != "" && mode == ModeAction {
		command += " --activate"
	}
	return command
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
	state := &proxyState{
		pendingClient: make(map[string]string), pendingAgent: make(map[string]string),
		peerProtocolFixes: !secureClientHost(),
	}
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
	// peerProtocolFixes accepts null-id error responses and words a session
	// the guard ends without internals (GAP-0351). Off on a Secure Client
	// host, which keeps the guard of main (issue #1092).
	peerProtocolFixes bool
	// uncheckedNotified holds the sessions an observe-mode user was told
	// that nothing is being checked, until checking works again. One flag
	// for the whole guard told only the first thread: an editor that keeps
	// one guard for every thread (Zed) showed nothing in a new thread after
	// a revoke (GAP-0354).
	uncheckedNotified map[string]bool
}

// checkingResumed re-arms the unchecked notice after an evaluation worked.
func (s *proxyState) checkingResumed() {
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(s.uncheckedNotified) > 0 {
		s.uncheckedNotified = nil
	}
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
	if msg.Method == "" && s.peerProtocolFixes && msg.IsNullIDError() {
		// An error report for a frame whose id the peer could not read: it
		// answers nothing pending and is forwarded as is.
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

// gatewayNotReadyReason is the same refusal when the gateway did answer, but
// with HTTP 503: it is not ready to check ACP traffic yet (GAP-2135).
const gatewayNotReadyReason = "DefenseClaw could not check this step because the gateway is not ready to check " +
	"ACP traffic yet (it may still be loading a setup change), so it was not delivered. Try again in a few " +
	"seconds; run defenseclaw acp status if it keeps happening."

// gatewayNotReadyRetryDelay is the pause before the one retry of a 503: the
// gateway applies a config change about half a second after it is saved.
var gatewayNotReadyRetryDelay = time.Second

func unavailableReason(err error) string {
	if errors.Is(err, ErrGatewayNotReady) {
		return gatewayNotReadyReason
	}
	return evaluationUnavailableReason
}

// refusalReason is what the editor sees for a frame refused because it
// could not be evaluated. A revoked credential used to read as a gateway
// that did not answer, and a managed user was told to run commands the host
// does not have, so they retried for ever (GAP-0354). Secure Client hosts
// keep the wording of main.
func (s *proxyState) refusalReason(opts ProxyOptions, err error) string {
	if !s.peerProtocolFixes {
		return unavailableReason(err)
	}
	const prefix = "DefenseClaw could not check this step because "
	next := "if it keeps happening, contact your administrator."
	switch {
	case errors.Is(err, ErrACPDisabled) && opts.Managed:
		return prefix + "your administrator switched ACP checking off, so it was not delivered. Contact your administrator."
	case errors.Is(err, ErrACPDisabled):
		return prefix + "the ACP guard is turned off (acp.enabled is false), so it was not delivered. " +
			"Turn it on again with defenseclaw acp setup, or remove this editor entry."
	case errors.Is(err, ErrCredentialOtherAccount):
		return prefix + "the ACP credential this editor entry uses was issued to another account, not to you, " +
			"so it was not delivered. Ask your administrator to enroll you for this editor and agent."
	case errors.Is(err, ErrCredentialRejected) && opts.Managed:
		return prefix + "the gateway did not accept this editor's ACP credential: your administrator may have revoked " +
			"your access. It was not delivered. Ask your administrator to enroll you again; running setup cannot restore " +
			"a revoked credential."
	case errors.Is(err, ErrCredentialRejected):
		rerun := "Run defenseclaw acp setup for this editor and agent again."
		if opts.SetupCommand != "" {
			rerun = "Run '" + opts.SetupCommand + "' again."
		}
		return prefix + "the gateway did not accept the ACP token, so it was not delivered. " + rerun
	case !opts.Managed:
		return unavailableReason(err)
	case errors.Is(err, ErrGatewayNotReady):
		return prefix + "the gateway is not ready to check ACP traffic yet (it may still be loading a setup change), " +
			"so it was not delivered. Try again in a few seconds; " + next
	}
	return prefix + "the gateway did not answer, so it was not delivered. Try again; " + next
}

// noticeUnchecked tells an observe-mode user, once, that the gateway refused
// the guard and nothing is being checked: observe mode lets the session go
// on, and the user was never told (GAP-0354). It answers the first prompt
// after the refusal with an agent message in that prompt's session.
func (s *proxyState) noticeUnchecked(opts ProxyOptions, direction Direction, msg Message, err error, client io.Writer) {
	if !s.peerProtocolFixes || direction != ClientToAgent || msg.Method != "session/prompt" ||
		!(errors.Is(err, ErrCredentialRejected) || errors.Is(err, ErrACPDisabled) || errors.Is(err, ErrCredentialOtherAccount)) {
		return
	}
	session := promptSessionID(msg)
	if session == "" {
		return
	}
	s.mu.Lock()
	sent := s.uncheckedNotified[session]
	if !sent {
		if s.uncheckedNotified == nil {
			s.uncheckedNotified = map[string]bool{}
		}
		if len(s.uncheckedNotified) < MaxPendingIDs {
			s.uncheckedNotified[session] = true
		}
	}
	s.mu.Unlock()
	if sent {
		return
	}
	why := "the gateway did not accept the ACP token"
	switch {
	case errors.Is(err, ErrACPDisabled):
		why = "ACP checking is switched off"
	case errors.Is(err, ErrCredentialOtherAccount):
		why = "the ACP credential this editor entry uses was issued to another account"
	case opts.Managed:
		why = "the gateway did not accept this editor's ACP credential (your administrator may have revoked your access)"
	}
	next := "Contact your administrator."
	switch {
	case opts.Managed && errors.Is(err, ErrCredentialRejected):
		// Setup cannot restore a revoked credential (GAP-0905).
		next = "Ask your administrator to enroll you again; running setup cannot restore a revoked credential."
	case errors.Is(err, ErrCredentialOtherAccount):
		next = "Ask your administrator to enroll you for this editor and agent."
	case !opts.Managed && opts.SetupCommand != "":
		next = "Run '" + opts.SetupCommand + "' again."
	}
	_, _ = client.Write(agentMessageChunk(session, "DefenseClaw is not checking this session: "+why+
		", so your messages reach the agent unchecked. "+next))
}

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
	result := struct {
		JSONRPC string          `json:"jsonrpc"`
		ID      json.RawMessage `json:"id"`
		Result  struct {
			StopReason string `json:"stopReason"`
		} `json:"result"`
	}{JSONRPC: "2.0", ID: id}
	result.Result.StopReason = "end_turn"
	second, _ := json.Marshal(result)
	out := agentMessageChunk(sessionID, blockMessage(reason))
	out = append(out, second...)
	return append(out, '\n')
}

// agentMessageChunk is a session/update notification that shows text as an
// agent message in sessionID, with its newline.
func agentMessageChunk(sessionID, text string) []byte {
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
		Content:       textContent{Type: "text", Text: text},
	}
	out, _ := json.Marshal(notification)
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
	if err == nil || opts.Mode != ModeAction || errors.Is(err, ErrModeMismatch) || errors.Is(err, ErrBindingRefused) ||
		errors.Is(err, ErrCredentialOtherAccount) || ctx.Err() != nil {
		return verdict, err
	}
	if errors.Is(err, ErrGatewayNotReady) {
		timer := time.NewTimer(gatewayNotReadyRetryDelay)
		select {
		case <-ctx.Done():
			timer.Stop()
			return verdict, err
		case <-timer.C:
		}
	}
	return opts.Evaluator.Evaluate(ctx, in)
}

func copyFrames(ctx context.Context, opts ProxyOptions, state *proxyState, direction Direction, src io.Reader, dst, rejectDst io.Writer) error {
	frames := newFrameReader(src, state.peerProtocolFixes)
	parse := ParseMessage
	if state.peerProtocolFixes {
		parse = ParseMessageAllowingNullIDErrors
	}
	for {
		frame, tooLong, readErr := frames.next()
		if errors.Is(readErr, io.EOF) {
			return nil
		}
		if readErr != nil {
			return fmt.Errorf("read ACP frame: %w", readErr)
		}
		if tooLong {
			// The Go text was "bufio.Scanner: token too long", in both
			// modes (GAP-0685).
			if opts.Mode == ModeAction {
				return &protocolEnded{message: fmt.Sprintf("DefenseClaw ended this ACP session because the %s sent a message "+
					"larger than the 1 MiB ACP frame limit", acpPeerName(direction))}
			}
			logf(opts.Stderr, "[defenseclaw-acp] observe protocol finding: the %s sent a message larger than the 1 MiB ACP frame limit; passed on unchecked\n",
				acpPeerName(direction))
			if err := frames.passThrough(frame, dst); err != nil {
				return err
			}
			continue
		}
		msg, err := parse(frame)
		matchedMethod := ""
		if err == nil {
			matchedMethod, err = state.track(msg, direction, opts.Mode)
		}
		if errors.Is(err, errAbortedTurnFrame) {
			continue
		}
		if err != nil {
			if opts.Mode == ModeAction && state.peerProtocolFixes {
				return &protocolEnded{err: err, message: fmt.Sprintf("DefenseClaw ended this ACP session because the %s sent a message "+
					"that is not valid ACP JSON-RPC (%s)", acpPeerName(direction), plainProtocolReason(err))}
			}
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
		if evalErr != nil && state.peerProtocolFixes && ctx.Err() != nil {
			// The session is ending: an evaluation the shutdown cancelled
			// is not a gateway problem to report (GAP-0351).
			return nil
		}
		if evalErr == nil && state.peerProtocolFixes {
			state.checkingResumed()
		}
		if evalErr != nil {
			if errors.Is(evalErr, ErrBindingRefused) && state.peerProtocolFixes {
				return endSessionTelling(direction, msg, bindingRefusedError(opts, evalErr), rejectDst)
			}
			if errors.Is(evalErr, ErrModeMismatch) && state.peerProtocolFixes {
				return endSessionTelling(direction, msg, modeDriftError(opts), rejectDst)
			}
			if errors.Is(evalErr, ErrModeMismatch) {
				return fmt.Errorf("ACP evaluation unavailable: %w", evalErr)
			}
			if opts.Mode == ModeAction {
				// Fail closed for this frame only, exactly as for a block.
				logf(opts.Stderr, "[defenseclaw-acp] evaluation unavailable, refused %s %s: %v\n", direction, msg.Method, evalErr)
				verdict = Verdict{Action: "block", Reason: state.refusalReason(opts, evalErr)}
			} else {
				logf(opts.Stderr, "[defenseclaw-acp] observe evaluation error: %v\n", evalErr)
				verdict = Verdict{Action: "allow"}
				state.noticeUnchecked(opts, direction, msg, evalErr, rejectDst)
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
					if errors.Is(turnErr, ErrBindingRefused) && state.peerProtocolFixes {
						return bindingRefusedError(opts, turnErr)
					}
					if errors.Is(turnErr, ErrModeMismatch) && state.peerProtocolFixes {
						return modeDriftError(opts)
					}
					if errors.Is(turnErr, ErrModeMismatch) {
						return fmt.Errorf("ACP completed-turn evaluation unavailable: %w", turnErr)
					}
					logf(opts.Stderr, "[defenseclaw-acp] completed-turn evaluation unavailable, refused the turn: %v\n", turnErr)
					turnVerdict = Verdict{Action: "block", Reason: state.refusalReason(opts, turnErr)}
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
}

// protocolEnded ends a session over a frame that is not valid ACP, in words.
type protocolEnded struct {
	message string
	err     error
}

func (e *protocolEnded) Error() string { return e.message }
func (e *protocolEnded) Unwrap() error { return e.err }

// plainProtocolReason says why a frame is not valid ACP JSON-RPC without
// the Go decoder text ("invalid character 'h' in literal true", "cannot
// unmarshal number into Go struct field Message.method") (GAP-0685).
func plainProtocolReason(err error) string {
	var syntax *json.SyntaxError
	var mistyped *json.UnmarshalTypeError
	switch {
	case errors.As(err, &syntax):
		return "it is not valid JSON"
	case errors.As(err, &mistyped):
		field := mistyped.Field
		if dot := strings.LastIndex(field, "."); dot >= 0 {
			field = field[dot+1:]
		}
		if field == "" {
			return "a value has the wrong type"
		}
		return fmt.Sprintf("its %q field has the wrong type", field)
	case errors.Is(err, ErrBatchUnsupported):
		return "it is a JSON-RPC batch, which ACP does not use"
	}
	text := strings.TrimPrefix(err.Error(), ErrInvalidMessage.Error()+": ")
	switch {
	case text == ErrInvalidMessage.Error():
		return "it is not a JSON-RPC object"
	case text == "frame size 0":
		return "it is empty"
	}
	return text
}

// frameReader reads newline-delimited ACP frames. Outside Secure Client a
// frame larger than MaxFrameBytes is reported instead of ending the read,
// so observe mode can pass it on; Secure Client keeps the scanner of main.
type frameReader struct {
	scanner *bufio.Scanner
	reader  *bufio.Reader
	// rest marks a too-long frame whose remaining bytes are still unread.
	rest bool
}

func newFrameReader(src io.Reader, report bool) *frameReader {
	if !report {
		scanner := bufio.NewScanner(src)
		scanner.Buffer(make([]byte, 64<<10), MaxFrameBytes+1)
		return &frameReader{scanner: scanner}
	}
	return &frameReader{reader: bufio.NewReaderSize(src, 64<<10)}
}

// next returns the next frame without its line ending, or io.EOF. A frame
// longer than MaxFrameBytes comes back as its first bytes with tooLong set.
func (f *frameReader) next() (frame []byte, tooLong bool, err error) {
	if f.scanner != nil {
		if f.scanner.Scan() {
			return append([]byte(nil), f.scanner.Bytes()...), false, nil
		}
		if err := f.scanner.Err(); err != nil {
			return nil, false, err
		}
		return nil, false, io.EOF
	}
	if f.rest {
		if err := f.passThrough(nil, io.Discard); err != nil {
			return nil, false, err
		}
	}
	var line []byte
	for {
		chunk, readErr := f.reader.ReadSlice('\n')
		line = append(line, chunk...)
		switch {
		case readErr == nil:
			line = trimFrameEnd(line)
			return line, len(line) > MaxFrameBytes, nil
		case errors.Is(readErr, bufio.ErrBufferFull):
			if len(line) > MaxFrameBytes {
				f.rest = true
				return line, true, nil
			}
		case errors.Is(readErr, io.EOF):
			if len(line) == 0 {
				return nil, false, io.EOF
			}
			line = trimFrameEnd(line)
			return line, len(line) > MaxFrameBytes, nil
		default:
			return nil, false, readErr
		}
	}
}

// passThrough writes a too-long frame to dst unchanged: what next returned
// and the rest of its line.
func (f *frameReader) passThrough(head []byte, dst io.Writer) error {
	if locked, ok := dst.(*lockedWriter); ok {
		// One frame: the other direction must not write inside it.
		locked.mu.Lock()
		defer locked.mu.Unlock()
		dst = locked.writer
	}
	if _, err := dst.Write(head); err != nil {
		return err
	}
	for f.rest {
		chunk, err := f.reader.ReadSlice('\n')
		if _, writeErr := dst.Write(chunk); writeErr != nil {
			return writeErr
		}
		switch {
		case err == nil, errors.Is(err, io.EOF):
			f.rest = false
			if err == nil {
				return nil
			}
		case !errors.Is(err, bufio.ErrBufferFull):
			return err
		}
	}
	_, err := dst.Write([]byte{'\n'})
	return err
}

// trimFrameEnd drops a line ending, as bufio.ScanLines does.
func trimFrameEnd(line []byte) []byte {
	line = bytes.TrimSuffix(line, []byte{'\n'})
	return bytes.TrimSuffix(line, []byte{'\r'})
}

// modeDriftError ends a session whose profile changed mode centrally. Its
// text named "managed setup", a command no host has, and the editor showed
// only "Agent failed to run" (GAP-0355): it now names the setup command to
// run, with --activate when the profile moved to action mode.
func modeDriftError(opts ProxyOptions) error {
	now, command := "action", opts.setupCommandFor(opts.Profile, ModeAction)
	if opts.Mode == ModeAction {
		now, command = "observe", opts.setupCommandFor(opts.Profile, ModeObserve)
	}
	who := "the ACP mode of profile " + opts.Profile + " changed to " + now
	if opts.Managed {
		who = "your administrator changed the ACP mode of profile " + opts.Profile + " to " + now
	}
	next := "run the setup command of this editor entry again"
	if strings.TrimSpace(opts.SetupCommand) != "" {
		next = "run '" + command + "' to set this editor entry up again"
	}
	return &modeDrift{message: "DefenseClaw ended this ACP session because " + who + "; " + next}
}

// modeDrift is ErrModeMismatch in words for the user.
type modeDrift struct{ message string }

func (e *modeDrift) Error() string { return e.message }
func (e *modeDrift) Unwrap() error { return ErrModeMismatch }

// bindingRefused is ErrBindingRefused in words for the user.
type bindingRefused struct{ message string }

func (e *bindingRefused) Error() string { return e.message }
func (e *bindingRefused) Unwrap() error { return ErrBindingRefused }

// bindingRefusedError ends a session whose editor entry the gateway no
// longer admits, in both modes: observe mode kept running unchecked, and
// action mode said the gateway did not answer (GAP-0723, GAP-0354).
func bindingRefusedError(opts ProxyOptions, err error) error {
	refusal := &BindingRefusedError{Code: RefusalBinding}
	errors.As(err, &refusal)
	pair := opts.ClientID + "/" + opts.AgentID
	command := func(profile string, mode Mode) string {
		if text := opts.setupCommandFor(profile, mode); text != "" {
			return "'" + text + "'"
		}
		return "the setup command of this editor entry"
	}
	const prefix = "DefenseClaw ended this ACP session because "
	switch {
	case refusal.Code == RefusalProfileChanged && refusal.Profile != "":
		mode := Mode(refusal.Mode)
		if mode == "" {
			mode = opts.Mode
		}
		if opts.Managed {
			return &bindingRefused{message: fmt.Sprintf("%syour administrator moved %s from ACP profile %s to %s (%s mode). "+
				"Once they enroll you for %s, run %s", prefix, pair, opts.Profile, refusal.Profile, mode, refusal.Profile, command(refusal.Profile, mode))}
		}
		return &bindingRefused{message: fmt.Sprintf("%s%s now uses ACP profile %s (%s mode), not %s; run %s",
			prefix, pair, refusal.Profile, mode, opts.Profile, command(refusal.Profile, mode))}
	case refusal.Code == RefusalCredentialBinding && refusal.CredentialProfile != "":
		return &bindingRefused{message: fmt.Sprintf("%sthe ACP credential of this editor entry is enrolled for profile %s, not %s. "+
			"Ask your administrator to enroll you for %s, then run %s",
			prefix, refusal.CredentialProfile, opts.Profile, opts.Profile, command(opts.Profile, opts.Mode))}
	case opts.Managed:
		return &bindingRefused{message: fmt.Sprintf("%sthe gateway refused this editor entry for %s (%s). Contact your administrator.",
			prefix, pair, strings.TrimSuffix(refusal.Message, "; re-run acp setup"))}
	}
	return &bindingRefused{message: fmt.Sprintf("%sthe gateway refused this editor entry for %s (%s); run %s",
		prefix, pair, strings.TrimSuffix(refusal.Message, "; re-run acp setup"), command(opts.Profile, opts.Mode))}
}

// maxSessionEndNoticeBytes bounds the reason a session-ending notice shows.
const maxSessionEndNoticeBytes = 2048

// endSessionTelling answers the editor request that ended the session with
// the reason, so the editor shows it, and returns the reason: an editor
// shows the agent's stderr only in its log.
func endSessionTelling(direction Direction, msg Message, reason error, client io.Writer) error {
	if direction != ClientToAgent || !msg.IsRequest() {
		return reason
	}
	text := reason.Error()
	if len(text) > maxSessionEndNoticeBytes {
		text = strings.ToValidUTF8(text[:maxSessionEndNoticeBytes], "") + "..."
	}
	if session := promptSessionID(msg); msg.Method == "session/prompt" && session != "" {
		result, _ := json.Marshal(struct {
			JSONRPC string          `json:"jsonrpc"`
			ID      json.RawMessage `json:"id"`
			Result  struct {
				StopReason string `json:"stopReason"`
			} `json:"result"`
		}{JSONRPC: "2.0", ID: msg.ID, Result: struct {
			StopReason string `json:"stopReason"`
		}{StopReason: "end_turn"}})
		_, _ = client.Write(append(agentMessageChunk(session, text), append(result, '\n')...))
		return reason
	}
	_, _ = client.Write(append(ErrorResponse(msg.ID, -32001, text), '\n'))
	return reason
}

// acpPeerName names the peer that sent a frame travelling in direction.
func acpPeerName(direction Direction) string {
	if direction == AgentToClient {
		return "agent"
	}
	return "editor"
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

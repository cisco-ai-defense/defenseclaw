// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package acp

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os/exec"
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
	turnBuffer    []byte
}

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
			s.turnBuffer = s.turnBuffer[:0]
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
			return "", errors.New("ACP response has no matching request")
		}
		delete(pending, msg.IDKey())
		return method, nil
	}
	return "", nil
}

func (s *proxyState) bufferOrFlush(msg Message, direction Direction, matchedMethod string, frame []byte) ([]byte, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if direction != AgentToClient || s.activePrompt == "" {
		return append(frame, '\n'), nil
	}
	// Agent requests must be delivered after evaluation so the editor can
	// answer them; buffering them would deadlock the turn. Non-prompt
	// responses likewise belong to an independently pending client request.
	if msg.IsRequest() || (msg.Method == "" && matchedMethod != "session/prompt") {
		return append(frame, '\n'), nil
	}
	if len(s.turnBuffer)+len(frame)+1 > MaxTurnBuffer {
		return nil, errors.New("ACP turn output exceeded the bounded action-mode buffer")
	}
	s.turnBuffer = append(s.turnBuffer, frame...)
	s.turnBuffer = append(s.turnBuffer, '\n')
	if matchedMethod != "session/prompt" || msg.IDKey() != s.activePrompt {
		return nil, nil
	}
	out := append([]byte(nil), s.turnBuffer...)
	s.turnBuffer = s.turnBuffer[:0]
	s.activePrompt = ""
	return out, nil
}

func (s *proxyState) abortPrompt() json.RawMessage {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.activePrompt == "" {
		return nil
	}
	id := json.RawMessage(s.activePrompt)
	delete(s.pendingClient, s.activePrompt)
	s.activePrompt = ""
	s.turnBuffer = s.turnBuffer[:0]
	return id
}

func (s *proxyState) reject(msg Message, direction Direction) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if direction == AgentToClient {
		delete(s.pendingAgent, msg.IDKey())
	} else {
		delete(s.pendingClient, msg.IDKey())
	}
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
		if err != nil {
			if opts.Mode == ModeAction {
				return fmt.Errorf("ACP protocol blocked: %w", err)
			}
			fmt.Fprintf(opts.Stderr, "[defenseclaw-acp] observe protocol finding: %v\n", err)
			if _, writeErr := fmt.Fprintln(dst, string(frame)); writeErr != nil {
				return writeErr
			}
			continue
		}
		verdict, evalErr := opts.Evaluator.Evaluate(ctx, Evaluation{
			Profile: opts.Profile, Mode: opts.Mode, AgentID: opts.AgentID, ClientID: opts.ClientID,
			Direction: direction, Surface: Classify(msg, direction), Method: msg.Method, Payload: msg.Raw,
		})
		if evalErr != nil {
			if opts.Mode == ModeAction || errors.Is(evalErr, ErrModeMismatch) {
				return fmt.Errorf("ACP evaluation unavailable: %w", evalErr)
			}
			fmt.Fprintf(opts.Stderr, "[defenseclaw-acp] observe evaluation error: %v\n", evalErr)
		} else if verdict.Action == "block" || verdict.Action == "confirm" {
			if opts.Mode == ModeAction {
				if msg.IsRequest() {
					response := ErrorResponse(msg.ID, -32001, "blocked by DefenseClaw ACP policy")
					state.reject(msg, direction)
					_, err = fmt.Fprintln(rejectDst, string(response))
					if err != nil {
						return err
					}
				}
				if direction == AgentToClient {
					if promptID := state.abortPrompt(); len(promptID) > 0 {
						response := ErrorResponse(promptID, -32001, "blocked by DefenseClaw ACP policy")
						if _, err = fmt.Fprintln(dst, string(response)); err != nil {
							return err
						}
					}
				}
				continue
			}
			fmt.Fprintf(opts.Stderr, "[defenseclaw-acp] would block %s %s: %s\n", direction, msg.Method, verdict.Reason)
		}
		if opts.Mode == ModeAction {
			out, bufferErr := state.bufferOrFlush(msg, direction, matchedMethod, frame)
			if bufferErr != nil {
				return bufferErr
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

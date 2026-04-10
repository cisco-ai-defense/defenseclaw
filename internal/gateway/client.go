// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"math"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/gorilla/websocket"

	"github.com/defenseclaw/defenseclaw/internal/config"
)

// Client connects to the OpenClaw gateway WebSocket and provides RPC methods
// and an event stream for the sidecar.
type Client struct {
	cfg    *config.GatewayConfig
	device *DeviceIdentity
	debug  bool

	conn       *websocket.Conn
	mu         sync.Mutex
	closed     bool
	seqMu      sync.Mutex
	lastSeq    int
	pending    map[string]chan *ResponseFrame
	hello      *HelloOK
	disconnCh  chan struct{}
	disconnOnce sync.Once

	// While the connect RPC is in flight, inbound events are queued here so
	// readLoop never blocks on OnEvent (handlers may call Client.request).
	handshakeMu           sync.Mutex
	bufferHandshakeEvents bool
	handshakeBuf          []EventFrame

	// OnEvent is called for every non-connect event frame.
	OnEvent func(EventFrame)
}

const connectRPCTimeout = 45 * time.Second

// NewClient creates a gateway client. The device identity is loaded or created
// automatically from the configured key file path.
func NewClient(cfg *config.GatewayConfig) (*Client, error) {
	device, err := LoadOrCreateIdentity(cfg.DeviceKeyFile)
	if err != nil {
		return nil, err
	}

	return &Client{
		cfg:     cfg,
		device:  device,
		debug:   os.Getenv("DEFENSECLAW_DEBUG") == "1",
		pending: make(map[string]chan *ResponseFrame),
		lastSeq: -1,
	}, nil
}

func (c *Client) wsURL() string {
	scheme := "ws"
	if c.cfg.RequiresTLS() {
		scheme = "wss"
	}
	u := url.URL{
		Scheme: scheme,
		Host:   fmt.Sprintf("%s:%d", c.cfg.Host, c.cfg.Port),
	}
	return u.String()
}

// Connect establishes the WebSocket connection and completes the protocol v3
// handshake including device challenge-response authentication.
func (c *Client) Connect(ctx context.Context) error {
	target := c.wsURL()
	fmt.Fprintf(os.Stderr, "[gateway] dialing %s ...\n", target)
	t0 := time.Now()

	dialer := websocket.Dialer{
		HandshakeTimeout: 10 * time.Second,
	}
	if c.cfg.RequiresTLS() {
		dialer.TLSClientConfig = &tls.Config{
			MinVersion:         tls.VersionTLS12,
			InsecureSkipVerify: c.cfg.TLSSkipVerify,
		}
	}
	conn, resp, err := dialer.DialContext(ctx, target, nil)
	if err != nil {
		return fmt.Errorf("gateway: dial %s: %w", target, err)
	}
	fmt.Fprintf(os.Stderr, "[gateway] websocket connected (%s, http %d)\n",
		time.Since(t0).Round(time.Millisecond), resp.StatusCode)
	c.conn = conn
	c.closed = false
	c.disconnCh = make(chan struct{})
	c.disconnOnce = sync.Once{}

	fmt.Fprintf(os.Stderr, "[gateway] waiting for connect.challenge ...\n")
	nonce, err := c.waitForChallenge(ctx)
	if err != nil {
		conn.Close()
		return fmt.Errorf("gateway: challenge: %w", err)
	}
	fmt.Fprintf(os.Stderr, "[gateway] got challenge nonce=%s...%s (%s elapsed)\n",
		nonce[:min(8, len(nonce))], nonce[max(0, len(nonce)-4):], time.Since(t0).Round(time.Millisecond))

	fmt.Fprintf(os.Stderr, "[gateway] starting read loop before connect handshake\n")
	c.startHandshakeEventBuffer()
	go c.readLoop()

	fmt.Fprintf(os.Stderr, "[gateway] sending connect (protocol=3, role=operator, device=%s) ...\n",
		c.device.DeviceID)
	hello, err := c.sendConnect(ctx, nonce)
	buf := c.stopHandshakeEventBuffer()
	if err != nil {
		conn.Close()
		return fmt.Errorf("gateway: connect handshake: %w", err)
	}
	fmt.Fprintf(os.Stderr, "[gateway] handshake complete (%s elapsed)\n", time.Since(t0).Round(time.Millisecond))

	c.hello = hello
	for _, evt := range buf {
		c.dispatchEvent(evt)
	}
	return nil
}

func (c *Client) startHandshakeEventBuffer() {
	c.handshakeMu.Lock()
	c.bufferHandshakeEvents = true
	c.handshakeBuf = nil
	c.handshakeMu.Unlock()
}

// stopHandshakeEventBuffer clears buffering and returns queued events (FIFO).
func (c *Client) stopHandshakeEventBuffer() []EventFrame {
	c.handshakeMu.Lock()
	defer c.handshakeMu.Unlock()
	c.bufferHandshakeEvents = false
	buf := c.handshakeBuf
	c.handshakeBuf = nil
	return buf
}

func (c *Client) maybeBufferOrDispatchEvent(evt EventFrame) {
	c.handshakeMu.Lock()
	if c.bufferHandshakeEvents {
		c.handshakeBuf = append(c.handshakeBuf, evt)
		readLoopLogf("[bifrost] event %s buffered during handshake (buf_size=%d)",
			evt.Event, len(c.handshakeBuf))
		c.handshakeMu.Unlock()
		return
	}
	c.handshakeMu.Unlock()
	c.dispatchEvent(evt)
}

func (c *Client) dispatchEvent(evt EventFrame) {
	if evt.Seq != nil {
		c.seqMu.Lock()
		seq := *evt.Seq
		if c.lastSeq >= 0 && seq > c.lastSeq+1 {
			fmt.Fprintf(os.Stderr, "[gateway] sequence gap: expected %d, got %d\n", c.lastSeq+1, seq)
		}
		c.lastSeq = seq
		c.seqMu.Unlock()
	}
	if c.OnEvent != nil {
		c.OnEvent(evt)
	} else {
		readLoopLogf("[bifrost] WARNING: OnEvent is nil, event %s dropped", evt.Event)
	}
}

func (c *Client) waitForChallenge(ctx context.Context) (string, error) {
	deadline, ok := ctx.Deadline()
	if !ok {
		deadline = time.Now().Add(10 * time.Second)
	}
	_ = c.conn.SetReadDeadline(deadline)

	_, raw, err := c.conn.ReadMessage()
	if err != nil {
		return "", fmt.Errorf("read challenge: %w", err)
	}
	if c.debug {
		fmt.Fprintf(os.Stderr, "[gateway] received frame (%d bytes): %s\n", len(raw), truncateBytes(raw, 300))
	}

	var frame RawFrame
	if err := json.Unmarshal(raw, &frame); err != nil {
		return "", fmt.Errorf("parse challenge frame: %w", err)
	}
	if frame.Type != "event" || frame.Event != "connect.challenge" {
		return "", fmt.Errorf("expected connect.challenge, got type=%s event=%s", frame.Type, frame.Event)
	}

	var evt EventFrame
	if err := json.Unmarshal(raw, &evt); err != nil {
		return "", fmt.Errorf("parse challenge event: %w", err)
	}

	var cp ChallengePayload
	if err := json.Unmarshal(evt.Payload, &cp); err != nil {
		return "", fmt.Errorf("parse challenge payload: %w", err)
	}
	if cp.Nonce == "" {
		return "", fmt.Errorf("empty challenge nonce")
	}

	_ = c.conn.SetReadDeadline(time.Time{})
	return cp.Nonce, nil
}

func (c *Client) sendConnect(ctx context.Context, nonce string) (*HelloOK, error) {
	clientID := "gateway-client"
	clientMode := "backend"
	role := "operator"
	scopes := []string{"operator.read", "operator.write", "operator.admin", "operator.approvals"}

	deviceParams := ConnectDeviceParams{
		ClientID:   clientID,
		ClientMode: clientMode,
		Role:       role,
		Scopes:     scopes,
		Token:      c.cfg.Token,
		Nonce:      nonce,
		Platform:   runtime.GOOS,
	}

	params := map[string]interface{}{
		"minProtocol": 3,
		"maxProtocol": 3,
		"client": map[string]interface{}{
			"id":       clientID,
			"version":  "1.0.0",
			"platform": runtime.GOOS,
			"mode":     clientMode,
		},
		"role":   role,
		"scopes": scopes,
		"caps":   []string{"tool-events"},
		"auth": map[string]interface{}{
			"token": c.cfg.Token,
		},
		"device":    c.device.ConnectDevice(deviceParams),
		"userAgent": "defenseclaw/1.0.0",
		"locale":    "en-US",
	}

	if c.debug {
		if debugData, err := json.MarshalIndent(params, "  ", "  "); err == nil {
			redacted := redactToken(string(debugData), c.cfg.Token)
			fmt.Fprintf(os.Stderr, "[gateway] connect params:\n  %s\n", redacted)
		}
	}

	fmt.Fprintf(os.Stderr, "[gateway] waiting for connect response ...\n")
	handshakeCtx, cancel := context.WithTimeout(ctx, connectRPCTimeout)
	defer cancel()
	resp, err := c.request(handshakeCtx, "connect", params)
	if err != nil {
		return nil, err
	}

	if c.debug {
		fmt.Fprintf(os.Stderr, "[gateway] connect response: ok=%v payload=%s\n",
			resp.OK, truncateBytes(resp.Payload, 500))
	} else {
		fmt.Fprintf(os.Stderr, "[gateway] connect response: ok=%v payload_len=%d\n",
			resp.OK, len(resp.Payload))
	}
	if resp.Error != nil {
		fmt.Fprintf(os.Stderr, "[gateway] connect error: code=%s message=%s\n",
			resp.Error.Code, resp.Error.Message)
	}

	if !resp.OK {
		msg := "connect rejected"
		code := "UNKNOWN"
		if resp.Error != nil {
			msg = resp.Error.Message
			code = resp.Error.Code
		}
		return nil, fmt.Errorf("%s (%s)", msg, code)
	}

	var hello HelloOK
	if err := json.Unmarshal(resp.Payload, &hello); err != nil {
		return nil, fmt.Errorf("parse hello-ok: %w", err)
	}
	return &hello, nil
}

func (c *Client) readLoop() {
	defer c.signalDisconnect()

	for {
		_, raw, err := c.conn.ReadMessage()
		if err != nil {
			if !c.closed {
				readLoopLogf("[gateway] read error: %v", err)
			}
			return
		}

		var frame RawFrame
		if err := json.Unmarshal(raw, &frame); err != nil {
			readLoopLogf("[gateway] unparseable frame (%d bytes)", len(raw))
			continue
		}

		switch frame.Type {
		case "res":
			var resp ResponseFrame
			if err := json.Unmarshal(raw, &resp); err != nil {
				readLoopLogf("[gateway] bad res frame: %v", err)
				continue
			}
			c.mu.Lock()
			ch, ok := c.pending[resp.ID]
			if ok {
				delete(c.pending, resp.ID)
			}
			c.mu.Unlock()
			if ok {
				ch <- &resp
				readLoopLogf("[gateway] ← res id=%s...%s ok=%v",
					resp.ID[:min(8, len(resp.ID))], resp.ID[max(0, len(resp.ID)-4):], resp.OK)
			} else {
				readLoopLogf("[gateway] orphan response (no pending request): id=%s", resp.ID)
			}

		case "event":
			var evt EventFrame
			if err := json.Unmarshal(raw, &evt); err != nil {
				readLoopLogf("[gateway] bad event frame: %v", err)
				continue
			}
			seqStr := "nil"
			if evt.Seq != nil {
				seqStr = fmt.Sprintf("%d", *evt.Seq)
			}
			if c.debug {
				readLoopLogf("[gateway] ← event %s seq=%s payload=%s",
					evt.Event, seqStr, truncateBytes(evt.Payload, 200))
			} else {
				readLoopLogf("[gateway] ← event %s seq=%s payload_len=%d",
					evt.Event, seqStr, len(evt.Payload))
			}
			c.maybeBufferOrDispatchEvent(evt)

		default:
			readLoopLogf("[gateway] ← unknown frame type=%s (%d bytes)",
				frame.Type, len(raw))
		}
	}
}

// Request sends an RPC request and waits for the response.
func (c *Client) Request(ctx context.Context, method string, params interface{}) (json.RawMessage, error) {
	resp, err := c.request(ctx, method, params)
	if err != nil {
		return nil, err
	}
	if !resp.OK {
		msg := "request failed"
		code := "UNKNOWN"
		if resp.Error != nil {
			msg = resp.Error.Message
			code = resp.Error.Code
		}
		return nil, fmt.Errorf("gateway: %s: %s (%s)", method, msg, code)
	}
	return resp.Payload, nil
}

func (c *Client) request(ctx context.Context, method string, params interface{}) (*ResponseFrame, error) {
	id := uuid.New().String()
	frame := RequestFrame{
		Type:   "req",
		ID:     id,
		Method: method,
		Params: params,
	}

	data, err := json.Marshal(frame)
	if err != nil {
		return nil, fmt.Errorf("gateway: marshal request: %w", err)
	}

	fmt.Fprintf(os.Stderr, "[gateway] → req %s id=%s...%s (%d bytes)\n",
		method, id[:min(8, len(id))], id[max(0, len(id)-4):], len(data))

	ch := make(chan *ResponseFrame, 1)
	c.mu.Lock()
	if c.conn == nil {
		c.mu.Unlock()
		return nil, fmt.Errorf("gateway: not connected")
	}
	c.pending[id] = ch
	c.mu.Unlock()

	if err := c.conn.WriteMessage(websocket.TextMessage, data); err != nil {
		c.mu.Lock()
		delete(c.pending, id)
		c.mu.Unlock()
		return nil, fmt.Errorf("gateway: send: %w", err)
	}
	fmt.Fprintf(os.Stderr, "[gateway] sent, waiting for response ...\n")

	select {
	case resp := <-ch:
		return resp, nil
	case <-ctx.Done():
		c.mu.Lock()
		delete(c.pending, id)
		c.mu.Unlock()
		return nil, ctx.Err()
	}
}

// Close shuts down the WebSocket connection.
func (c *Client) Close() error {
	c.closed = true
	c.signalDisconnect()
	if c.conn != nil {
		return c.conn.Close()
	}
	return nil
}

// Disconnected returns a channel that is closed when the underlying WebSocket
// connection drops. Used by the sidecar to trigger reconnection.
func (c *Client) Disconnected() <-chan struct{} {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.disconnCh == nil {
		c.disconnCh = make(chan struct{})
	}
	return c.disconnCh
}

func (c *Client) signalDisconnect() {
	c.disconnOnce.Do(func() {
		if c.disconnCh != nil {
			close(c.disconnCh)
		}
	})
}

// Hello returns the hello-ok payload from the initial handshake.
func (c *Client) Hello() *HelloOK {
	return c.hello
}

// ConnectWithRetry connects to the gateway with exponential backoff.
// It blocks until a connection is established or the context is cancelled.
func (c *Client) ConnectWithRetry(ctx context.Context) error {
	backoff := time.Duration(c.cfg.ReconnectMs) * time.Millisecond
	maxBackoff := time.Duration(c.cfg.MaxReconnectMs) * time.Millisecond
	attempt := 0

	for {
		attempt++
		fmt.Fprintf(os.Stderr, "[gateway] connection attempt #%d\n", attempt)
		err := c.Connect(ctx)
		if err == nil {
			return nil
		}
		fmt.Fprintf(os.Stderr, "[gateway] connect failed (attempt #%d): %v (retry in %s)\n",
			attempt, err, backoff)

		c.tryAuthRepair(err)

		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(backoff):
		}

		backoff = time.Duration(math.Min(float64(backoff)*1.7, float64(maxBackoff)))
	}
}

// ---------------------------------------------------------------------------
// Auth auto-repair: when the OpenClaw gateway rejects a connect handshake
// with an auth error (token_missing, token_mismatch, unauthorized, etc.),
// the sidecar can self-heal by:
//
//  1. Re-injecting its device entry into OpenClaw's devices/paired.json
//     (handles NOT_PAIRED after OpenClaw restarts and clears pairing state)
//  2. Re-reading the shared gateway.auth.token from openclaw.json
//     (handles token_mismatch if the token was rotated)
//
// OpenClaw auth checks the shared gateway.auth.token first; the per-device
// token in device-auth.json is a Node.js client-side cache irrelevant here.
//
// Only activates in standalone sandbox mode (cfg.SandboxHome != "").
// ---------------------------------------------------------------------------

// tryAuthRepair attempts to repair device pairing and refresh the shared
// gateway token when a connect attempt fails with an auth-related error.
// Uses SandboxHome in sandbox mode, otherwise falls back to ClawHome
// (the user's real home directory) so auth repair works everywhere.
func (c *Client) tryAuthRepair(connectErr error) {
	if !c.shouldAutoRepair(connectErr) {
		return
	}

	home := c.authRepairHome()
	fmt.Fprintf(os.Stderr, "[gateway] auth rejected — repairing device pairing and token (home=%s) ...\n", home)

	if err := c.device.RepairPairing(home); err != nil {
		fmt.Fprintf(os.Stderr, "[gateway] repair pairing failed: %v\n", err)
	}

	if newToken, ok := readOpenClawGatewayToken(home); ok && newToken != c.cfg.Token {
		fmt.Fprintf(os.Stderr, "[gateway] gateway token refreshed from openclaw.json\n")
		c.cfg.Token = newToken
	}
}

// shouldAutoRepair returns true when auth auto-repair should be attempted.
func (c *Client) shouldAutoRepair(err error) bool {
	return c.authRepairHome() != "" && isAuthError(err)
}

// authRepairHome returns the home directory used for pairing repair.
// Prefers SandboxHome (standalone sandbox mode), falls back to ClawHome
// (regular installs).
func (c *Client) authRepairHome() string {
	if c.cfg.SandboxHome != "" {
		return c.cfg.SandboxHome
	}
	return c.cfg.ClawHome
}

// isAuthError returns true if the error message indicates the OpenClaw
// gateway rejected the connect handshake due to a missing/invalid token
// or device pairing.
func isAuthError(err error) bool {
	if err == nil {
		return false
	}
	msg := strings.ToLower(err.Error())
	for _, needle := range []string{
		"token_missing", "token_mismatch",
		"unauthorized", "pairing_required", "not paired",
	} {
		if strings.Contains(msg, needle) {
			return true
		}
	}
	return false
}

// readOpenClawGatewayToken reads gateway.auth.token from the OpenClaw
// config file inside the sandbox home directory.
func readOpenClawGatewayToken(sandboxHome string) (string, bool) {
	path := filepath.Join(sandboxHome, ".openclaw", "openclaw.json")
	data, err := os.ReadFile(path)
	if err != nil {
		return "", false
	}
	var cfg struct {
		Gateway struct {
			Auth struct {
				Token string `json:"token"`
			} `json:"auth"`
		} `json:"gateway"`
	}
	if err := json.Unmarshal(data, &cfg); err != nil {
		return "", false
	}
	if cfg.Gateway.Auth.Token == "" {
		return "", false
	}
	return cfg.Gateway.Auth.Token, true
}

func truncateBytes(b []byte, maxLen int) string {
	s := string(b)
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen] + "..."
}

func redactToken(s, token string) string {
	if token == "" || len(token) < 8 {
		return s
	}
	redacted := token[:4] + "..." + token[len(token)-4:]
	return strings.ReplaceAll(s, token, redacted)
}

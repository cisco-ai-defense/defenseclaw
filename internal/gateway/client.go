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
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/google/uuid"
	"github.com/gorilla/websocket"

	"github.com/defenseclaw/defenseclaw/internal/gateway/connector/hookexec"
	"github.com/defenseclaw/defenseclaw/internal/managed"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/envvars"
	"github.com/defenseclaw/defenseclaw/internal/jsonc"
	"github.com/defenseclaw/defenseclaw/internal/redaction"
)

// Client connects to the OpenClaw gateway WebSocket and provides RPC methods
// and an event stream for the sidecar.
type Client struct {
	cfg     *config.GatewayConfig
	device  *DeviceIdentity
	dataDir string
	debug   bool

	// mu guards conn, pending, hello, disconnCh and readDone. Connect
	// replaces conn and disconnCh only after the readLoop of the previous
	// connection has exited (readDone), so a reader that is still unwinding
	// never touches the state of the next connection.
	mu   sync.Mutex
	conn *websocket.Conn

	// writeMu serializes data writes for the lifetime of this Client, including
	// requests that overlap a connection change. Response waits do not hold it.
	writeMu sync.Mutex

	closed    atomic.Bool
	seqMu     sync.Mutex
	lastSeq   int
	pending   map[string]chan *ResponseFrame
	hello     *HelloOK
	disconnCh chan struct{}
	readDone  chan struct{}

	// While the connect RPC is in flight, inbound events are queued here so
	// readLoop never blocks on OnEvent (handlers may call Client.request).
	handshakeMu           sync.Mutex
	bufferHandshakeEvents bool
	handshakeBuf          []EventFrame

	// OnEvent is called for every non-connect event frame.
	OnEvent func(EventFrame)

	// OnConnectError, when set, is called after every failed connect
	// attempt of ConnectWithRetry. hint is the operator step for an
	// OpenClaw pairing or token rejection, and "" for any other failure.
	OnConnectError func(err error, hint string)

	// refreshedToken is the gateway token handleConnectRejection adopted from
	// openclaw.json after boot. The API server accepts it next to its
	// boot token until the next restart (GAP-2259).
	refreshedToken atomic.Pointer[string]

	// tokenRetryEvery and tokenWatch override tokenNotPersistedRetry and
	// tokenWatchInterval; tests set them, zero means the default.
	tokenRetryEvery time.Duration
	tokenWatch      time.Duration
}

// RefreshedToken returns the gateway token re-read from openclaw.json at
// runtime, or "" when none was adopted since boot.
func (c *Client) RefreshedToken() string {
	if c == nil {
		return ""
	}
	if p := c.refreshedToken.Load(); p != nil {
		return *p
	}
	return ""
}

const (
	connectRPCTimeout = 45 * time.Second

	// tokenNotPersistedRetry is the retry interval while OpenClaw rejects the
	// gateway token and openclaw.json holds none (see
	// openClawTokenNotPersistedHint). tokenWatchInterval is how often the
	// wait looks for a token to appear.
	tokenNotPersistedRetry = 5 * time.Minute
	tokenWatchInterval     = 5 * time.Second

	openClawMinProtocol = 3
	openClawMaxProtocol = 4
)

// NewClient creates a gateway client. The device identity is loaded or created
// automatically from the configured key file path.
func NewClient(cfg *config.GatewayConfig, dataDirs ...string) (*Client, error) {
	if len(dataDirs) > 1 {
		return nil, fmt.Errorf("gateway: device identity accepts at most one data directory")
	}
	target, dataDir, err := normalizeDeviceIdentityPaths(cfg.DeviceKeyFile, dataDirs)
	if err != nil {
		return nil, err
	}
	device, err := loadOrCreateIdentityAt(target, dataDir)
	if err != nil {
		return nil, err
	}
	// Keep every downstream consumer, including the telemetry resource
	// fingerprint, on the same canonical path used for identity custody.
	cfg.DeviceKeyFile = target

	return &Client{
		cfg:     cfg,
		device:  device,
		dataDir: dataDir,
		debug:   envvars.Getenv("DEFENSECLAW_DEBUG") == "1",
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

// Connect establishes the WebSocket connection and completes the OpenClaw
// gateway handshake including device challenge-response authentication.
func (c *Client) Connect(ctx context.Context) error {
	target := c.wsURL()
	fmt.Fprintf(os.Stderr, "[gateway] dialing %s ...\n", target)
	t0 := time.Now()

	dialer := websocket.Dialer{
		HandshakeTimeout: 10 * time.Second,
		NetDialContext:   dialOpenClawListener,
	}
	if c.cfg.RequiresTLS() {
		dialer.TLSClientConfig = &tls.Config{
			MinVersion:         tls.VersionTLS12,
			InsecureSkipVerify: c.cfg.TLSSkipVerify,
		}
	}
	if err := c.joinPreviousReader(ctx); err != nil {
		return err
	}
	conn, resp, err := dialer.DialContext(ctx, target, nil)
	if err != nil {
		return fmt.Errorf("gateway: dial %s: %w", target, err)
	}
	fmt.Fprintf(os.Stderr, "[gateway] websocket connected (%s, http %d)\n",
		time.Since(t0).Round(time.Millisecond), resp.StatusCode)
	c.mu.Lock()
	c.conn = conn
	c.disconnCh = make(chan struct{})
	c.mu.Unlock()
	c.closed.Store(false)

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
	readDone := make(chan struct{})
	c.mu.Lock()
	c.readDone = readDone
	c.mu.Unlock()
	go c.readLoop(conn, readDone)

	fmt.Fprintf(os.Stderr, "[gateway] sending connect (protocol=%d..%d, role=operator, device=%s) ...\n",
		openClawMinProtocol, openClawMaxProtocol, c.device.DeviceID)
	hello, err := c.sendConnect(ctx, nonce)
	buf := c.stopHandshakeEventBuffer()
	if err != nil {
		conn.Close()
		return fmt.Errorf("gateway: connect handshake: %w", err)
	}
	fmt.Fprintf(os.Stderr, "[gateway] handshake complete (%s elapsed)\n", time.Since(t0).Round(time.Millisecond))

	c.mu.Lock()
	c.hello = hello
	c.mu.Unlock()
	for _, evt := range buf {
		c.dispatchEvent(evt)
	}
	return nil
}

// errOpenClawListenerUnverified is a loopback OpenClaw gateway port whose
// listener is not this account's (GAP-0594).
var errOpenClawListenerUnverified = errors.New("the OpenClaw gateway listener does not belong to this account")

// verifyOpenClawListener checks the account of the accepted server socket:
// on Linux this account or root, on macOS this account only (the socket
// owner is read from this account's processes). Replaceable in tests.
var verifyOpenClawListener = hookexec.VerifyLocalPeer

// dialOpenClawListener opens the TCP connection of the OpenClaw WebSocket.
// On Linux a loopback listener must belong to this account or root, on macOS
// to this account, before DefenseClaw writes any byte to it, so a process
// of another account that holds the port while OpenClaw restarts never gets
// the WebSocket upgrade, the gateway token or the device signature
// (GAP-0594). A listener on another host is protected by TLS, not by this
// check. Windows does not run the OpenClaw connector.
func dialOpenClawListener(ctx context.Context, network, addr string) (net.Conn, error) {
	var dialer net.Dialer
	conn, err := dialer.DialContext(ctx, network, addr)
	if err != nil {
		return nil, err
	}
	if !openClawListenerOwnerChecked(conn) {
		return conn, nil
	}
	if err := verifyOpenClawListener(conn); err != nil {
		_ = conn.Close()
		return nil, fmt.Errorf("%w (%s): %v", errOpenClawListenerUnverified, addr, err)
	}
	return conn, nil
}

// openClawListenerOwnerChecked reports whether conn's listener account is
// checked: a loopback connection on Linux or macOS.
func openClawListenerOwnerChecked(conn net.Conn) bool {
	if runtime.GOOS != "linux" && runtime.GOOS != "darwin" {
		return false
	}
	remote, ok := conn.RemoteAddr().(*net.TCPAddr)
	return ok && remote.IP.IsLoopback()
}

// joinPreviousReader closes the previous connection, if its readLoop is
// still running, and waits for that readLoop to exit. Its deferred
// drainPending and signalDisconnect then cannot clear or close the state
// that this Connect is about to install.
func (c *Client) joinPreviousReader(ctx context.Context) error {
	c.mu.Lock()
	prevConn, prevDone := c.conn, c.readDone
	c.mu.Unlock()
	if prevDone == nil {
		return nil
	}
	select {
	case <-prevDone:
		return nil
	default:
	}
	if prevConn != nil {
		_ = prevConn.Close()
	}
	select {
	case <-prevDone:
		return nil
	case <-ctx.Done():
		return fmt.Errorf("gateway: previous connection still closing: %w", ctx.Err())
	}
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
		// Raw frame bytes can echo untrusted content when
		// the server surfaces errors that include request
		// bodies. Run the truncated preview through the
		// message-content redactor before emitting.
		fmt.Fprintf(os.Stderr, "[gateway] received frame (%d bytes): %s\n",
			len(raw), redaction.MessageContent(string(truncateBytes(raw, 300))))
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
		"minProtocol": openClawMinProtocol,
		"maxProtocol": openClawMaxProtocol,
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
			resp.OK, redaction.MessageContent(string(truncateBytes(resp.Payload, 500))))
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

// readLoop reads frames from conn until it fails. readDone is closed last,
// after the pending requests are drained and the disconnect is signalled.
func (c *Client) readLoop(conn *websocket.Conn, readDone chan struct{}) {
	defer close(readDone)
	defer c.signalDisconnect()
	defer c.drainPending()

	for {
		_, raw, err := conn.ReadMessage()
		if err != nil {
			if !c.closed.Load() {
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
				// Event payloads frequently carry chat
				// message text, tool args, and agent
				// errors verbatim. DEFENSECLAW_DEBUG is
				// an operator opt-in, but the redactor
				// still scrubs obvious secrets/PII so
				// accidental capture of these logs
				// (e.g. tee'd to a shared session) is
				// safe.
				readLoopLogf("[gateway] ← event %s seq=%s payload=%s",
					evt.Event, seqStr,
					redaction.MessageContent(string(truncateBytes(evt.Payload, 200))))
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
	c.writeMu.Lock()
	if err := ctx.Err(); err != nil {
		c.writeMu.Unlock()
		return nil, err
	}
	c.mu.Lock()
	conn := c.conn
	if conn == nil {
		c.mu.Unlock()
		c.writeMu.Unlock()
		return nil, fmt.Errorf("gateway: not connected")
	}
	c.pending[id] = ch
	c.mu.Unlock()

	err = conn.WriteMessage(websocket.TextMessage, data)
	if err != nil {
		_ = conn.Close()
	}
	c.writeMu.Unlock()
	if err != nil {
		c.mu.Lock()
		delete(c.pending, id)
		c.mu.Unlock()
		return nil, fmt.Errorf("gateway: send: %w", err)
	}
	fmt.Fprintf(os.Stderr, "[gateway] sent, waiting for response ...\n")

	select {
	case resp := <-ch:
		if resp == nil {
			return nil, fmt.Errorf("gateway: not connected")
		}
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
	c.closed.Store(true)
	c.signalDisconnect()
	c.mu.Lock()
	conn := c.conn
	c.mu.Unlock()
	if conn != nil {
		return conn.Close()
	}
	return nil
}

// disconnectForReload closes the current WebSocket without announcing a
// disconnect before its reader has drained. The fleet loop waits on the
// returned channel before a later reload may reuse this Client.
func (c *Client) disconnectForReload() <-chan struct{} {
	done := c.Disconnected()
	c.mu.Lock()
	conn := c.conn
	c.mu.Unlock()
	if conn != nil {
		_ = conn.Close()
	}
	return done
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

// signalDisconnect closes the disconnect channel of the current connection
// once.
func (c *Client) signalDisconnect() {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.disconnCh == nil {
		return
	}
	select {
	case <-c.disconnCh:
	default:
		close(c.disconnCh)
	}
}

// drainPending closes all pending response channels and nils out the
// connection so that in-flight requests fail fast with a retryable error
// instead of hanging until context deadline.
func (c *Client) drainPending() {
	c.mu.Lock()
	defer c.mu.Unlock()
	for id, ch := range c.pending {
		close(ch)
		delete(c.pending, id)
	}
	c.conn = nil
}

// Hello returns the hello-ok payload from the initial handshake.
func (c *Client) Hello() *HelloOK {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.hello
}

// ConnectWithRetry connects to the gateway with exponential backoff.
// It blocks until a connection is established or the context is cancelled.
//
// A token that changed since the last attempt has not been tried yet, so the
// wait before it is the base interval and the backoff starts over: the
// backoff was earned by attempts that used the old token (GAP-0847).
func (c *Client) ConnectWithRetry(ctx context.Context) error {
	base := time.Duration(c.cfg.ReconnectMs) * time.Millisecond
	backoff := base
	maxBackoff := time.Duration(c.cfg.MaxReconnectMs) * time.Millisecond
	attempt := 0

	for {
		attempt++
		fmt.Fprintf(os.Stderr, "[gateway] connection attempt #%d\n", attempt)
		err := c.Connect(ctx)
		if err == nil {
			return nil
		}
		tokenBefore := c.cfg.Token
		hint := c.handleConnectRejection(err)
		wait := backoff
		var wake func() bool
		restart := c.cfg.Token != tokenBefore
		switch {
		case restart:
			wait = base
		case hint == openClawTokenNotPersistedHint:
			// Nothing DefenseClaw can read changes until the operator
			// persists a token, so retrying every few seconds only fills
			// both logs. Retry slowly, and at once when a token appears.
			wait = max(wait, c.tokenNotPersistedRetryEvery())
		}
		switch {
		case hint == openClawTokenNotPersistedHint:
			wake = c.persistedTokenAppeared
		case c.shouldRefreshToken(err):
			// A rejected token can be rotated while the wait runs, so the
			// wait ends when openclaw.json holds a token other than the one
			// just rejected, whatever backoff has grown to.
			wake = c.persistedTokenChanged
		}
		fmt.Fprintf(os.Stderr, "[gateway] connect failed (attempt #%d): %v (retry in %s)\n",
			attempt, err, wait)
		if c.OnConnectError != nil {
			c.OnConnectError(err, hint)
		}

		woken, err := c.waitBeforeRetry(ctx, wait, wake)
		if err != nil {
			return err
		}
		if woken {
			// The wait ended because openclaw.json got a token. Load it
			// now: the next attempt would otherwise send the old token,
			// be rejected, and only then pick this one up.
			c.adoptPersistedToken()
			restart = true
		}

		if restart {
			backoff = base
			continue
		}
		backoff = time.Duration(math.Min(float64(backoff)*1.7, float64(maxBackoff)))
	}
}

// waitBeforeRetry sleeps for d. With wake set it checks wake every
// tokenWatchEvery and returns early, reporting woken, when it reports true.
func (c *Client) waitBeforeRetry(ctx context.Context, d time.Duration, wake func() bool) (woken bool, err error) {
	if wake == nil {
		select {
		case <-ctx.Done():
			return false, ctx.Err()
		case <-time.After(d):
			return false, nil
		}
	}
	deadline := time.NewTimer(d)
	defer deadline.Stop()
	tick := time.NewTicker(c.tokenWatchEvery())
	defer tick.Stop()
	for {
		select {
		case <-ctx.Done():
			return false, ctx.Err()
		case <-deadline.C:
			return false, nil
		case <-tick.C:
			if wake() {
				return true, nil
			}
		}
	}
}

func (c *Client) tokenNotPersistedRetryEvery() time.Duration {
	if c.tokenRetryEvery > 0 {
		return c.tokenRetryEvery
	}
	return tokenNotPersistedRetry
}

func (c *Client) tokenWatchEvery() time.Duration {
	if c.tokenWatch > 0 {
		return c.tokenWatch
	}
	return tokenWatchInterval
}

// persistedTokenAppeared reports that openclaw.json now holds a gateway
// token, or a reference to one DefenseClaw cannot read. The wait started
// because it held none, so any token is a change to act on, including the
// value DefenseClaw already sends: the operator persisted it and OpenClaw
// has restarted to use it.
func (c *Client) persistedTokenAppeared() bool {
	if c.cfg.ClawHome == "" {
		return false
	}
	_, ok, err := readOpenClawGatewayToken(c.cfg.ClawHome)
	return ok || errors.Is(err, errOpenClawTokenUnreadable)
}

// persistedTokenChanged reports that openclaw.json holds a readable gateway
// token other than the one this client sends: the operator rotated it after
// the last rejection.
func (c *Client) persistedTokenChanged() bool {
	if c.cfg.ClawHome == "" {
		return false
	}
	token, ok, _ := readOpenClawGatewayToken(c.cfg.ClawHome)
	return ok && token != c.cfg.Token
}

// adoptPersistedToken makes the gateway token persisted in openclaw.json the
// one the next connect attempt sends. A token equal to the current one, or
// none DefenseClaw can read, changes nothing.
func (c *Client) adoptPersistedToken() {
	if c.cfg.ClawHome == "" {
		return
	}
	token, ok, _ := readOpenClawGatewayToken(c.cfg.ClawHome)
	if !ok || token == c.cfg.Token {
		return
	}
	fmt.Fprintf(os.Stderr, "[gateway] openclaw.json now holds a gateway token; trying it\n")
	c.adoptOpenClawToken(token)
}

// adoptOpenClawToken makes token, read from openclaw.json, the gateway token
// of this client, the API server and the on-disk token sources.
func (c *Client) adoptOpenClawToken(token string) {
	c.cfg.Token = token
	c.refreshedToken.Store(&token)

	// Persist the refreshed token to disk so hook scripts and
	// operator shells see the same value. Without this, the in-
	// memory refresh only helps the sidecar itself — downstream
	// consumers (hooks/.token, .env) stay stale and every
	// hook-driven request 401s until the next full sidecar
	// restart re-reads openclaw.json on boot.
	//
	// Keep refreshed credentials in the configured data directory even
	// when device_key_file is nested beneath it. Errors are logged but
	// not returned — persistence is best-effort, the primary in-memory
	// refresh already succeeded.
	if c.dataDir != "" {
		if err := persistRefreshedToken(c.dataDir, token); err != nil {
			fmt.Fprintf(os.Stderr, "[gateway] WARNING: failed to persist refreshed token to disk: %v — hook scripts may 401 until next restart\n", err)
		}
	}
}

// ---------------------------------------------------------------------------
// Connect rejections. OpenClaw owns its device pairing state and DefenseClaw
// never writes it (GAP-0592: the sidecar used to rewrite
// devices/paired.json and grant itself operator.read, write, admin and
// approvals). OpenClaw approves a first-time device on a direct loopback
// connection itself (gateway.nodes.pairing.autoApproveLocal, on by
// default). Any other pairing request, and every role or scope upgrade
// OpenClaw does not approve on its own, waits for the operator:
// `openclaw devices list`, then `openclaw devices approve <requestId>`. The
// sidecar logs that step, publishes it in /health and keeps retrying.
//
// A rotated shared gateway.auth.token is re-read from openclaw.json. The
// read changes no OpenClaw state; the token is written only to
// DefenseClaw's own .env and hooks/.token.
// ---------------------------------------------------------------------------

// openClawGiveTokenStep is the one way to give the background gateway a
// token it cannot read from openclaw.json. A variable exported in the shell
// that starts the gateway does not reach the daemon, so it is not offered.
//
// Token precedence, highest first: a token the operator saved with
// defenseclaw keys set (the process environment and ~/.defenseclaw/.env),
// the gateway.auth.token in openclaw.json, and the copy the gateway adopted
// from openclaw.json earlier. An adopted copy is rewritten whenever
// openclaw.json holds a different token, and keys set replaces it under
// both variable names, so a stale copy never shadows a newer saved token. A
// token saved by editing one spelling in .env also wins over the adopted copy
// under the other: adoption records the copy it wrote in a marker comment, and
// every .env reader leaves a marked copy out when the other spelling differs
// (envvars.ShadowedAdoptedGatewayTokens).
const openClawGiveTokenStep = "defenseclaw keys set OPENCLAW_GATEWAY_TOKEN and restart the gateway with " +
	"defenseclaw-gateway restart (a variable exported in your shell does not reach the background gateway)"

// openClawTokenRejectedHint is the operator step for a rejected gateway token.
const openClawTokenRejectedHint = "OpenClaw rejected the gateway token. DefenseClaw re-reads gateway.auth.token " +
	"from openclaw.json on every retry; when it is a secret reference, give the DefenseClaw gateway the token " +
	"with " + openClawGiveTokenStep

// openClawTokenNotPersistedHint is the operator step when OpenClaw rejects the
// gateway token and openclaw.json holds no gateway.auth.token. The token
// OpenClaw expects then comes from somewhere DefenseClaw cannot see: its own
// environment (OPENCLAW_GATEWAY_TOKEN, its .env file, its service unit), or a
// runtime token it generates at start when none is set. DefenseClaw cannot
// tell which, so the hint names the fixes that work for each. Hooks and the
// guardrail proxy do not use this connection.
const openClawTokenNotPersistedHint = "OpenClaw rejected the gateway token and openclaw.json has no " +
	"gateway.auth.token, so DefenseClaw cannot tell which token OpenClaw expects: it takes one from its own " +
	"environment (OPENCLAW_GATEWAY_TOKEN, its .env file or service unit) or generates a runtime token at start. " +
	"Give the DefenseClaw gateway that same token with " + openClawGiveTokenStep + ", or persist one with " +
	"'openclaw config set gateway.auth.mode token' and 'openclaw config set gateway.auth.token <token>', " +
	"restart OpenClaw, then run 'defenseclaw setup openclaw'. DefenseClaw retries every few minutes, and at once " +
	"when openclaw.json gets a token"

// openClawTokenEnvRejectedHint is the operator step when OpenClaw rejects the
// token DefenseClaw already took from OPENCLAW_GATEWAY_TOKEN and openclaw.json
// has no gateway.auth.token. OpenClaw may be using a token from its own
// environment or a runtime token it generated; DefenseClaw cannot tell which.
const openClawTokenEnvRejectedHint = "OpenClaw rejected the gateway token DefenseClaw took from OPENCLAW_GATEWAY_TOKEN " +
	"(its saved value in ~/.defenseclaw/.env, which may be a copy adopted from openclaw.json before the token was " +
	"removed there), and openclaw.json has no gateway.auth.token. Save the token OpenClaw expects with " +
	openClawGiveTokenStep + ", start OpenClaw with that same OPENCLAW_GATEWAY_TOKEN, or persist " +
	"one with 'openclaw config set gateway.auth.mode token' and 'openclaw config set gateway.auth.token <token>', " +
	"restart OpenClaw, then run 'defenseclaw setup openclaw'"

// openClawListenerUnverifiedHint is the operator step for an OpenClaw
// gateway port that another account's process holds.
const openClawListenerUnverifiedHint = "The OpenClaw gateway port is held by a process of another account. " +
	"DefenseClaw sends it nothing and keeps retrying. Stop that process, or give this account's OpenClaw " +
	"gateway its own port (gateway.port in openclaw.json) and run 'defenseclaw setup openclaw'"

// openClawPairingApprovalHint is the operator step for a device OpenClaw has
// not approved (yet) for the role and scopes DefenseClaw asks for.
func openClawPairingApprovalHint(deviceID string) string {
	return "OpenClaw has not approved the DefenseClaw device " + deviceID + " (client gateway-client). " +
		"Run 'openclaw devices list', then 'openclaw devices approve <requestId>' for its pending request. " +
		"DefenseClaw keeps retrying and connects once it is approved"
}

// handleConnectRejection reacts to a failed connect attempt. It returns the
// operator step for an OpenClaw pairing or token rejection, or "" for any
// other failure. It never writes OpenClaw state.
func (c *Client) handleConnectRejection(connectErr error) string {
	hint := ""
	switch {
	case errors.Is(connectErr, errOpenClawListenerUnverified):
		hint = openClawListenerUnverifiedHint
		fmt.Fprintf(os.Stderr, "[gateway] %s\n", hint)
		return hint
	case openClawPairingApprovalNeeded(connectErr):
		hint = openClawPairingApprovalHint(c.device.DeviceID)
		fmt.Fprintf(os.Stderr, "[gateway] %s\n", hint)
	case isAuthError(connectErr):
		hint = openClawTokenRejectedHint
	}
	if !c.shouldRefreshToken(connectErr) {
		return hint
	}

	home := c.cfg.ClawHome
	fmt.Fprintf(os.Stderr, "[gateway] auth rejected — re-reading the gateway token from openclaw.json (home=%s) ...\n", home)

	newToken, ok, tokenErr := readOpenClawGatewayToken(home)
	if tokenErr != nil {
		fmt.Fprintf(os.Stderr, "[gateway] %v\n", tokenErr)
	}
	fromEnv := false
	if errors.Is(tokenErr, errOpenClawTokenNotPersisted) && isAuthError(connectErr) &&
		!openClawPairingApprovalNeeded(connectErr) &&
		strings.Contains(strings.ToLower(connectErr.Error()), "token") {
		// openclaw.json holds no token. OpenClaw then takes
		// OPENCLAW_GATEWAY_TOKEN from its environment when it has one. The
		// sidecar's own environment is not OpenClaw's (its .env file and
		// service unit are not visible here), so an empty variable proves
		// no cause.
		switch env := openClawEnvGatewayToken(); {
		case env == "":
			hint = openClawTokenNotPersistedHint
		case env != c.cfg.Token:
			newToken, ok, fromEnv = env, true, true
		default:
			hint = openClawTokenEnvRejectedHint
		}
		if hint != "" {
			fmt.Fprintf(os.Stderr, "[gateway] %s\n", hint)
		}
	}
	if fromEnv && newToken != c.cfg.Token {
		// Only this connection tries it. It is not DefenseClaw's own token,
		// so it is not written to .env or the hook token file.
		fmt.Fprintf(os.Stderr, "[gateway] openclaw.json has no gateway.auth.token; trying OPENCLAW_GATEWAY_TOKEN\n")
		c.cfg.Token = newToken
	} else if ok && newToken != c.cfg.Token {
		fmt.Fprintf(os.Stderr, "[gateway] gateway token refreshed from openclaw.json\n")
		c.adoptOpenClawToken(newToken)
	}
	return hint
}

// persistRefreshedToken writes newToken into the on-disk token sources
// that downstream consumers read:
//
//   - <dataDir>/.env              — sourced by operator shells and
//     loaded into the sidecar process env at boot
//   - <dataDir>/hooks/.token      — sourced by claude-code-hook.sh and
//     codex-hook.sh before every call to the API server
//
// The .env file is modified in place, preserving unrelated entries.
// Both OPENCLAW_GATEWAY_TOKEN (legacy env var) and
// DEFENSECLAW_GATEWAY_TOKEN (current canonical name) are updated so
// either naming convention works.
//
// hooks/.token is skipped when the hooks directory is missing (e.g.
// connector not yet set up); that's not an error.
//
// T5.8 symmetry note: both writes below go through
// managed.WriteServiceRuntimeFile with the same PinnedDeploymentMode +
// (implicit) WindowsServiceAccountEnv lookup, so a transient unset of
// either env produces the same failure at both call sites — surfaced
// as the clear "DEFENSECLAW_WINDOWS_SERVICE_ACCOUNT is not set" error
// from T3.5 rather than a divergent pair of "untrusted-owner" vs
// "not-owned-by-caller" wrapper errors. When one call fails the other
// is skipped, so the file pair cannot end up with a mixed old/new
// token from a partial rotation.
func persistRefreshedToken(dataDir, newToken string) error {
	if err := updateEnvFileToken(filepath.Join(dataDir, ".env"), newToken); err != nil {
		return fmt.Errorf("update .env: %w", err)
	}

	hookTokenPath := filepath.Join(dataDir, "hooks", ".token")
	if _, err := os.Stat(filepath.Dir(hookTokenPath)); err == nil {
		content := fmt.Sprintf("DEFENSECLAW_GATEWAY_TOKEN=%q\n", newToken)
		if err := managed.WriteServiceRuntimeFile(
			managed.PinnedDeploymentMode(), hookTokenPath, "gateway hook token", []byte(content),
		); err != nil {
			return fmt.Errorf("write hooks/.token: %w", err)
		}
	}
	return nil
}

// updateEnvFileToken rewrites OPENCLAW_GATEWAY_TOKEN and
// DEFENSECLAW_GATEWAY_TOKEN lines in a .env-style file. Missing keys
// are appended. The file is created if it doesn't exist. Other lines
// (LLM keys, comments, etc.) are preserved verbatim, except the adopted-token
// marker: newToken is an adopted copy, so the marker is replaced with one that
// records it. A later edit of one spelling then shows which value the operator
// saved, and every .env reader prefers it (envvars.ShadowedAdoptedGatewayTokens).
func updateEnvFileToken(path, newToken string) error {
	var lines []string
	// One line ending per file: the one the file already uses (CRLF when it
	// holds any CRLF, otherwise LF). Every line is written with it, so a file
	// never ends up half CRLF; the readers accept both.
	eol := "\n"
	if data, err := os.ReadFile(path); err == nil {
		if bytes.Contains(data, []byte("\r\n")) {
			eol = "\r\n"
		}
		for _, line := range strings.Split(string(data), "\n") {
			line = strings.TrimSuffix(line, "\r")
			if !envvars.IsAdoptedGatewayTokenMarker(line) {
				lines = append(lines, line)
			}
		}
	} else if !os.IsNotExist(err) {
		return err
	}

	keys := map[string]bool{
		"OPENCLAW_GATEWAY_TOKEN":    false,
		"DEFENSECLAW_GATEWAY_TOKEN": false,
	}

	for i, line := range lines {
		trimmed := strings.TrimSpace(line)
		if trimmed == "" || strings.HasPrefix(trimmed, "#") {
			continue
		}
		for k := range keys {
			if strings.HasPrefix(trimmed, k+"=") {
				lines[i] = k + "=" + newToken
				keys[k] = true
				break
			}
		}
	}

	for k, seen := range keys {
		if !seen {
			lines = append(lines, k+"="+newToken)
		}
	}

	// Trim trailing blank lines from the original split artifact and end
	// every line, the last one included, with the file's line ending.
	for len(lines) > 0 && lines[len(lines)-1] == "" {
		lines = lines[:len(lines)-1]
	}
	lines = append(lines, envvars.AdoptedGatewayTokenMarker(newToken))
	out := strings.Join(lines, eol) + eol
	// The whole new file is checked before anything is published: a file over the
	// size every reader accepts would lose the token, so it is refused and the
	// current file stays as it is.
	if err := checkDotEnvSize(path, len(out)); err != nil {
		return err
	}

	return managed.WriteServiceRuntimeFile(
		managed.PinnedDeploymentMode(), path, "gateway dotenv", []byte(out),
	)
}

// shouldRefreshToken reports whether the gateway token is re-read from
// openclaw.json after err.
func (c *Client) shouldRefreshToken(err error) bool {
	return c.cfg.ClawHome != "" && isAuthError(err)
}

// openClawPairingApprovalNeeded reports a connect rejection that only an
// OpenClaw device approval resolves: a device OpenClaw has not paired, a
// changed device identity, or a role or scope upgrade. OpenClaw sends these
// as NOT_PAIRED with a "pairing required: ..." message, or as
// AUTH_SCOPE_MISMATCH.
func openClawPairingApprovalNeeded(err error) bool {
	if err == nil {
		return false
	}
	msg := strings.ToLower(err.Error())
	for _, needle := range []string{
		"not_paired", "not paired", "pairing required", "pairing_required",
		"device identity changed", "higher role than", "more scopes than",
		"scope_mismatch",
	} {
		if strings.Contains(msg, needle) {
			return true
		}
	}
	return false
}

// isAuthError returns true if the error message indicates the OpenClaw
// gateway rejected the connect handshake due to a missing/invalid token
// or device pairing. It decides when the gateway token is re-read from
// openclaw.json.
//
// The needles cover three OpenClaw error formats simultaneously:
//
//  1. The machine-readable code (NOT_PAIRED, AUTH_TOKEN_MISMATCH, etc.) —
//     match these as substrings of the lowercased message.
//  2. The lowercased pairing message prefix ("pairing required") — this
//     is the wire form OpenClaw sends; it is NOT "pairing_required".
//  3. Specific reason fragments ("device identity changed",
//     "higher role than", "more scopes than") that come from the
//     metadata-upgrade / role-upgrade / scope-upgrade subreasons —
//     these signal the device record exists but disagrees with the
//     handshake.
//
// Past bug: this list previously included "pairing_required" (underscore)
// and "not paired" (lowercased phrase), neither of which match the wire
// format. Do not regress this.
func isAuthError(err error) bool {
	if err == nil {
		return false
	}
	msg := strings.ToLower(err.Error())
	// Role-upgrade and scope-upgrade rejections are not token failures:
	// only an OpenClaw approval resolves them
	// (openClawPairingApprovalNeeded). Short-circuit them BEFORE the
	// generic "pairing required" needle below would otherwise match.
	if strings.Contains(msg, "higher role than") ||
		strings.Contains(msg, "more scopes than") {
		return false
	}
	for _, needle := range []string{
		"token_missing", "token_mismatch",
		"auth_token_mismatch", "auth_unauthorized", "auth_required",
		"unauthorized",
		"not_paired",
		"not paired", // legacy prose form ("device not paired with gateway")
		"pairing required",
		"pairing_required",
		"device identity changed",
	} {
		if strings.Contains(msg, needle) {
			return true
		}
	}
	return false
}

// errOpenClawTokenUnreadable reports a gateway.auth.token that is a SecretRef
// DefenseClaw cannot resolve (issue #1404). It never carries the token.
var errOpenClawTokenUnreadable = errors.New("openclaw.json gateway.auth.token is a secret reference DefenseClaw cannot read; " +
	"give DefenseClaw the token with " + openClawGiveTokenStep)

// errOpenClawTokenNotPersisted reports an openclaw.json that parses and holds
// no gateway.auth.token. It is not a failure of the file; it tells the caller
// that the token OpenClaw expects is one DefenseClaw cannot read.
var errOpenClawTokenNotPersisted = errors.New("openclaw.json has no gateway.auth.token")

// readOpenClawGatewayToken reads gateway.auth.token from the OpenClaw
// config file inside the sandbox home directory. The token is a string or
// a SecretRef object; a {"source":"env","id":NAME} reference is resolved
// from the environment, and any other reference returns
// errOpenClawTokenUnreadable instead of a token (issue #1404).
func readOpenClawGatewayToken(sandboxHome string) (string, bool, error) {
	path := filepath.Join(sandboxHome, ".openclaw", "openclaw.json")
	data, err := os.ReadFile(path)
	if err != nil {
		return "", false, nil
	}
	var cfg struct {
		Gateway struct {
			Auth struct {
				Token json.RawMessage `json:"token"`
			} `json:"auth"`
		} `json:"gateway"`
	}
	// OpenClaw reads openclaw.json as JSON5 (comments, bare keys, single
	// quotes, trailing commas).
	if err := json.Unmarshal(jsonc.JSON5ToJSON(data), &cfg); err != nil {
		return "", false, nil
	}
	raw := bytes.TrimSpace(cfg.Gateway.Auth.Token)
	if len(raw) == 0 || bytes.Equal(raw, []byte("null")) {
		return "", false, errOpenClawTokenNotPersisted
	}
	var token string
	if json.Unmarshal(raw, &token) == nil {
		if token == "" {
			return "", false, errOpenClawTokenNotPersisted
		}
		return token, true, nil
	}
	var ref struct {
		Source string `json:"source"`
		ID     string `json:"id"`
	}
	if json.Unmarshal(raw, &ref) == nil && ref.Source == "env" && openClawEnvNameRE.MatchString(ref.ID) {
		if value := os.Getenv(ref.ID); value != "" {
			return value, true, nil
		}
	}
	return "", false, errOpenClawTokenUnreadable
}

// openClawEnvGatewayToken is the token in OPENCLAW_GATEWAY_TOKEN, the one
// OpenClaw itself reads when openclaw.json holds no gateway.auth.token. A
// SecretRef text an earlier build saved there is not a token (#1404).
func openClawEnvGatewayToken() string {
	token := strings.TrimSpace(os.Getenv("OPENCLAW_GATEWAY_TOKEN"))
	if envvars.IsSecretRefText(token) {
		return ""
	}
	return token
}

var openClawEnvNameRE = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*$`)

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

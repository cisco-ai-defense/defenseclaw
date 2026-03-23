package gateway

import (
	"context"
	"encoding/json"
	"fmt"
	"math"
	"net/url"
	"os"
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

	conn     *websocket.Conn
	mu       sync.Mutex
	closed   bool
	lastSeq  int
	pending  map[string]chan *ResponseFrame
	hello    *HelloOK

	// OnEvent is called for every non-connect event frame.
	OnEvent func(EventFrame)
}

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
		pending: make(map[string]chan *ResponseFrame),
		lastSeq: -1,
	}, nil
}

func (c *Client) wsURL() string {
	u := url.URL{
		Scheme: "ws",
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
	conn, resp, err := dialer.DialContext(ctx, target, nil)
	if err != nil {
		return fmt.Errorf("gateway: dial %s: %w", target, err)
	}
	fmt.Fprintf(os.Stderr, "[gateway] websocket connected (%s, http %d)\n",
		time.Since(t0).Round(time.Millisecond), resp.StatusCode)
	c.conn = conn
	c.closed = false

	fmt.Fprintf(os.Stderr, "[gateway] waiting for connect.challenge ...\n")
	nonce, err := c.waitForChallenge(ctx)
	if err != nil {
		conn.Close()
		return fmt.Errorf("gateway: challenge: %w", err)
	}
	fmt.Fprintf(os.Stderr, "[gateway] got challenge nonce=%s...%s (%s elapsed)\n",
		nonce[:min(8, len(nonce))], nonce[max(0, len(nonce)-4):], time.Since(t0).Round(time.Millisecond))

	fmt.Fprintf(os.Stderr, "[gateway] starting read loop before connect handshake\n")
	go c.readLoop()

	fmt.Fprintf(os.Stderr, "[gateway] sending connect (protocol=3, role=operator, device=%s) ...\n",
		c.device.DeviceID)
	hello, err := c.sendConnect(ctx, nonce)
	if err != nil {
		conn.Close()
		return fmt.Errorf("gateway: connect handshake: %w", err)
	}
	fmt.Fprintf(os.Stderr, "[gateway] handshake complete (%s elapsed)\n", time.Since(t0).Round(time.Millisecond))

	c.hello = hello
	return nil
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
	fmt.Fprintf(os.Stderr, "[gateway] received frame (%d bytes): %s\n", len(raw), truncateBytes(raw, 300))

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

	if debugData, err := json.MarshalIndent(params, "  ", "  "); err == nil {
		redacted := redactToken(string(debugData), c.cfg.Token)
		fmt.Fprintf(os.Stderr, "[gateway] connect params:\n  %s\n", redacted)
	}

	fmt.Fprintf(os.Stderr, "[gateway] waiting for connect response ...\n")
	resp, err := c.request(ctx, "connect", params)
	if err != nil {
		return nil, err
	}

	fmt.Fprintf(os.Stderr, "[gateway] connect response: ok=%v payload=%s\n",
		resp.OK, truncateBytes(resp.Payload, 500))
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
	for {
		_, raw, err := c.conn.ReadMessage()
		if err != nil {
			if !c.closed {
				fmt.Fprintf(os.Stderr, "[gateway] read error: %v\n", err)
			}
			return
		}

		var frame RawFrame
		if err := json.Unmarshal(raw, &frame); err != nil {
			fmt.Fprintf(os.Stderr, "[gateway] unparseable frame (%d bytes): %s\n",
				len(raw), truncateBytes(raw, 200))
			continue
		}

		switch frame.Type {
		case "res":
			var resp ResponseFrame
			if err := json.Unmarshal(raw, &resp); err != nil {
				fmt.Fprintf(os.Stderr, "[gateway] bad res frame: %v\n", err)
				continue
			}
			fmt.Fprintf(os.Stderr, "[gateway] ← res id=%s...%s ok=%v\n",
				resp.ID[:min(8, len(resp.ID))], resp.ID[max(0, len(resp.ID)-4):], resp.OK)
			c.mu.Lock()
			ch, ok := c.pending[resp.ID]
			if ok {
				delete(c.pending, resp.ID)
			}
			c.mu.Unlock()
			if ok {
				ch <- &resp
			} else {
				fmt.Fprintf(os.Stderr, "[gateway] orphan response (no pending request): id=%s\n", resp.ID)
			}

		case "event":
			var evt EventFrame
			if err := json.Unmarshal(raw, &evt); err != nil {
				fmt.Fprintf(os.Stderr, "[gateway] bad event frame: %v\n", err)
				continue
			}
			seqStr := "nil"
			if evt.Seq != nil {
				seqStr = fmt.Sprintf("%d", *evt.Seq)
			}
			fmt.Fprintf(os.Stderr, "[gateway] ← event %s seq=%s payload=%s\n",
				evt.Event, seqStr, truncateBytes(evt.Payload, 200))
			if evt.Seq != nil {
				seq := *evt.Seq
				if c.lastSeq >= 0 && seq > c.lastSeq+1 {
					fmt.Fprintf(os.Stderr, "[gateway] sequence gap: expected %d, got %d\n", c.lastSeq+1, seq)
				}
				c.lastSeq = seq
			}
			if c.OnEvent != nil {
				c.OnEvent(evt)
			}

		default:
			fmt.Fprintf(os.Stderr, "[gateway] ← unknown frame type=%s (%d bytes): %s\n",
				frame.Type, len(raw), truncateBytes(raw, 200))
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
	if c.conn != nil {
		return c.conn.Close()
	}
	return nil
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

		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(backoff):
		}

		backoff = time.Duration(math.Min(float64(backoff)*1.7, float64(maxBackoff)))
	}
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

// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package relay

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/gorilla/websocket"
)

// DetachKey is Ctrl-] (the launcher's detach key, PLAN 4.1).
const DetachKey = 0x1d

// AttachOptions configure a client attachment. The launcher (A6) uses this
// client; tests and the hand-driven cells use it through relayctl.
type AttachOptions struct {
	// BaseURL is the relay's http(s) origin as the client reaches it.
	BaseURL string
	Token   string
	Cols    uint16
	Rows    uint16
	// LongPoll uses the HTTP long-poll transport instead of WebSocket.
	LongPoll bool
	// FlatRoutes means BaseURL is a route base (the gateway attach prefix):
	// every route is BaseURL + "/" + route. Without it BaseURL is the relay
	// origin and the routes are under Prefix.
	FlatRoutes bool
	// HTTPClient carries long-poll requests (default http.DefaultClient).
	HTTPClient *http.Client
	// Dialer dials WebSocket (default websocket.DefaultDialer).
	Dialer *websocket.Dialer
	// Resize delivers terminal size changes.
	Resize <-chan Resize
	// OnControl sees every CONTROL frame.
	OnControl func(Control)
}

// AttachResult is how an attachment ended.
type AttachResult struct {
	Detached bool
	ExitCode *int
	Session  string
}

// Attach connects in to the agent's terminal and copies in to the agent and
// the agent's screen to out until the user detaches (Ctrl-]), the agent
// exits or the connection ends.
func Attach(ctx context.Context, in io.Reader, out io.Writer, o AttachOptions) (AttachResult, error) {
	if o.Cols == 0 || o.Rows == 0 {
		o.Cols, o.Rows = 80, 24
	}
	if o.LongPoll {
		return attachPoll(ctx, in, out, o)
	}
	return attachWS(ctx, in, out, o)
}

func sizeQuery(o AttachOptions) string {
	return "?cols=" + strconv.Itoa(int(o.Cols)) + "&rows=" + strconv.Itoa(int(o.Rows))
}

// pumpInput reads in and calls send for each chunk until Ctrl-] or EOF.
func pumpInput(in io.Reader, send func([]byte) error) (detached bool) {
	buf := make([]byte, 4096)
	for {
		n, err := in.Read(buf)
		if n > 0 {
			chunk := buf[:n]
			if i := bytes.IndexByte(chunk, DetachKey); i >= 0 {
				if i > 0 {
					_ = send(chunk[:i])
				}
				return true
			}
			if send(chunk) != nil {
				return false
			}
		}
		if err != nil {
			return false
		}
	}
}

func attachWS(ctx context.Context, in io.Reader, out io.Writer, o AttachOptions) (AttachResult, error) {
	d := o.Dialer
	if d == nil {
		d = &websocket.Dialer{HandshakeTimeout: 15 * time.Second}
	}
	dd := *d
	dd.Subprotocols = []string{Subprotocol}
	u := strings.Replace(strings.Replace(strings.TrimRight(o.BaseURL, "/"), "https://", "wss://", 1), "http://", "ws://", 1)
	h := http.Header{}
	h.Set("Authorization", "Bearer "+o.Token)
	conn, resp, err := dd.DialContext(ctx, RouteURL(o.routeBase(u), RouteWS)+sizeQuery(o), h)
	if err != nil {
		if resp != nil {
			return AttachResult{}, fmt.Errorf("relay refused the attachment (status %d): %w", resp.StatusCode, err)
		}
		return AttachResult{}, err
	}
	defer conn.Close()
	var wmu sync.Mutex
	send := func(frame []byte) error {
		wmu.Lock()
		defer wmu.Unlock()
		return conn.WriteMessage(websocket.BinaryMessage, frame)
	}
	var res AttachResult
	var resMu sync.Mutex // the reader goroutine writes res while the paths below read it
	done := make(chan struct{})
	go func() {
		defer close(done)
		for {
			_, msg, err := conn.ReadMessage()
			if err != nil {
				return
			}
			t, p, err := Decode(msg)
			if err != nil {
				continue
			}
			switch t {
			case FrameData:
				_, _ = out.Write(p)
			case FrameControl:
				c, _ := DecodeControl(p)
				if o.OnControl != nil {
					o.OnControl(c)
				}
				resMu.Lock()
				switch c.Type {
				case CtlHello:
					res.Session = c.Session
				case CtlExit:
					res.ExitCode = c.Code
				}
				resMu.Unlock()
			}
		}
	}()
	if o.Resize != nil {
		go func() {
			for {
				select {
				case <-done:
					return
				case r := <-o.Resize:
					b, _ := json.Marshal(r)
					_ = send(Encode(FrameResize, b))
				}
			}
		}()
	}
	detached := make(chan bool, 1)
	go func() { detached <- pumpInput(in, func(b []byte) error { return send(Encode(FrameData, b)) }) }()
	select {
	case <-done:
	case d := <-detached:
		if d {
			resMu.Lock()
			res.Detached = true
			resMu.Unlock()
			_ = send(EncodeControl(Control{Type: CtlDetach}))
			wmu.Lock()
			_ = conn.WriteControl(websocket.CloseMessage, websocket.FormatCloseMessage(websocket.CloseNormalClosure, "detach"), time.Now().Add(time.Second))
			wmu.Unlock()
		}
	case <-ctx.Done():
	}
	resMu.Lock()
	defer resMu.Unlock()
	return res, nil
}

func attachPoll(ctx context.Context, in io.Reader, out io.Writer, o AttachOptions) (AttachResult, error) {
	c := o.HTTPClient
	if c == nil {
		c = http.DefaultClient
	}
	base := o.routeBase(o.BaseURL)
	do := func(ctx context.Context, method, route string, body []byte) (*http.Response, error) {
		req, err := http.NewRequestWithContext(ctx, method, RouteURL(base, route), bytes.NewReader(body))
		if err != nil {
			return nil, err
		}
		req.Header.Set("Authorization", "Bearer "+o.Token)
		return c.Do(req)
	}
	resp, err := do(ctx, http.MethodPost, RoutePoll+sizeQuery(o), nil)
	if err != nil {
		return AttachResult{}, err
	}
	var open struct {
		ID string `json:"id"`
	}
	_ = json.NewDecoder(resp.Body).Decode(&open)
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK || open.ID == "" {
		return AttachResult{}, fmt.Errorf("relay refused the attachment (status %d)", resp.StatusCode)
	}
	path := RoutePoll + "/" + open.ID
	var res AttachResult
	var resMu sync.Mutex // the follower goroutine writes res while the paths below read it
	var outMu sync.Mutex
	send := func(frame []byte) error {
		r, err := do(ctx, http.MethodPost, path, AppendStream(nil, frame))
		if err != nil {
			return err
		}
		r.Body.Close()
		if r.StatusCode != http.StatusNoContent {
			return fmt.Errorf("relay write status %d", r.StatusCode)
		}
		return nil
	}
	done := make(chan struct{})
	go func() {
		defer close(done)
		cursor := "0"
		for ctx.Err() == nil {
			r, err := do(ctx, http.MethodGet, path+"?cursor="+cursor, nil)
			if err != nil {
				return
			}
			body, _ := io.ReadAll(io.LimitReader(r.Body, 8*MaxFrame))
			r.Body.Close()
			if r.StatusCode == http.StatusGone || r.StatusCode != http.StatusOK {
				return
			}
			if next := r.Header.Get("X-Dcrelay-Cursor"); next != "" {
				cursor = next
			}
			frames, err := SplitStream(body)
			if err != nil {
				return
			}
			for _, f := range frames {
				t, p, err := Decode(f)
				if err != nil {
					continue
				}
				switch t {
				case FrameData:
					outMu.Lock()
					_, _ = out.Write(p)
					outMu.Unlock()
				case FrameControl:
					cc, _ := DecodeControl(p)
					if o.OnControl != nil {
						o.OnControl(cc)
					}
					resMu.Lock()
					switch cc.Type {
					case CtlHello:
						res.Session = cc.Session
					case CtlExit:
						res.ExitCode = cc.Code
					}
					resMu.Unlock()
				}
			}
		}
	}()
	if o.Resize != nil {
		go func() {
			for {
				select {
				case <-done:
					return
				case rs := <-o.Resize:
					b, _ := json.Marshal(rs)
					_ = send(Encode(FrameResize, b))
				}
			}
		}()
	}
	detached := make(chan bool, 1)
	go func() { detached <- pumpInput(in, func(b []byte) error { return send(Encode(FrameData, b)) }) }()
	select {
	case <-done:
	case d := <-detached:
		if d {
			resMu.Lock()
			res.Detached = true
			resMu.Unlock()
			if r, err := do(context.Background(), http.MethodDelete, path, nil); err == nil {
				r.Body.Close()
			}
		}
	case <-ctx.Done():
	}
	resMu.Lock()
	defer resMu.Unlock()
	return res, nil
}

// routeBase is where the routes begin for origin (BaseURL, or its ws:// form).
func (o AttachOptions) routeBase(origin string) string {
	if o.FlatRoutes {
		return strings.TrimRight(origin, "/")
	}
	return RouteBase(origin)
}

// RunTask starts a headless task and copies its NDJSON events to emit until
// it exits. routeBase is where the relay routes begin: RouteBase(origin)
// for a relay reached directly, the attach prefix through the gateway.
// It returns the task's exit code.
func RunTask(ctx context.Context, c *http.Client, routeBase, token string, req TaskRequest, emit func(TaskEvent)) (int, error) {
	if c == nil {
		c = http.DefaultClient
	}
	body, _ := json.Marshal(req)
	r, err := http.NewRequestWithContext(ctx, http.MethodPost, RouteURL(routeBase, RouteTask), bytes.NewReader(body))
	if err != nil {
		return -1, err
	}
	r.Header.Set("Authorization", "Bearer "+token)
	r.Header.Set("Content-Type", "application/json")
	resp, err := c.Do(r)
	if err != nil {
		return -1, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		msg, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		return -1, fmt.Errorf("relay refused the task (status %d): %s", resp.StatusCode, strings.TrimSpace(string(msg)))
	}
	dec := json.NewDecoder(resp.Body)
	for {
		var e TaskEvent
		if err := dec.Decode(&e); err != nil {
			if errors.Is(err, io.EOF) {
				return -1, errors.New("the task log ended without an exit")
			}
			return -1, err
		}
		if emit != nil {
			emit(e)
		}
		if e.Type == "exit" && e.Code != nil {
			return *e.Code, nil
		}
	}
}

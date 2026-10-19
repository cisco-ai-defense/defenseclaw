// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package sandboxapi

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/url"
	"sync"
	"sync/atomic"
	"time"

	"github.com/gorilla/websocket"
)

// ClientAttachment is one bounded connection to an already admitted process.
// Closing this transport asks the manager to stop its attachment; it is not an
// independent observation of native cleanup. Only the final exit event carries
// the server's cleanup barrier. A canceled operation aborts the whole transport.
type ClientAttachment struct {
	conn                      *websocket.Conn
	ctx                       context.Context
	cancel                    context.CancelFunc
	stop                      func() bool
	deadline                  time.Time
	writer                    chan struct{}
	reader                    chan struct{}
	closed                    atomic.Bool
	once                      sync.Once
	closeErr                  error
	eof                       bool // writer owns input state
	inputBytes, inputFrames   uint64
	outputBytes, outputFrames uint64 // reader owns output state
}

// Attach uses the same API authority, credentials, TLS policy and owned socket
// dialer as REST calls. It does not follow redirects, put tokens in URLs, launch
// commands, or fall back to another runtime. ctx bounds the entire attachment.
func (c *Client) Attach(ctx context.Context, name string, request AttachRequest) (*ClientAttachment, error) {
	if c == nil || !attachID.MatchString(name) || request.Validate() != nil {
		return nil, ErrAttachProtocol
	}
	u, err := url.Parse(c.BaseURL)
	if err != nil || u.User != nil || u.Host == "" || (u.Scheme != "http" && u.Scheme != "https") || (u.Path != "" && u.Path != "/") || u.RawQuery != "" || u.Fragment != "" || u.ForceQuery {
		return nil, ErrAttachProtocol
	}
	transport := http.DefaultTransport
	if c.HTTP != nil && c.HTTP.Transport != nil {
		transport = c.HTTP.Transport
	}
	t, ok := transport.(*http.Transport)
	if !ok || (t.Dial != nil && t.DialContext == nil) || (t.DialTLS != nil && t.DialTLSContext == nil) || t.OnProxyConnectResponse != nil || t.GetProxyConnectHeader != nil || len(t.ProxyConnectHeader) != 0 { //nolint:staticcheck // Reject legacy dialers that cannot honor attachment cancellation.
		return nil, errors.New("sandbox attachment requires the API's context-aware HTTP transport")
	}
	dialer := websocket.Dialer{NetDialContext: t.DialContext, NetDialTLSContext: t.DialTLSContext,
		Proxy: t.Proxy, HandshakeTimeout: 5 * time.Second, ReadBufferSize: 4096, WriteBufferSize: 4096}
	if t.ResponseHeaderTimeout > 0 && t.ResponseHeaderTimeout < dialer.HandshakeTimeout {
		dialer.HandshakeTimeout = t.ResponseHeaderTimeout
	}
	if t.TLSClientConfig != nil {
		dialer.TLSClientConfig = t.TLSClientConfig.Clone()
		dialer.TLSClientConfig.NextProtos = []string{"http/1.1"}
	}
	lifetime := time.Duration(request.TimeoutSeconds) * time.Second
	if c.HTTP != nil && c.HTTP.Timeout > 0 && c.HTTP.Timeout < lifetime {
		lifetime = c.HTTP.Timeout
	}
	owned, cancel := context.WithTimeout(ctx, lifetime)
	defer func() {
		if err != nil {
			cancel()
		}
	}()
	u.Path = sandboxPath(name, "attach")
	req, err := c.newRequest(owned, http.MethodGet, u.Path, nil, nil)
	if err != nil {
		return nil, err
	}
	if u.Scheme == "https" {
		u.Scheme = "wss"
	} else {
		u.Scheme = "ws"
	}
	conn, response, err := dialer.DialContext(owned, u.String(), req.Header)
	if err != nil {
		if response != nil {
			defer response.Body.Close()
			if response.StatusCode != http.StatusSwitchingProtocols {
				return nil, decodeError(response)
			}
		}
		return nil, errors.New("sandbox attachment handshake failed")
	}
	deadline, _ := owned.Deadline()
	a := &ClientAttachment{conn: conn, ctx: owned, cancel: cancel, deadline: deadline,
		writer: make(chan struct{}, 1), reader: make(chan struct{}, 1)}
	a.stop = context.AfterFunc(owned, func() { _ = conn.Close() })
	conn.SetReadLimit(AttachFrameBytes)
	if err = conn.SetReadDeadline(deadline); err == nil {
		err = a.write(request)
	}
	if err == nil {
		err = a.operationError(owned)
	}
	if err != nil {
		_ = a.Close()
		return nil, err
	}
	return a, nil
}

func (a *ClientAttachment) write(value any) error {
	deadline := time.Now().Add(5 * time.Second)
	if a.deadline.Before(deadline) {
		deadline = a.deadline
	}
	if !time.Now().Before(deadline) {
		return context.DeadlineExceeded
	}
	if err := a.conn.SetWriteDeadline(deadline); err != nil {
		return err
	}
	return a.conn.WriteJSON(value)
}

func (a *ClientAttachment) enter(ctx context.Context, slot chan struct{}) error {
	select {
	case slot <- struct{}{}:
		if ctx.Err() != nil || a.ctx.Err() != nil || a.closed.Load() {
			<-slot
			if ctx.Err() != nil {
				return ctx.Err()
			}
			if a.ctx.Err() != nil {
				return a.ctx.Err()
			}
			return io.EOF
		}
		return nil
	case <-ctx.Done():
		return ctx.Err()
	case <-a.ctx.Done():
		return a.ctx.Err()
	}
}

func (a *ClientAttachment) operationError(ctx context.Context) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := a.ctx.Err(); err != nil {
		return err
	}
	if !time.Now().Before(a.deadline) {
		return context.DeadlineExceeded
	}
	return nil
}

// Send preserves binary stdin and enforces the aggregate input bound and EOF
// ordering locally as well as on the server. One sender and receiver may run
// concurrently; waiting for another caller also observes ctx.
func (a *ClientAttachment) Send(ctx context.Context, frame AttachInput) (err error) {
	if frame.Validate() != nil {
		return ErrAttachProtocol
	}
	if err = a.enter(ctx, a.writer); err != nil {
		_ = a.Close()
		return err
	}
	defer func() { <-a.writer }()
	if (frame.Kind == "stdin" || frame.Kind == "stdin_eof") && a.eof {
		return ErrAttachProtocol
	}
	if a.inputFrames >= 8192 || uint64(len(frame.Data)) > (64<<20)-a.inputBytes {
		return ErrAttachProtocol
	}
	stop := context.AfterFunc(ctx, func() { _ = a.conn.Close() })
	defer stop()
	err = a.write(frame)
	if err == nil {
		err = a.operationError(ctx)
	}
	if err != nil {
		_ = a.Close()
		return err
	}
	a.inputFrames++
	a.inputBytes += uint64(len(frame.Data))
	if frame.Kind == "stdin_eof" {
		a.eof = true
	}
	return nil
}

// Receive refuses ambiguous, oversized and non-text server frames. A connection
// ending without the final exit event is an error, never a successful agent run.
func (a *ClientAttachment) Receive(ctx context.Context) (event AttachEvent, err error) {
	if err = a.enter(ctx, a.reader); err != nil {
		_ = a.Close()
		return event, err
	}
	defer func() { <-a.reader }()
	stop := context.AfterFunc(ctx, func() { _ = a.conn.Close() })
	defer stop()
	kind, raw, err := a.conn.ReadMessage()
	if err == nil {
		err = a.operationError(ctx)
	}
	if err == nil && kind == websocket.TextMessage {
		event, err = DecodeAttachEvent(raw)
	} else if err == nil {
		err = ErrAttachProtocol
	}
	if err == nil && (a.outputFrames >= 8192 || uint64(len(event.Data)) > (64<<20)-a.outputBytes) {
		err = ErrAttachProtocol
	}
	if err == nil {
		err = a.operationError(ctx)
	}
	if err != nil {
		_ = a.Close()
		return AttachEvent{}, err
	}
	a.outputFrames++
	a.outputBytes += uint64(len(event.Data))
	if event.Kind == "exit" || event.Kind == "failure" {
		_ = a.Close()
	}
	return event, nil
}

// Close only releases the socket. It makes no native cleanup claim.
func (a *ClientAttachment) Close() error {
	a.once.Do(func() {
		a.closed.Store(true)
		a.stop()
		a.cancel()
		a.closeErr = a.conn.Close()
	})
	return a.closeErr
}

// DecodeAttachEvent applies the same exact-key rules to the nested exit object.
func DecodeAttachEvent(raw []byte) (AttachEvent, error) {
	var wire struct {
		Kind string          `json:"kind"`
		Data []byte          `json:"data,omitempty"`
		Exit json.RawMessage `json:"exit,omitempty"`
		Code string          `json:"code,omitempty"`
	}
	if err := decodeAttach(raw, map[string]bool{"kind": true, "data": true, "exit": true, "code": true}, &wire); err != nil {
		return AttachEvent{}, err
	}
	event := AttachEvent{Kind: wire.Kind, Data: wire.Data, Code: wire.Code}
	if wire.Exit != nil {
		var fields map[string]json.RawMessage
		if json.Unmarshal(wire.Exit, &fields) != nil || len(fields) != 3 || fields["code"] == nil || fields["timed_out"] == nil || fields["truncated"] == nil {
			return AttachEvent{}, ErrAttachProtocol
		}
		for _, value := range fields {
			if string(value) == "null" {
				return AttachEvent{}, ErrAttachProtocol
			}
		}
		event.Exit = new(AttachExit)
		if err := decodeAttach(wire.Exit, map[string]bool{"code": true, "timed_out": true, "truncated": true}, event.Exit); err != nil {
			return AttachEvent{}, err
		}
	}
	return event, event.Validate()
}

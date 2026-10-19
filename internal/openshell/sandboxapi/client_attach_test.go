// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package sandboxapi

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/gorilla/websocket"
)

func TestAttachmentClientPreservesAuthorityDialerBinaryAndExit(t *testing.T) {
	done := make(chan error, 1)
	data := []byte{0, 0xff, 0xc0, '\n'}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != PathSandboxes+"/owned/attach" || r.URL.RawQuery != "" || r.Header.Get("Authorization") != "Bearer private-token" || r.Header.Get(ClientHeader) != ClientName {
			done <- errors.New("API authority or authentication changed")
			http.Error(w, "bad request", 400)
			return
		}
		conn, err := (&websocket.Upgrader{}).Upgrade(w, r, nil)
		if err != nil {
			done <- err
			return
		}
		defer conn.Close()
		_, raw, err := conn.ReadMessage()
		req, decode := DecodeAttachRequest(raw)
		if err != nil || decode != nil || req.SessionID != "session:owned" {
			done <- ErrAttachProtocol
			return
		}
		for _, expected := range []string{"stdin", "stdin_eof"} {
			_, raw, err = conn.ReadMessage()
			frame, decode := DecodeAttachInput(raw)
			if err != nil || decode != nil || frame.Kind != expected || (expected == "stdin" && !bytes.Equal(frame.Data, data)) {
				done <- ErrAttachProtocol
				return
			}
		}
		if err := conn.WriteJSON(AttachEvent{Kind: "stdout", Data: data}); err != nil {
			done <- err
			return
		}
		done <- conn.WriteJSON(AttachEvent{Kind: "exit", Exit: &AttachExit{Code: 23}})
	}))
	defer server.Close()
	client := NewClient("http://sandbox-daemon", "private-token")
	dials := 0
	client.HTTP = &http.Client{Transport: &http.Transport{DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
		dials++
		return (&net.Dialer{}).DialContext(ctx, "tcp", strings.TrimPrefix(server.URL, "http://"))
	}}}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	a, err := client.Attach(ctx, "owned", AttachRequest{Version: 1, SessionID: "session:owned", TimeoutSeconds: 3})
	if err != nil {
		t.Fatal(err)
	}
	defer a.Close()
	if err := a.Send(ctx, AttachInput{Kind: "stdin", Data: data}); err != nil {
		t.Fatal(err)
	}
	if err := a.Send(ctx, AttachInput{Kind: "stdin_eof"}); err != nil {
		t.Fatal(err)
	}
	if err := a.Send(ctx, AttachInput{Kind: "stdin", Data: data}); !errors.Is(err, ErrAttachProtocol) {
		t.Fatalf("post-EOF input: %v", err)
	}
	event, err := a.Receive(ctx)
	if err != nil || event.Kind != "stdout" || !bytes.Equal(event.Data, data) {
		t.Fatalf("output changed: %+v %v", event, err)
	}
	event, err = a.Receive(ctx)
	if err != nil || event.Exit == nil || event.Exit.Code != 23 {
		t.Fatalf("exit changed: %+v %v", event, err)
	}
	if _, err := a.Receive(ctx); err == nil {
		t.Fatal("terminal attachment remained open")
	}
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	if dials != 1 {
		t.Fatalf("API dialer count %d", dials)
	}
}

func TestAttachmentClientCancellationUnblocksReceiveAndKeepsNoWorker(t *testing.T) {
	disconnected := make(chan struct{})
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		conn, err := (&websocket.Upgrader{}).Upgrade(w, r, nil)
		if err != nil {
			return
		}
		defer conn.Close()
		for {
			if _, _, err := conn.ReadMessage(); err != nil {
				close(disconnected)
				return
			}
		}
	}))
	defer server.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	a, err := NewClient(server.URL, "token").Attach(ctx, "owned", AttachRequest{Version: 1, SessionID: "owned", TimeoutSeconds: 3})
	if err != nil {
		t.Fatal(err)
	}
	defer a.Close()
	read, stop := context.WithTimeout(ctx, 30*time.Millisecond)
	defer stop()
	if _, err := a.Receive(read); err == nil {
		t.Fatal("canceled receive succeeded")
	}
	select {
	case <-disconnected:
	case <-ctx.Done():
		t.Fatal("canceled receive retained socket")
	}
}

func TestAttachmentClientCancelledSlotWaitAbortsOwnedSocket(t *testing.T) {
	for _, kind := range []string{"send", "receive"} {
		t.Run(kind, func(t *testing.T) {
			disconnected := make(chan struct{})
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				conn, err := (&websocket.Upgrader{}).Upgrade(w, r, nil)
				if err != nil {
					return
				}
				defer conn.Close()
				for {
					if _, _, err := conn.ReadMessage(); err != nil {
						close(disconnected)
						return
					}
				}
			}))
			defer server.Close()
			ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
			defer cancel()
			a, err := NewClient(server.URL, "token").Attach(ctx, "owned", AttachRequest{Version: 1, SessionID: "owned", TimeoutSeconds: 3})
			if err != nil {
				t.Fatal(err)
			}
			defer a.Close()
			slot := a.writer
			if kind == "receive" {
				slot = a.reader
			}
			slot <- struct{}{} // represent another caller owning this operation slot
			defer func() { <-slot }()
			operation, stop := context.WithCancel(ctx)
			stop()
			if kind == "send" {
				err = a.Send(operation, AttachInput{Kind: "stdin_eof"})
			} else {
				_, err = a.Receive(operation)
			}
			if !errors.Is(err, context.Canceled) {
				t.Fatalf("slot cancellation changed: %v", err)
			}
			select {
			case <-disconnected:
			case <-ctx.Done():
				t.Fatal("canceled slot wait retained session socket")
			}
		})
	}
}

func TestAttachmentClientRefusesRedirectBeforeCredentialForwarding(t *testing.T) {
	forwarded := false
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { forwarded = true; http.Error(w, "unexpected", 500) }))
	defer target.Close()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, target.URL, http.StatusTemporaryRedirect)
	}))
	defer server.Close()
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if _, err := NewClient(server.URL, "token").Attach(ctx, "owned", AttachRequest{Version: 1, SessionID: "owned", TimeoutSeconds: 1}); err == nil {
		t.Fatal("redirect accepted")
	}
	if forwarded {
		t.Fatal("credential-bearing attachment followed redirect")
	}
}

func TestAttachmentEventRefusesAmbiguousExitAndPrematureEOF(t *testing.T) {
	for _, raw := range []string{
		`{"kind":"exit","exit":{}}`,
		`{"kind":"exit","exit":{"code":null,"timed_out":false,"truncated":false}}`,
		`{"kind":"exit","exit":{"code":0,"code":1,"timed_out":false,"truncated":false}}`,
		`{"kind":"exit","exit":{"Code":0,"timed_out":false,"truncated":false}}`,
		`{"kind":"exit","exit":{"code":0,"timed_out":false,"truncated":false,"argv":[]}}`,
		`{"kind":"stdout","data":"AA==","Kind":"exit"}`,
	} {
		if _, err := DecodeAttachEvent([]byte(raw)); err == nil {
			t.Fatalf("accepted %s", raw)
		}
	}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		conn, err := (&websocket.Upgrader{}).Upgrade(w, r, nil)
		if err == nil {
			_, _, _ = conn.ReadMessage()
			_ = conn.Close()
		}
	}))
	defer server.Close()
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	a, err := NewClient(server.URL, "").Attach(ctx, "owned", AttachRequest{Version: 1, SessionID: "owned", TimeoutSeconds: 1})
	if err != nil {
		t.Fatal(err)
	}
	defer a.Close()
	if _, err := a.Receive(ctx); err == nil || errors.Is(err, io.EOF) {
		t.Fatalf("premature EOF treated as terminal success: %v", err)
	}
}

// The OS accepted a write just before cancellation, but its result returns
// afterward. A successful socket write alone must not become a successful Send.
type attachmentDelayedWrite struct {
	net.Conn
	gate    atomic.Bool
	writes  atomic.Int32
	gateAt  int32
	written chan struct{}
	release chan struct{}
}

func (c *attachmentDelayedWrite) Write(p []byte) (int, error) {
	n, err := c.Conn.Write(p)
	count := c.writes.Add(1)
	if (c.gate.Load() || c.gateAt == count) && err == nil {
		close(c.written)
		<-c.release
	}
	return n, err
}

func TestAttachmentClientRejectsAdmissionWriteAfterCancellation(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		conn, err := (&websocket.Upgrader{}).Upgrade(w, r, nil)
		if err != nil {
			return
		}
		defer conn.Close()
		for {
			if _, _, err := conn.ReadMessage(); err != nil {
				return
			}
		}
	}))
	defer server.Close()
	ctx, done := context.WithTimeout(context.Background(), 3*time.Second)
	defer done()
	client := NewClient(server.URL, "token")
	ready := make(chan *attachmentDelayedWrite, 1)
	client.HTTP = &http.Client{Transport: &http.Transport{DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
		conn, err := (&net.Dialer{}).DialContext(ctx, network, addr)
		if err != nil {
			return nil, err
		}
		held := &attachmentDelayedWrite{Conn: conn, written: make(chan struct{}), release: make(chan struct{}), gateAt: 2}
		ready <- held
		return held, nil
	}}}
	operation, stop := context.WithCancel(ctx)
	defer stop()
	result := make(chan error, 1)
	go func() {
		a, err := client.Attach(operation, "owned", AttachRequest{Version: 1, SessionID: "owned", TimeoutSeconds: 3})
		if a != nil {
			_ = a.Close()
		}
		result <- err
	}()
	var held *attachmentDelayedWrite
	select {
	case held = <-ready:
	case <-ctx.Done():
		<-result
		t.Fatal("no API dial")
	}
	select {
	case <-held.written:
	case <-ctx.Done():
		close(held.release)
		<-result
		t.Fatal("admission write never completed")
	}
	stop()
	close(held.release)
	if err := <-result; !errors.Is(err, context.Canceled) {
		t.Fatalf("expired admission succeeded: %v", err)
	}
}

func TestAttachmentClientRejectsWriteSuccessAfterCancellation(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		conn, err := (&websocket.Upgrader{}).Upgrade(w, r, nil)
		if err != nil {
			return
		}
		defer conn.Close()
		for {
			if _, _, err := conn.ReadMessage(); err != nil {
				return
			}
		}
	}))
	defer server.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	client := NewClient(server.URL, "token")
	var held *attachmentDelayedWrite
	client.HTTP = &http.Client{Transport: &http.Transport{DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
		conn, err := (&net.Dialer{}).DialContext(ctx, network, addr)
		if err != nil {
			return nil, err
		}
		held = &attachmentDelayedWrite{Conn: conn, written: make(chan struct{}), release: make(chan struct{})}
		return held, nil
	}}}
	a, err := client.Attach(ctx, "owned", AttachRequest{Version: 1, SessionID: "owned", TimeoutSeconds: 3})
	if err != nil {
		t.Fatal(err)
	}
	defer a.Close()
	held.gate.Store(true)
	operation, stop := context.WithCancel(ctx)
	defer stop()
	result := make(chan error, 1)
	go func() { result <- a.Send(operation, AttachInput{Kind: "stdin", Data: []byte("x")}) }()
	select {
	case <-held.written:
	case <-ctx.Done():
		close(held.release)
		<-result
		t.Fatal("write never completed")
	}
	stop()
	close(held.release)
	if err := <-result; !errors.Is(err, context.Canceled) {
		t.Fatalf("late write succeeded: %v", err)
	}
}

// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"bytes"
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/gorilla/websocket"

	"github.com/defenseclaw/defenseclaw/internal/openshell/sandboxapi"
	"github.com/defenseclaw/defenseclaw/internal/sandboxruntime"
)

type fakeAttachment struct {
	mu               sync.Mutex
	inputs           []sandboxapi.AttachInput
	events           chan sandboxapi.AttachEvent
	closed           chan struct{}
	closeOnce        sync.Once
	closes           atomic.Int32
	closeErr         error
	closeGate        <-chan struct{}
	closeEntered     chan struct{}
	cleanupContextOK atomic.Bool
	sendGate         <-chan struct{}
	sendEntered      chan struct{}
	sendErr          error
}

func newFakeAttachment() *fakeAttachment {
	return &fakeAttachment{events: make(chan sandboxapi.AttachEvent, 8), closed: make(chan struct{})}
}
func (f *fakeAttachment) Send(ctx context.Context, input sandboxapi.AttachInput) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if f.sendErr != nil {
		// Model the native race: an exit arrives as the pending input fails.
		f.events <- sandboxapi.AttachEvent{Kind: "exit", Exit: &sandboxapi.AttachExit{Code: 0}}
		return f.sendErr
	}
	if f.sendGate != nil {
		close(f.sendEntered)
		select {
		case <-f.sendGate:
		case <-ctx.Done():
			return ctx.Err()
		}
	}
	f.mu.Lock()
	f.inputs = append(f.inputs, input)
	f.mu.Unlock()
	return nil
}
func (f *fakeAttachment) Receive(ctx context.Context) (sandboxapi.AttachEvent, error) {
	select {
	case frame := <-f.events:
		return frame, nil
	case <-ctx.Done():
		return sandboxapi.AttachEvent{}, ctx.Err()
	}
}
func (f *fakeAttachment) Close(ctx context.Context) error {
	f.closes.Add(1)
	_, bounded := ctx.Deadline()
	f.cleanupContextOK.Store(ctx.Err() == nil && bounded)
	if f.closeEntered != nil {
		close(f.closeEntered)
	}
	if f.closeGate != nil {
		select {
		case <-f.closeGate:
		case <-ctx.Done():
			return ctx.Err()
		}
	}
	f.closeOnce.Do(func() { close(f.closed) })
	return f.closeErr
}

type attachController struct {
	*fakeSandboxController
	attachment       *fakeAttachment
	attached         atomic.Int32
	request          sandboxapi.AttachRequest
	name             string
	admissionBounded atomic.Bool
	entered          chan struct{}
}

func (c *attachController) Attach(ctx context.Context, name string, req sandboxapi.AttachRequest) (sandboxruntime.Attachment, error) {
	c.name, c.request = name, req
	deadline, bounded := ctx.Deadline()
	c.admissionBounded.Store(bounded && time.Until(deadline) <= 5*time.Second)
	c.attached.Add(1)
	close(c.entered)
	return c.attachment, nil
}

func attachmentTestServer(t *testing.T) (*APIServer, *attachController, *httptest.Server) {
	t.Helper()
	c := &attachController{fakeSandboxController: &fakeSandboxController{}, attachment: newFakeAttachment(), entered: make(chan struct{})}
	a, handler := sandboxTestAPI(t, c, true)
	server := httptest.NewServer(handler)
	t.Cleanup(server.Close)
	return a, c, server
}
func dialAttachment(t *testing.T, server *httptest.Server) *websocket.Conn {
	return dialAttachmentTimeout(t, server, 10)
}

func dialAttachmentTimeout(t *testing.T, server *httptest.Server, timeoutSeconds uint32) *websocket.Conn {
	t.Helper()
	h := http.Header{"Authorization": []string{"Bearer test-token"}, sandboxapi.ClientHeader: []string{sandboxapi.ClientName}}
	conn, resp, err := websocket.DefaultDialer.Dial("ws"+strings.TrimPrefix(server.URL, "http")+sandboxapi.PathSandboxes+"/box/attach", h)
	if err != nil {
		t.Fatalf("attachment handshake: %v response=%v", err, resp)
	}
	t.Cleanup(func() { _ = conn.Close() })
	if err := conn.WriteJSON(sandboxapi.AttachRequest{Version: 1, SessionID: "owned:1", TimeoutSeconds: timeoutSeconds}); err != nil {
		t.Fatal(err)
	}
	return conn
}
func awaitAttachmentClose(t *testing.T, f *fakeAttachment) {
	t.Helper()
	select {
	case <-f.closed:
	case <-time.After(3 * time.Second):
		t.Fatal("attachment cleanup did not complete")
	}
	if !f.cleanupContextOK.Load() {
		t.Fatal("cleanup inherited canceled/unbounded request context")
	}
}

func TestSandboxAttachRequiresAuthenticationCSRFOriginAndQualifiedController(t *testing.T) {
	_, c, server := attachmentTestServer(t)
	for _, test := range []struct {
		name, token, marker, origin, query string
		status                             int
	}{
		{"no token", "", sandboxapi.ClientName, "", "", 401},
		{"no marker", "Bearer test-token", "", "", "", 403},
		{"foreign origin", "Bearer test-token", sandboxapi.ClientName, "https://attacker.invalid", "", 403},
		{"query credential", "Bearer test-token", sandboxapi.ClientName, "", "?token=secret", 400},
	} {
		t.Run(test.name, func(t *testing.T) {
			h := http.Header{"Authorization": []string{test.token}, sandboxapi.ClientHeader: []string{test.marker}, "Origin": []string{test.origin}}
			conn, resp, err := websocket.DefaultDialer.Dial("ws"+strings.TrimPrefix(server.URL, "http")+sandboxapi.PathSandboxes+"/box/attach"+test.query, h)
			if conn != nil {
				_ = conn.Close()
			}
			if resp != nil {
				defer resp.Body.Close()
			}
			if err == nil || resp == nil || resp.StatusCode != test.status {
				t.Fatalf("unexpected handshake %v, %v", resp, err)
			}
		})
	}
	if c.attached.Load() != 0 {
		t.Fatal("refused request reached attachment admission")
	}
	_, h := sandboxTestAPI(t, &fakeSandboxController{}, true)
	w := serve(h, sandboxRequest(http.MethodGet, sandboxapi.PathSandboxes+"/box/attach", ""))
	if w.Code != http.StatusServiceUnavailable {
		t.Fatalf("unqualified controller status=%d", w.Code)
	}
}

func TestSandboxAttachmentBinaryIOEOFAndCleanupBeforeExit(t *testing.T) {
	_, c, server := attachmentTestServer(t)
	gate := make(chan struct{})
	c.attachment.closeGate = gate
	conn := dialAttachment(t, server)
	select {
	case <-c.entered:
	case <-time.After(3 * time.Second):
		t.Fatal("attachment admission did not finish")
	}
	data := []byte{0, 0xff, '\n', 0x80}
	if err := conn.WriteJSON(sandboxapi.AttachInput{Kind: "stdin", Data: data}); err != nil {
		t.Fatal(err)
	}
	if err := conn.WriteJSON(sandboxapi.AttachInput{Kind: "stdin_eof"}); err != nil {
		t.Fatal(err)
	}
	// Synchronize on Send rather than sleeping or guessing when EOF arrived.
	deadline := time.Now().Add(2 * time.Second)
	for {
		c.attachment.mu.Lock()
		n := len(c.attachment.inputs)
		c.attachment.mu.Unlock()
		if n == 2 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("input not delivered")
		}
		time.Sleep(time.Millisecond)
	}
	c.attachment.events <- sandboxapi.AttachEvent{Kind: "stdout", Data: data}
	c.attachment.events <- sandboxapi.AttachEvent{Kind: "stderr", Data: []byte("diagnostic")}
	c.attachment.events <- sandboxapi.AttachEvent{Kind: "exit", Exit: &sandboxapi.AttachExit{Code: 23}}
	for _, kind := range []string{"stdout", "stderr"} {
		var event sandboxapi.AttachEvent
		if err := conn.ReadJSON(&event); err != nil || event.Kind != kind {
			t.Fatalf("event=%+v err=%v", event, err)
		}
		if kind == "stdout" && !bytes.Equal(event.Data, data) {
			t.Fatal("binary output changed")
		}
	}
	delivered := make(chan sandboxapi.AttachEvent, 1)
	go func() { var event sandboxapi.AttachEvent; _ = conn.ReadJSON(&event); delivered <- event }()
	select {
	case <-delivered:
		t.Fatal("exit published before native cleanup")
	case <-time.After(40 * time.Millisecond):
	}
	close(gate)
	select {
	case event := <-delivered:
		if event.Kind != "exit" || event.Exit == nil || event.Exit.Code != 23 {
			t.Fatalf("exit=%+v", event)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("no exit after cleanup")
	}
	awaitAttachmentClose(t, c.attachment)
	if c.name != "box" || c.request.SessionID != "owned:1" || !c.admissionBounded.Load() {
		t.Fatal("session/admission binding changed")
	}
	c.attachment.mu.Lock()
	defer c.attachment.mu.Unlock()
	if !bytes.Equal(c.attachment.inputs[0].Data, data) || c.attachment.inputs[1].Kind != "stdin_eof" {
		t.Fatal("binary input/EOF changed")
	}
}

func TestSandboxAttachmentFailureDisconnectAndControllerReplacement(t *testing.T) {
	for _, failure := range []bool{false, true} {
		t.Run(map[bool]string{false: "disconnect", true: "native cleanup failure"}[failure], func(t *testing.T) {
			a, c, server := attachmentTestServer(t)
			if failure {
				c.attachment.closeErr = errors.New("private provider detail must not be sent")
			}
			conn := dialAttachment(t, server)
			select {
			case <-c.entered:
			case <-time.After(3 * time.Second):
				t.Fatal("attachment admission did not finish")
			}
			// A Receive-blocked stream must not pin controller replacement.
			replaced := make(chan struct{})
			go func() { a.SetSandboxController(nil); close(replaced) }()
			select {
			case <-replaced:
			case <-time.After(time.Second):
				t.Fatal("stream holds controller lock")
			}
			if failure {
				c.attachment.events <- sandboxapi.AttachEvent{Kind: "exit", Exit: &sandboxapi.AttachExit{Code: 0}}
				var event sandboxapi.AttachEvent
				if err := conn.ReadJSON(&event); err != nil || event.Kind != "failure" || event.Code != "stream_failed" || event.Exit != nil {
					t.Fatalf("cleanup failure became success: %+v %v", event, err)
				}
			} else {
				_ = conn.Close()
			}
			awaitAttachmentClose(t, c.attachment)
		})
	}
}

func TestSandboxAttachmentExitInterruptsPendingInputSend(t *testing.T) {
	_, c, server := attachmentTestServer(t)
	c.attachment.sendGate = make(chan struct{})
	c.attachment.sendEntered = make(chan struct{})
	conn := dialAttachment(t, server)
	select {
	case <-c.entered:
	case <-time.After(3 * time.Second):
		t.Fatal("no admission")
	}
	if err := conn.WriteJSON(sandboxapi.AttachInput{Kind: "stdin", Data: []byte("pending")}); err != nil {
		t.Fatal(err)
	}
	select {
	case <-c.attachment.sendEntered:
	case <-time.After(3 * time.Second):
		t.Fatal("Send did not block")
	}
	c.attachment.events <- sandboxapi.AttachEvent{Kind: "exit", Exit: &sandboxapi.AttachExit{Code: 23}}
	if err := conn.SetReadDeadline(time.Now().Add(3 * time.Second)); err != nil {
		t.Fatal(err)
	}
	var event sandboxapi.AttachEvent
	if err := conn.ReadJSON(&event); err != nil || event.Kind != "exit" || event.Exit == nil || event.Exit.Code != 23 {
		t.Fatalf("pending Send blocked exit: %+v %v", event, err)
	}
	awaitAttachmentClose(t, c.attachment)
}

type attachmentNativeTimeout struct{}

func (attachmentNativeTimeout) Error() string { return "private native input timeout" }
func (attachmentNativeTimeout) Timeout() bool { return true }

func TestSandboxAttachmentNativeInputTimeoutCannotBecomeExitSuccess(t *testing.T) {
	_, c, server := attachmentTestServer(t)
	c.attachment.sendErr = attachmentNativeTimeout{}
	conn := dialAttachment(t, server)
	select {
	case <-c.entered:
	case <-time.After(3 * time.Second):
		t.Fatal("no admission")
	}
	if err := conn.WriteJSON(sandboxapi.AttachInput{Kind: "stdin", Data: []byte("undelivered")}); err != nil {
		t.Fatal(err)
	}
	if err := conn.SetReadDeadline(time.Now().Add(3 * time.Second)); err != nil {
		t.Fatal(err)
	}
	var event sandboxapi.AttachEvent
	err := conn.ReadJSON(&event)
	if err == nil && (event.Kind != "failure" || event.Code != "stream_failed" || event.Exit != nil) {
		t.Fatalf("native timeout treated as successful socket interruption: %+v", event)
	}
	awaitAttachmentClose(t, c.attachment)
}

func TestSandboxAttachmentDeadlineDuringCleanupCannotBecomeSuccess(t *testing.T) {
	_, c, server := attachmentTestServer(t)
	gate := make(chan struct{})
	c.attachment.closeGate = gate
	c.attachment.closeEntered = make(chan struct{})
	conn := dialAttachmentTimeout(t, server, 1)
	select {
	case <-c.entered:
	case <-time.After(3 * time.Second):
		t.Fatal("no admission")
	}
	c.attachment.events <- sandboxapi.AttachEvent{Kind: "exit", Exit: &sandboxapi.AttachExit{Code: 0}}
	select {
	case <-c.attachment.closeEntered:
	case <-time.After(3 * time.Second):
		t.Fatal("cleanup did not start")
	}
	// The route intentionally cancels its context to stop the reader at exit.
	// Its original absolute deadline must still apply during fresh cleanup.
	time.Sleep(1100 * time.Millisecond)
	close(gate)
	var event sandboxapi.AttachEvent
	if err := conn.ReadJSON(&event); err != nil || event.Kind != "failure" || event.Code != "stream_failed" || event.Exit != nil {
		t.Fatalf("deadline during cleanup became success: %+v %v", event, err)
	}
	awaitAttachmentClose(t, c.attachment)
}

// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/gorilla/websocket"

	"github.com/defenseclaw/defenseclaw/internal/openshell/sandboxapi"
	"github.com/defenseclaw/defenseclaw/internal/sandboxruntime"
)

// Bound unauthenticated handshake resource use after the ordinary API auth gate.
// Each admitted stream has one reader and one writer, without per-frame workers
// or unbounded queues. The manager separately limits session/consumer admission.
var sandboxAttachSlots = make(chan struct{}, 32)

func sandboxAttachOrigin(r *http.Request) bool {
	if site := r.Header.Get("Sec-Fetch-Site"); site != "" && site != "same-origin" && site != "none" {
		return false
	}
	if origin := r.Header.Get("Origin"); origin != "" {
		u, err := url.Parse(origin)
		return err == nil && (u.Scheme == "http" || u.Scheme == "https") && u.Host == r.Host && u.User == nil && u.Path == "" && u.RawQuery == "" && u.Fragment == ""
	}
	return true
}

// This route remains behind registerSandboxRoutes' existing master-token / uid
// authentication. WebSocket GET also requires the mutating client's CSRF marker
// and a same-origin check; it never accepts credentials or identity in a URL.
func (a *APIServer) handleSandboxAttach(w http.ResponseWriter, r *http.Request) {
	if r.Header.Get(sandboxapi.ClientHeader) != sandboxapi.ClientName || !sandboxAttachOrigin(r) {
		writeSandboxError(w, &sandboxapi.Error{Code: sandboxapi.CodeInvalid, Message: "sandbox attachment client or origin refused", Status: http.StatusForbidden})
		return
	}
	if r.URL.RawQuery != "" || len(r.PathValue("name")) == 0 || len(r.PathValue("name")) > 128 || strings.ContainsRune(r.PathValue("name"), 0) {
		writeSandboxError(w, sandboxapi.Errorf(sandboxapi.CodeInvalid, "invalid sandbox attachment route"))
		return
	}
	c, release := a.leaseSandboxController()
	_, supported := c.(sandboxruntime.AttachController)
	release()
	if !supported {
		writeSandboxError(w, sandboxapi.Errorf(sandboxapi.CodeUnavailable, "this sandbox runtime has no qualified attachment transport"))
		return
	}
	select {
	case sandboxAttachSlots <- struct{}{}:
		defer func() { <-sandboxAttachSlots }()
	default:
		writeSandboxError(w, sandboxapi.Errorf(sandboxapi.CodeUnavailable, "sandbox attachment capacity reached"))
		return
	}
	upgrader := websocket.Upgrader{HandshakeTimeout: 5 * time.Second, ReadBufferSize: 4096, WriteBufferSize: 4096, CheckOrigin: sandboxAttachOrigin}
	conn, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		return
	}
	defer conn.Close()
	conn.SetReadLimit(sandboxapi.AttachFrameBytes)
	if conn.SetReadDeadline(time.Now().Add(5*time.Second)) != nil {
		return
	}
	kind, raw, err := conn.ReadMessage()
	if err != nil || kind != websocket.TextMessage {
		return
	}
	req, err := sandboxapi.DecodeAttachRequest(raw)
	if err != nil {
		_ = writeSandboxAttach(conn, sandboxapi.AttachEvent{Kind: "failure", Code: "invalid_request"})
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), time.Duration(req.TimeoutSeconds)*time.Second)
	defer cancel()
	deadline, _ := ctx.Deadline()
	if conn.SetReadDeadline(deadline) != nil {
		return
	}
	// Pin only the admission call. A long-running stream must not hold the
	// gateway controller replacement lock; the returned attachment remains
	// owned/canceled by the previous manager until native cleanup completes.
	c, release = a.leaseSandboxController()
	controller, supported := c.(sandboxruntime.AttachController)
	if !supported {
		release()
		_ = writeSandboxAttach(conn, sandboxapi.AttachEvent{Kind: "failure", Code: "unavailable"})
		return
	}
	admission, doneAdmission := context.WithTimeout(ctx, 5*time.Second)
	attachment, err := controller.Attach(admission, r.PathValue("name"), req)
	doneAdmission()
	release()
	var closeOnce sync.Once
	var closeErr error
	closeAttachment := func() error {
		closeOnce.Do(func() {
			cleanup, done := context.WithTimeout(context.WithoutCancel(ctx), 10*time.Second)
			defer done()
			closeErr = attachment.Close(cleanup)
		})
		return closeErr
	}
	if attachment != nil {
		defer closeAttachment() // manager retains custody on failure
	}
	if err != nil || attachment == nil {
		_ = writeSandboxAttach(conn, sandboxapi.AttachEvent{Kind: "failure", Code: "unavailable"})
		return
	}
	a.serveSandboxAttachment(ctx, cancel, conn, attachment, closeAttachment)
}

func writeSandboxAttach(conn *websocket.Conn, event sandboxapi.AttachEvent) error {
	return writeSandboxAttachBefore(conn, event, time.Time{})
}

func writeSandboxAttachBefore(conn *websocket.Conn, event sandboxapi.AttachEvent, admittedDeadline time.Time) error {
	if event.Validate() != nil {
		return sandboxapi.ErrAttachProtocol
	}
	raw, err := json.Marshal(event)
	if err != nil || len(raw) > sandboxapi.AttachFrameBytes {
		return sandboxapi.ErrAttachProtocol
	}
	deadline := time.Now().Add(5 * time.Second)
	if !admittedDeadline.IsZero() && admittedDeadline.Before(deadline) {
		deadline = admittedDeadline
	}
	if !time.Now().Before(deadline) {
		return context.DeadlineExceeded
	}
	if err := conn.SetWriteDeadline(deadline); err != nil {
		return err
	}
	return conn.WriteMessage(websocket.TextMessage, raw)
}

func (a *APIServer) serveSandboxAttachment(ctx context.Context, cancel context.CancelFunc, conn *websocket.Conn, attachment sandboxruntime.Attachment, closeAttachment func() error) {
	admittedDeadline, bounded := ctx.Deadline()
	if !bounded {
		return
	}
	// A manager's concrete Send/Receive honor cancellation on owned transports.
	// Closing the socket independently interrupts the sole network reader.
	stop := context.AfterFunc(ctx, func() { _ = conn.Close() })
	defer stop()
	readerDone := make(chan struct{})
	var inputErr error
	var inputReadError bool
	var inputReadBeforeDeadline bool
	var normalExit sync.Once
	// Gorilla's SetReadDeadline is itself a reader method. Only the underlying
	// net.Conn deadline may be changed concurrently with ReadMessage; net.Conn
	// explicitly permits concurrent method calls. Keep the socket open for Exit.
	stopReading := func() { normalExit.Do(func() { _ = conn.UnderlyingConn().SetReadDeadline(time.Now()) }) }
	go func() {
		defer close(readerDone)
		defer cancel()
		var total int64
		var frames uint64
		eof := false
		for {
			kind, raw, err := conn.ReadMessage()
			if err != nil {
				inputErr = err
				inputReadError = true
				inputReadBeforeDeadline = time.Now().Before(admittedDeadline)
				return
			}
			if kind != websocket.TextMessage {
				inputErr = sandboxapi.ErrAttachProtocol
				return
			}
			frame, err := sandboxapi.DecodeAttachInput(raw)
			frames++
			if frames > 8192 || err != nil || (eof && (frame.Kind == "stdin" || frame.Kind == "stdin_eof")) {
				inputErr = sandboxapi.ErrAttachProtocol
				return
			}
			total += int64(len(frame.Data))
			if total > 64<<20 {
				inputErr = sandboxapi.ErrAttachProtocol
				return
			}
			if frame.Kind == "stdin_eof" {
				eof = true
			}
			if err := attachment.Send(ctx, frame); err != nil {
				inputErr = err
				return
			}
			if frame.Kind == "cancel" {
				return
			}
		}
	}()
	defer func() { cancel(); _ = conn.Close(); <-readerDone }()
	var total int64
	var frames uint64
	for {
		event, err := attachment.Receive(ctx)
		frames++
		if frames > 8192 || err != nil || event.Validate() != nil {
			_ = writeSandboxAttach(conn, sandboxapi.AttachEvent{Kind: "failure", Code: "stream_failed"})
			return
		}
		total += int64(len(event.Data))
		if total > 64<<20 {
			_ = writeSandboxAttach(conn, sandboxapi.AttachEvent{Kind: "failure", Code: "stream_failed"})
			return
		}
		if event.Kind == "exit" {
			if ctx.Err() != nil || !time.Now().Before(admittedDeadline) {
				return
			} // canceled input/request cannot become success
			// Native cleanup must complete before a terminal success result.
			// Stop the reader without canceling this final bounded write.
			stop()
			cancel() // also interrupts a concurrent native Send, not just socket Read
			stopReading()
			<-readerDone
			closeErr := closeAttachment()
			inputFailed := inputErr != nil && !errors.Is(inputErr, context.Canceled)
			expectedReadDeadline := inputReadError && inputReadBeforeDeadline && isSandboxAttachReadDeadline(inputErr)
			if closeErr != nil || !time.Now().Before(admittedDeadline) || (inputFailed && !expectedReadDeadline) {
				_ = writeSandboxAttach(conn, sandboxapi.AttachEvent{Kind: "failure", Code: "stream_failed"})
				return
			}
			_ = writeSandboxAttachBefore(conn, event, admittedDeadline)
			return
		}
		if err := writeSandboxAttachBefore(conn, event, admittedDeadline); err != nil {
			return
		}
		if event.Kind == "failure" {
			return
		}
	}
}

func isSandboxAttachReadDeadline(err error) bool {
	var timeout interface{ Timeout() bool }
	return errors.As(err, &timeout) && timeout.Timeout()
}

// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package backend

import (
	"context"
	"errors"
	"io"
	"slices"
	"sync"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/axis/bridgeowner"
	"github.com/defenseclaw/defenseclaw/internal/axis/bridgeprocess"
	"github.com/defenseclaw/defenseclaw/internal/axis/bridgeproto"
	"github.com/defenseclaw/defenseclaw/internal/openshell/sandboxapi"
	"github.com/defenseclaw/defenseclaw/internal/sandboxruntime"
)

// attachment borrows one immutable concrete session from the backend's retained
// entry. No stream worker, executable discovery or second process is created.
type attachment struct {
	backend                        *Backend
	entry                          *entry
	native                         *bridgeprocess.Session
	binding                        bridgeproto.Binding
	launch                         uint64
	limit                          uint32
	lifetime                       context.Context
	cancel                         context.CancelFunc
	stopExpiry                     func() bool
	sendMu, receiveMu              sync.Mutex
	mu                             sync.Mutex
	closed, eof, cancelled, exited bool
	output                         uint64
	inputBytes, inputFrames        uint64 // guarded by the single sender token
	closeErr                       error
}

var _ sandboxruntime.Attachment = (*attachment)(nil)

// OpenAttachment is a trusted manager operation after its current-policy and
// owner checks. ctx bounds only admission. There is exactly one consumer of an
// already launched, fully identified execution: no argv/environment/launch input.
// The public catalog remains closed until this transport and complete policy
// enforcement are independently qualified. Manager AttachController wraps this
// operation; an API client's name/SessionID alone is never the owned identity.
func (b *Backend) OpenAttachment(ctx context.Context, identity sandboxruntime.SessionIdentity, request sandboxapi.AttachRequest) (sandboxruntime.Attachment, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if !b.info.Available {
		return nil, ErrUnavailable
	}
	if request.Validate() != nil || identity.Validate() != nil || request.SessionID != identity.ID || identity.Runtime != b.info.Identity {
		return nil, sandboxapi.ErrAttachProtocol
	}
	if err := b.info.Require(sandboxruntime.Headless); err != nil {
		return nil, err
	}
	e, err := b.find(identity)
	if err != nil {
		return nil, err
	}
	if err := e.acquire(ctx); err != nil {
		return nil, err
	}
	defer e.release()
	if !b.active() || e.isClosing() || e.phase != "started" || !e.consumed || e.attached || e.native == nil || e.launchRequest == 0 || e.executionDeadline.IsZero() || e.outputLimit == 0 {
		return nil, ErrSession
	}
	deadline := time.Now().Add(time.Duration(request.TimeoutSeconds) * time.Second)
	if e.executionDeadline.Before(deadline) {
		deadline = e.executionDeadline
	}
	if !deadline.After(time.Now()) {
		return nil, context.DeadlineExceeded
	}
	lifetime, cancel := context.WithDeadline(b.owner, deadline)
	a := &attachment{backend: b, entry: e, native: e.native, binding: e.binding, launch: e.launchRequest, limit: e.outputLimit, lifetime: lifetime, cancel: cancel}
	// A timeout terminates the existing session using its existing protocol/native
	// owner. The callback does no blocking I/O or wait; custody stays in b.entries
	// until explicit Close observes worker and native completion.
	a.stopExpiry = context.AfterFunc(lifetime, e.interruptLifetime)
	e.attached = true // a lifetime tombstone; errors/Close never permit a new consumer
	_, err = b.calls.send(ctx, e.native, bridgeowner.Command{Kind: bridgeproto.Wait})
	if err == nil {
		err = ctx.Err()
	}
	if err == nil && (!b.active() || e.isClosing() || lifetime.Err() != nil) {
		err = errors.Join(ErrSession, lifetime.Err())
	}
	if err != nil {
		a.stopExpiry()
		cancel()
		cleanup, done := cleanupContext(ctx)
		defer done()
		return nil, errors.Join(err, b.closeEntry(cleanup, e))
	}
	return a, nil
}

func (e *entry) interruptLifetime() {
	e.cancelMu.Lock()
	e.closing = true
	cancel := e.cancel
	e.cancelMu.Unlock()
	if cancel != nil {
		cancel()
	}
}

func (a *attachment) operationContext(ctx context.Context) (context.Context, func()) {
	deadline, _ := a.lifetime.Deadline()
	op, cancel := context.WithDeadline(ctx, deadline)
	stop := context.AfterFunc(a.lifetime, cancel)
	return op, func() { stop(); cancel() }
}

func (a *attachment) Send(ctx context.Context, input sandboxapi.AttachInput) error {
	if input.Validate() != nil || input.Kind == "resize" {
		return sandboxapi.ErrAttachProtocol
	}
	if !a.sendMu.TryLock() {
		return sandboxapi.ErrAttachProtocol
	}
	defer a.sendMu.Unlock()
	if a.inputFrames >= 8192 || a.inputBytes > 64<<20 || uint64(len(input.Data)) > (64<<20)-a.inputBytes {
		return sandboxapi.ErrAttachProtocol
	}
	a.mu.Lock()
	if a.closed || a.exited || a.cancelled || !a.backend.active() || a.entry.isClosing() || a.lifetime.Err() != nil {
		a.mu.Unlock()
		return ErrSession
	}
	command := bridgeowner.Command{}
	switch input.Kind {
	case "stdin":
		if a.eof {
			a.mu.Unlock()
			return sandboxapi.ErrAttachProtocol
		}
		command.Kind = bridgeproto.Input
		command.Data = &bridgeproto.Data{Stream: "stdin", Bytes: slices.Clone(input.Data)}
	case "stdin_eof":
		if a.eof {
			a.mu.Unlock()
			return sandboxapi.ErrAttachProtocol
		}
		a.eof = true
		command.Kind = bridgeproto.InputEOF
	case "cancel":
		a.cancelled = true
		command.Kind = bridgeproto.Cancel
	}
	a.mu.Unlock()
	op, done := a.operationContext(ctx)
	defer done()
	if err := op.Err(); err != nil {
		return errors.Join(err, a.Close(ctx))
	}
	_, err := a.backend.calls.send(op, a.native, command)
	if err != nil {
		return errors.Join(err, a.Close(ctx))
	}
	if err := op.Err(); err != nil {
		return errors.Join(err, a.Close(ctx))
	}
	a.mu.Lock()
	closed := a.closed
	a.mu.Unlock()
	if closed || !a.backend.active() || a.entry.isClosing() || a.lifetime.Err() != nil {
		return errors.Join(ErrSession, a.Close(ctx))
	}
	a.inputFrames++
	a.inputBytes += uint64(len(input.Data))
	return nil
}

func (a *attachment) Receive(ctx context.Context) (sandboxapi.AttachEvent, error) {
	if !a.receiveMu.TryLock() {
		return sandboxapi.AttachEvent{}, sandboxapi.ErrAttachProtocol
	}
	defer a.receiveMu.Unlock()
	a.mu.Lock()
	closed, exited := a.closed, a.exited
	a.mu.Unlock()
	if closed || !a.backend.active() || a.entry.isClosing() {
		return sandboxapi.AttachEvent{}, ErrSession
	}
	if exited {
		return sandboxapi.AttachEvent{}, io.EOF
	}
	op, done := a.operationContext(ctx)
	defer done()
	frame, err := a.backend.calls.receive(op, a.native)
	if err != nil {
		return sandboxapi.AttachEvent{}, errors.Join(err, a.Close(ctx))
	}
	if err := op.Err(); err != nil {
		return sandboxapi.AttachEvent{}, errors.Join(err, a.Close(ctx))
	}
	if frame.Validate() != nil || frame.Binding != a.binding || frame.Request != a.launch {
		return sandboxapi.AttachEvent{}, errors.Join(sandboxapi.ErrAttachProtocol, a.Close(ctx))
	}
	a.mu.Lock()
	if a.closed || !a.backend.active() || a.entry.isClosing() || a.lifetime.Err() != nil {
		a.mu.Unlock()
		return sandboxapi.AttachEvent{}, errors.Join(ErrSession, a.Close(ctx))
	}
	event := sandboxapi.AttachEvent{}
	switch frame.Kind {
	case bridgeproto.Output:
		a.output += uint64(len(frame.Data.Bytes))
		if a.output > uint64(a.limit) {
			a.mu.Unlock()
			return sandboxapi.AttachEvent{}, errors.Join(sandboxapi.ErrAttachProtocol, a.Close(ctx))
		}
		event.Kind = frame.Data.Stream
		event.Data = slices.Clone(frame.Data.Bytes)
	case bridgeproto.Exited:
		a.exited = true
		event.Kind = "exit"
		event.Exit = &sandboxapi.AttachExit{Code: frame.Result.ExitCode, TimedOut: frame.Result.TimedOut, Truncated: frame.Result.Truncated}
	default:
		a.mu.Unlock()
		return sandboxapi.AttachEvent{}, errors.Join(sandboxapi.ErrAttachProtocol, a.Close(ctx))
	}
	a.mu.Unlock()
	if event.Validate() != nil {
		return sandboxapi.AttachEvent{}, errors.Join(sandboxapi.ErrAttachProtocol, a.Close(ctx))
	}
	// Exit is the correlated peer observation, not native cleanup proof. Close
	// still joins owner workers and independently waits the exact native custody.
	return event, nil
}

func (a *attachment) Close(ctx context.Context) error {
	a.mu.Lock()
	a.closed = true
	a.mu.Unlock()
	a.stopExpiry()
	// Stop/Close must be able to interrupt a blocked Receive without taking its
	// consumer lock. Existing Owner.Close closes owned pipes before native wait.
	a.entry.requestClose()
	cleanup, done := cleanupContext(ctx)
	defer done()
	err := a.entry.acquire(cleanup)
	if err == nil {
		err = a.backend.closeEntry(cleanup, a.entry)
		a.entry.release()
	}
	a.cancel()
	a.mu.Lock()
	a.closeErr = errors.Join(a.closeErr, err)
	result := a.closeErr
	a.mu.Unlock()
	return result
}

// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package backend

import (
	"context"
	"errors"
	"io"
	"slices"
	"sync"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/axis/bridgeowner"
	"github.com/defenseclaw/defenseclaw/internal/axis/bridgeprocess"
	"github.com/defenseclaw/defenseclaw/internal/axis/bridgeproto"
	"github.com/defenseclaw/defenseclaw/internal/openshell/sandboxapi"
	"github.com/defenseclaw/defenseclaw/internal/sandboxruntime"
)

// Every helper below uses the existing private fake nativeCalls. None executes
// a peer or image, creates a namespace, or invokes the real process factory.
func launchedFake(t *testing.T) (*Backend, *fakePeer, sandboxruntime.Spec, *Assets) {
	t.Helper()
	b, f, policy, spec, assets := fakeHost(t)
	process, _, err := b.Prepare(context.Background(), policy, spec)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := process.Launch(context.Background(), spec); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = b.Close(context.Background()) })
	return b, f, spec, assets
}

func attachFake(t *testing.T, b *Backend, identity sandboxruntime.SessionIdentity) *attachment {
	t.Helper()
	value, err := b.OpenAttachment(context.Background(), identity, sandboxapi.AttachRequest{Version: sandboxapi.AttachVersion, SessionID: identity.ID, TimeoutSeconds: 30})
	if err != nil {
		t.Fatal(err)
	}
	return value.(*attachment)
}

func eventFrame(a *attachment, kind bridgeproto.Kind, data *bridgeproto.Data, result *bridgeproto.Result) bridgeproto.Frame {
	return bridgeproto.Frame{Version: bridgeproto.Version, Sequence: 3, Request: a.launch, Binding: a.binding, Kind: kind, Data: data, Result: result}
}

func TestAttachmentDefaultCatalogRefusesBeforeNativeCalls(t *testing.T) {
	_, spec := resolved(t, "")
	b, _ := host(t, spec.Identity.Runtime)
	b.calls.send = func(context.Context, *bridgeprocess.Session, bridgeowner.Command) (uint64, error) {
		t.Fatal("unqualified attachment reached native protocol")
		return 0, nil
	}
	a, err := b.OpenAttachment(context.Background(), spec.Identity, sandboxapi.AttachRequest{Version: 1, SessionID: spec.Identity.ID, TimeoutSeconds: 1})
	if a != nil || !errors.Is(err, ErrUnavailable) {
		t.Fatal("default catalog admitted attachment", err)
	}
}

func TestAttachmentRequiresStartedFullIdentityAndOneConsumer(t *testing.T) {
	b, f, policy, spec, _ := fakeHost(t)
	process, _, err := b.Prepare(context.Background(), policy, spec)
	if err != nil {
		t.Fatal(err)
	}
	request := sandboxapi.AttachRequest{Version: 1, SessionID: spec.Identity.ID, TimeoutSeconds: 1}
	if value, err := b.OpenAttachment(context.Background(), spec.Identity, request); value != nil || !errors.Is(err, ErrSession) {
		t.Fatal("unlaunched prepared handle admitted", err)
	}
	if _, err := process.Launch(context.Background(), spec); err != nil {
		t.Fatal(err)
	}
	for _, field := range []string{"owner", "name", "session"} {
		identity, candidate := spec.Identity, request
		switch field {
		case "owner":
			identity.Owner = "other-owner"
		case "name":
			identity.Name = "other-name"
		case "session":
			candidate.SessionID = "other-session"
		}
		before := f.request
		if value, err := b.OpenAttachment(context.Background(), identity, candidate); value != nil || err == nil || f.request != before {
			t.Fatal("partial identity reached native stream", field, err)
		}
	}
	a := attachFake(t, b, spec.Identity)
	if value, err := b.OpenAttachment(context.Background(), spec.Identity, request); value != nil || !errors.Is(err, ErrSession) {
		t.Fatal("second consumer admitted", err)
	}
	if err := a.Close(context.Background()); err != nil {
		t.Fatal(err)
	}
	if value, err := b.OpenAttachment(context.Background(), spec.Identity, request); value != nil || !errors.Is(err, ErrSession) {
		t.Fatal("closed consumer reservation reused", err)
	}
	if f.starts != 1 || f.launches != 1 {
		t.Fatal("attachment launched another process")
	}
}

func TestAttachmentAdmissionContextDetachesAndCannotExtendExecution(t *testing.T) {
	b, f, spec, _ := launchedFake(t)
	ctx, cancel := context.WithCancel(context.Background())
	value, err := b.OpenAttachment(ctx, spec.Identity, sandboxapi.AttachRequest{Version: 1, SessionID: spec.Identity.ID, TimeoutSeconds: 30})
	if err != nil {
		t.Fatal(err)
	}
	a := value.(*attachment)
	cancel()
	if a.lifetime.Err() != nil || f.lifetime.Err() != nil {
		t.Fatal("completed HTTP admission retained lifetime authority")
	}
	deadline, ok := a.lifetime.Deadline()
	if !ok || deadline.After(a.entry.executionDeadline) || time.Until(deadline) > 5*time.Second {
		t.Fatal("attachment extended the native execution deadline")
	}
	if err := a.Send(context.Background(), sandboxapi.AttachInput{Kind: "stdin", Data: []byte{0, 255}}); err != nil {
		t.Fatal(err)
	}
	if err := a.Close(context.Background()); err != nil {
		t.Fatal(err)
	}
}

func TestAttachmentBinaryEOFAndCorrelatedExit(t *testing.T) {
	b, _, spec, assets := launchedFake(t)
	a := attachFake(t, b, spec.Identity)
	var sent []bridgeowner.Command
	b.calls.send = func(_ context.Context, _ *bridgeprocess.Session, c bridgeowner.Command) (uint64, error) {
		sent = append(sent, c)
		return uint64(len(sent) + 10), nil
	}
	input := []byte{0, 255, 10}
	if err := a.Send(context.Background(), sandboxapi.AttachInput{Kind: "stdin", Data: input}); err != nil {
		t.Fatal(err)
	}
	input[0] = 42
	if !slices.Equal(sent[0].Data.Bytes, []byte{0, 255, 10}) {
		t.Fatal("caller retained mutable native command bytes")
	}
	if err := a.Send(context.Background(), sandboxapi.AttachInput{Kind: "stdin_eof"}); err != nil {
		t.Fatal(err)
	}
	for _, input := range []sandboxapi.AttachInput{{Kind: "stdin", Data: []byte{1}}, {Kind: "stdin_eof"}, {Kind: "resize", Rows: 30, Columns: 100}} {
		if err := a.Send(context.Background(), input); !errors.Is(err, sandboxapi.ErrAttachProtocol) {
			t.Fatal("invalid/unqualified input admitted", err)
		}
	}
	if len(sent) != 2 || sent[0].Kind != bridgeproto.Input || sent[1].Kind != bridgeproto.InputEOF {
		t.Fatal("literal input/EOF mapping changed")
	}
	data := []byte{255, 0, 128}
	frames := []bridgeproto.Frame{eventFrame(a, bridgeproto.Output, &bridgeproto.Data{Stream: "stderr", Bytes: data}, nil), eventFrame(a, bridgeproto.Exited, nil, &bridgeproto.Result{ExitCode: 7, TimedOut: true})}
	b.calls.receive = func(context.Context, *bridgeprocess.Session) (bridgeproto.Frame, error) {
		if len(frames) == 0 {
			t.Fatal("terminal observation read native stream again")
		}
		v := frames[0]
		frames = frames[1:]
		return v, nil
	}
	event, err := a.Receive(context.Background())
	if err != nil || event.Kind != "stderr" || !slices.Equal(event.Data, data) {
		t.Fatal("binary output changed", err)
	}
	data[0] = 1
	if event.Data[0] != 255 {
		t.Fatal("event retained mutable peer data")
	}
	event, err = a.Receive(context.Background())
	if err != nil || event.Kind != "exit" || event.Exit.Code != 7 || !event.Exit.TimedOut || event.Exit.Truncated || assets.closed {
		t.Fatal("exit observation became cleanup proof", err)
	}
	if _, err := a.Receive(context.Background()); !errors.Is(err, io.EOF) {
		t.Fatal("terminal event repeated", err)
	}
	if err := a.Send(context.Background(), sandboxapi.AttachInput{Kind: "cancel"}); !errors.Is(err, ErrSession) {
		t.Fatal("input admitted after exit", err)
	}
	if err := a.Close(context.Background()); err != nil || !assets.closed {
		t.Fatal("native close failed", err)
	}
}

func TestAttachmentRejectsMisboundUnexpectedOrExcessOutputAndCloses(t *testing.T) {
	for _, kind := range []string{"binding", "request", "unexpected", "excess", "cancelled-context", "manager-closed"} {
		t.Run(kind, func(t *testing.T) {
			b, _, spec, assets := launchedFake(t)
			a := attachFake(t, b, spec.Identity)
			frame := eventFrame(a, bridgeproto.Output, &bridgeproto.Data{Stream: "stdout", Bytes: []byte{1}}, nil)
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			switch kind {
			case "binding":
				frame.Binding.SessionID = "other-session"
			case "request":
				frame.Request++
			case "unexpected":
				frame.Kind, frame.Data = bridgeproto.Destroyed, nil
			case "excess":
				a.output = uint64(a.limit)
			}
			b.calls.receive = func(context.Context, *bridgeprocess.Session) (bridgeproto.Frame, error) {
				if kind == "cancelled-context" {
					cancel() // an injected late reply must not bypass cancellation
				}
				if kind == "manager-closed" {
					b.mu.Lock()
					b.closed = true // manager shutdown may precede this entry's Stop
					b.mu.Unlock()
				}
				return frame, nil
			}
			if event, err := a.Receive(ctx); err == nil || event.Kind != "" || !assets.closed {
				t.Fatal("invalid stream event escaped or lost cleanup", event, err)
			}
		})
	}
}

func TestAttachmentBlockedReceiveDoesNotPreventStopOrPublishLateOutput(t *testing.T) {
	b, _, spec, assets := launchedFake(t)
	a := attachFake(t, b, spec.Identity)
	receiving, release := make(chan struct{}), make(chan struct{})
	var once sync.Once
	t.Cleanup(func() { once.Do(func() { close(release) }) })
	b.calls.receive = func(context.Context, *bridgeprocess.Session) (bridgeproto.Frame, error) {
		close(receiving)
		<-release
		return eventFrame(a, bridgeproto.Output, &bridgeproto.Data{Stream: "stdout", Bytes: []byte("late")}, nil), nil
	}
	b.calls.close = func(context.Context, *bridgeprocess.Session) cleanupObservation {
		once.Do(func() { close(release) })
		return cleanupObservation{complete: true}
	}
	result := make(chan error, 1)
	go func() {
		event, err := a.Receive(context.Background())
		if event.Kind != "" || err == nil {
			result <- errors.New("closing session published late output")
			return
		}
		result <- nil
	}()
	select {
	case <-receiving:
	case <-time.After(time.Second):
		t.Fatal("receive never reached fake barrier")
	}
	if _, err := a.Receive(context.Background()); !errors.Is(err, sandboxapi.ErrAttachProtocol) {
		t.Fatal("two concurrent native stream consumers admitted", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if _, err := b.Stop(ctx, spec.Identity); err != nil || !assets.closed {
		t.Fatal("blocked Receive retained the lifecycle operation token", err)
	}
	select {
	case err := <-result:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("native close failed to interrupt Receive")
	}
}

func TestAttachmentCloseRetainsNativeUncertaintyAndStickyFailure(t *testing.T) {
	b, f, spec, assets := launchedFake(t)
	a := attachFake(t, b, spec.Identity)
	failure := errors.New("synthetic pending native wait")
	f.closeErr = failure
	if err := a.Close(context.Background()); !errors.Is(err, failure) || assets.closed {
		t.Fatal("failed cleanup released assets or hid failure", err)
	}
	f.closeErr = nil
	if err := a.Close(context.Background()); !errors.Is(err, failure) || !assets.closed || f.closes != 2 {
		t.Fatal("retry lost custody or laundered original failure", err)
	}
}

func TestAttachmentAggregateInputBoundsApplyBeforeNativeSend(t *testing.T) {
	for _, kind := range []string{"bytes", "frames", "failed-send"} {
		t.Run(kind, func(t *testing.T) {
			b, _, spec, _ := launchedFake(t)
			a := attachFake(t, b, spec.Identity)
			calls := 0
			failure := errors.New("synthetic failed input send")
			b.calls.send = func(context.Context, *bridgeprocess.Session, bridgeowner.Command) (uint64, error) {
				calls++
				if kind == "failed-send" {
					return 0, failure
				}
				return 10, nil
			}
			switch kind {
			case "bytes":
				a.inputBytes = (64 << 20) - 2
				if err := a.Send(context.Background(), sandboxapi.AttachInput{Kind: "stdin", Data: []byte{0, 255}}); err != nil {
					t.Fatal("last allowed binary input refused", err)
				}
				if err := a.Send(context.Background(), sandboxapi.AttachInput{Kind: "stdin", Data: []byte{1}}); !errors.Is(err, sandboxapi.ErrAttachProtocol) || a.inputBytes != 64<<20 || a.inputFrames != 1 {
					t.Fatal("aggregate byte limit or accounting differed", err)
				}
			case "frames":
				a.inputFrames = 8191
				if err := a.Send(context.Background(), sandboxapi.AttachInput{Kind: "stdin_eof"}); err != nil {
					t.Fatal("last allowed frame refused", err)
				}
				if err := a.Send(context.Background(), sandboxapi.AttachInput{Kind: "cancel"}); !errors.Is(err, sandboxapi.ErrAttachProtocol) || a.inputFrames != 8192 || a.inputBytes != 0 {
					t.Fatal("aggregate frame limit or accounting differed", err)
				}
			case "failed-send":
				if err := a.Send(context.Background(), sandboxapi.AttachInput{Kind: "stdin", Data: []byte{0, 255}}); !errors.Is(err, failure) || a.inputFrames != 0 || a.inputBytes != 0 {
					t.Fatal("failed send advanced aggregate accounting", err)
				}
			}
			if calls != 1 {
				t.Fatal("overflow reached native send", calls)
			}
		})
	}
}

func TestAttachmentCancellationIsBoundedControlAndCannotBeReplayed(t *testing.T) {
	b, _, spec, _ := launchedFake(t)
	a := attachFake(t, b, spec.Identity)
	var sent []bridgeproto.Kind
	b.calls.send = func(_ context.Context, _ *bridgeprocess.Session, c bridgeowner.Command) (uint64, error) {
		sent = append(sent, c.Kind)
		return uint64(len(sent) + 10), nil
	}
	if err := a.Send(context.Background(), sandboxapi.AttachInput{Kind: "stdin_eof"}); err != nil {
		t.Fatal(err)
	}
	if err := a.Send(context.Background(), sandboxapi.AttachInput{Kind: "cancel"}); err != nil {
		t.Fatal(err)
	}
	for _, input := range []sandboxapi.AttachInput{{Kind: "cancel"}, {Kind: "stdin", Data: []byte{1}}} {
		if err := a.Send(context.Background(), input); !errors.Is(err, ErrSession) {
			t.Fatal("control replay/input after cancel admitted", err)
		}
	}
	if !slices.Equal(sent, []bridgeproto.Kind{bridgeproto.InputEOF, bridgeproto.Cancel}) {
		t.Fatal("cancel was translated into a new launch or different command")
	}
}

func TestAttachmentFailedAdmissionCleansBeforeReturningNoHandle(t *testing.T) {
	b, _, spec, assets := launchedFake(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	original := b.calls.send
	b.calls.send = func(ctx context.Context, native *bridgeprocess.Session, c bridgeowner.Command) (uint64, error) {
		request, err := original(ctx, native, c)
		if c.Kind == bridgeproto.Wait {
			cancel()
		}
		return request, err
	}
	value, err := b.OpenAttachment(ctx, spec.Identity, sandboxapi.AttachRequest{Version: 1, SessionID: spec.Identity.ID, TimeoutSeconds: 1})
	if value != nil || !errors.Is(err, context.Canceled) || !assets.closed {
		t.Fatal("late admission cancellation published a stream or lost cleanup", err)
	}
}

func TestAttachmentRequestShortensDeadlineAndExpiryCancelsOwnedSession(t *testing.T) {
	b, f, spec, assets := launchedFake(t)
	before := time.Now()
	value, err := b.OpenAttachment(context.Background(), spec.Identity, sandboxapi.AttachRequest{Version: 1, SessionID: spec.Identity.ID, TimeoutSeconds: 1})
	if err != nil {
		t.Fatal(err)
	}
	a := value.(*attachment)
	deadline, _ := a.lifetime.Deadline()
	if deadline.After(before.Add(time.Second+100*time.Millisecond)) || !deadline.Before(a.entry.executionDeadline) {
		t.Fatal("request did not shorten existing execution lifetime")
	}
	select {
	case <-f.lifetime.Done():
	case <-time.After(2 * time.Second):
		t.Fatal("attachment timeout did not cancel exact owned native lifetime")
	}
	if !a.entry.isClosing() || assets.closed {
		t.Fatal("timeout inferred native cleanup without independent wait")
	}
	if err := a.Close(context.Background()); err != nil || !assets.closed {
		t.Fatal("explicit bounded cleanup after expiry failed", err)
	}
}

func TestConcurrentStopPreventsLateStartedReplyFromReportingSuccess(t *testing.T) {
	b, _, policy, spec, assets := fakeHost(t)
	process, _, err := b.Prepare(context.Background(), policy, spec)
	if err != nil {
		t.Fatal(err)
	}
	receiving, release := make(chan struct{}), make(chan struct{})
	var once sync.Once
	t.Cleanup(func() { once.Do(func() { close(release) }) })
	original := b.calls.receive
	b.calls.receive = func(ctx context.Context, native *bridgeprocess.Session) (bridgeproto.Frame, error) {
		close(receiving)
		<-release
		return original(ctx, native)
	}
	launched := make(chan error, 1)
	go func() {
		value, err := process.Launch(context.Background(), spec)
		if value.Identity.ID != "" || err == nil {
			launched <- errors.New("closing launch reported a started session")
			return
		}
		launched <- nil
	}()
	select {
	case <-receiving:
	case <-time.After(time.Second):
		t.Fatal("launch never reached reply barrier")
	}
	// Reproduce Stop's first, independent step while Launch holds its operation
	// token; the following Stop waits/cleans through the same retained entry.
	e, err := b.find(spec.Identity)
	if err != nil {
		t.Fatal(err)
	}
	e.requestClose()
	once.Do(func() { close(release) })
	if _, err := b.Stop(context.Background(), spec.Identity); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-launched:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("closing launch remained blocked")
	}
	if !assets.closed {
		t.Fatal("closing launch lost owned cleanup")
	}
}

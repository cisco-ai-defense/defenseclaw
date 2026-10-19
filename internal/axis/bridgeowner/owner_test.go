// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package bridgeowner

import (
	"context"
	"errors"
	"io"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/axis/bridgeproto"
)

type testCustody struct {
	calls atomic.Int32
	fail  bool
}

func (c *testCustody) StopAndWait(context.Context) error {
	c.calls.Add(1)
	if c.fail {
		return errors.New("private backend diagnostic must not escape")
	}
	return nil
}

type fixture struct {
	owner       *Owner
	input       *os.File
	output      *os.File
	diagnostics *os.File
	custody     *testCustody
	plan        bridgeproto.Preparation
	binding     bridgeproto.Binding
}

func newFixture(t *testing.T, writeTimeout time.Duration) fixture {
	t.Helper()
	input, err := NewPrivatePipe(ToPeer)
	if err != nil {
		t.Fatal(err)
	}
	output, err := NewPrivatePipe(FromPeer)
	if err != nil {
		t.Fatal(err)
	}
	diag, err := NewPrivatePipe(FromPeer)
	if err != nil {
		t.Fatal(err)
	}
	inputR, inputW, outputR, outputW, diagR, diagW := input.Child, input.Parent, output.Parent, output.Child, diag.Parent, diag.Child
	for _, f := range []*os.File{inputR, inputW, outputR, outputW, diagR, diagW} {
		t.Cleanup(func() { _ = f.Close() })
	}
	plan := bridgeproto.Preparation{Backend: "bubblewrap", Argv: []string{"/bin/fixed", "literal;value"}, Environment: []bridgeproto.Variable{},
		Workdir: "/work", Filesystem: bridgeproto.Filesystem{Read: []string{"/bin"}, Write: []string{"/work"}, Deny: []string{}}, Offline: true, TimeoutMS: 1000, OutputLimit: 1 << 20}
	hash, err := bridgeproto.PreparationDigest(plan)
	if err != nil {
		t.Fatal(err)
	}
	digest := "sha256:" + strings.Repeat("a", 64)
	binding := bridgeproto.Binding{SessionID: "fixed-session", SessionDigest: digest, PolicyDigest: digest, RuntimeDigest: digest, HarnessDigest: digest, PreparationHash: hash}
	custody := &testCustody{}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	t.Cleanup(cancel)
	owner, err := New(ctx, binding, Pipes{inputW, outputR, diagR, custody}, Limits{writeTimeout, time.Second})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		_ = owner.Close(ctx)
	})
	return fixture{owner, inputR, outputW, diagW, custody, plan, binding}
}

func (f fixture) bridgeFrame(seq, request uint64, kind bridgeproto.Kind) bridgeproto.Frame {
	return bridgeproto.Frame{Version: bridgeproto.Version, Sequence: seq, Request: request, Binding: f.binding, Kind: kind}
}

func receiveKind(t *testing.T, owner *Owner, kind bridgeproto.Kind) bridgeproto.Frame {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	frame, err := owner.Receive(ctx)
	if err != nil || frame.Kind != kind {
		t.Fatalf("receive %s: kind=%s err=%v", kind, frame.Kind, err)
	}
	return frame
}

func TestOwnedPipesCompleteLifecycleRequiresCleanup(t *testing.T) {
	f := newFixture(t, time.Second)
	peerDone := make(chan error, 1)
	go func() {
		decoder := bridgeproto.NewDecoder(f.input)
		encoder := bridgeproto.NewEncoder(f.output)
		for i, kind := range []bridgeproto.Kind{bridgeproto.Prepare, bridgeproto.Launch, bridgeproto.Wait, bridgeproto.Destroy} {
			frame, err := decoder.Decode()
			if err != nil {
				peerDone <- err
				return
			}
			if frame.Kind != kind || frame.Sequence != uint64(i+1) || frame.Request != uint64(i+1) {
				peerDone <- bridgeproto.ErrProtocol
				return
			}
			var reply bridgeproto.Frame
			switch kind {
			case bridgeproto.Prepare:
				reply = f.bridgeFrame(1, 1, bridgeproto.Prepared)
			case bridgeproto.Launch:
				reply = f.bridgeFrame(2, 2, bridgeproto.Started)
			case bridgeproto.Wait:
				reply = f.bridgeFrame(3, 2, bridgeproto.Exited)
				reply.Result = &bridgeproto.Result{ExitCode: 23}
			case bridgeproto.Destroy:
				reply = f.bridgeFrame(4, 4, bridgeproto.Destroyed)
			}
			if err := encoder.Encode(reply); err != nil {
				peerDone <- err
				return
			}
		}
		peerDone <- nil
	}()
	for i, command := range []Command{{Kind: bridgeproto.Prepare, Plan: &f.plan}, {Kind: bridgeproto.Launch}, {Kind: bridgeproto.Wait}, {Kind: bridgeproto.Destroy}} {
		if request, err := f.owner.Send(context.Background(), command); err != nil || request != uint64(i+1) {
			t.Fatalf("send %d: request=%d err=%v", i, request, err)
		}
		kind := []bridgeproto.Kind{bridgeproto.Prepared, bridgeproto.Started, bridgeproto.Exited, bridgeproto.Destroyed}[i]
		frame := receiveKind(t, f.owner, kind)
		if kind == bridgeproto.Exited && frame.Result.ExitCode != 23 {
			t.Fatal("lost typed exit")
		}
	}
	if err := <-peerDone; err != nil {
		t.Fatal(err)
	}
	if err := f.owner.Close(context.Background()); err != nil {
		t.Fatal(err)
	}
	if f.custody.calls.Load() != 1 {
		t.Fatal("normal protocol completion did not invoke exactly one native cleanup")
	}
}

func prepareRunning(t *testing.T, f fixture) {
	t.Helper()
	decoder := bridgeproto.NewDecoder(f.input)
	encoder := bridgeproto.NewEncoder(f.output)
	for i, command := range []Command{{Kind: bridgeproto.Prepare, Plan: &f.plan}, {Kind: bridgeproto.Launch}} {
		errC := make(chan error, 1)
		go func() { _, err := f.owner.Send(context.Background(), command); errC <- err }()
		if _, err := decoder.Decode(); err != nil {
			t.Fatal(err)
		}
		if err := <-errC; err != nil {
			t.Fatal(err)
		}
		kind := []bridgeproto.Kind{bridgeproto.Prepared, bridgeproto.Started}[i]
		if err := encoder.Encode(f.bridgeFrame(uint64(i+1), uint64(i+1), kind)); err != nil {
			t.Fatal(err)
		}
		receiveKind(t, f.owner, kind)
	}
}

func TestBlockedCommandWriteHasDeadlineAndOneCleanup(t *testing.T) {
	f := newFixture(t, 50*time.Millisecond)
	f.plan.Argv = []string{"/bin/fixed", strings.Repeat("x", 96<<10)}
	hash, err := bridgeproto.PreparationDigest(f.plan)
	if err != nil {
		t.Fatal(err)
	}
	// Rebind before any reader activity; a fresh owner is necessary because
	// bindings are immutable. This fixture has sent no bytes yet.
	f.owner.binding.PreparationHash = hash
	f.owner.conversation, err = bridgeproto.NewConversation(f.owner.binding)
	if err != nil {
		t.Fatal(err)
	}
	started := time.Now()
	if _, err := f.owner.Send(context.Background(), Command{Kind: bridgeproto.Prepare, Plan: &f.plan}); err == nil {
		t.Fatal("unread pipe accepted oversized buffered write")
	}
	if time.Since(started) > time.Second {
		t.Fatal("command write did not honor deadline")
	}
	if err := f.owner.Close(context.Background()); err == nil {
		t.Fatal("lost write failure")
	}
	if f.custody.calls.Load() != 1 {
		t.Fatal("missing or duplicate cleanup")
	}
}

func TestMalformedPeerFrameStopsAndWaits(t *testing.T) {
	f := newFixture(t, time.Second)
	go func() { _, _ = f.output.Write([]byte{0, 0, 0, 1, '{'}) }()
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if _, err := f.owner.Receive(ctx); !errors.Is(err, bridgeproto.ErrProtocol) {
		t.Fatalf("malformed frame: %v", err)
	}
	if f.custody.calls.Load() != 1 {
		t.Fatal("peer protocol failure missed custody")
	}
}

func TestBackpressureStopsRatherThanBlocksPeer(t *testing.T) {
	f := newFixture(t, time.Second)
	prepareRunning(t, f)
	encoder := bridgeproto.NewEncoder(f.output)
	peerDone := make(chan struct{})
	go func() {
		defer close(peerDone)
		for i := uint64(3); i < 50; i++ {
			frame := f.bridgeFrame(i, 2, bridgeproto.Output)
			frame.Data = &bridgeproto.Data{Stream: "stdout", Bytes: []byte("x")}
			if encoder.Encode(frame) != nil {
				return
			}
		}
	}()
	select {
	case <-f.owner.done:
	case <-time.After(time.Second):
		t.Fatal("full event queue stalled peer cleanup")
	}
	if err := f.owner.Close(context.Background()); !errors.Is(err, ErrBackpressure) {
		t.Fatalf("backpressure: %v", err)
	}
	select {
	case <-peerDone:
	case <-time.After(time.Second):
		t.Fatal("peer writer remained blocked")
	}
	if f.custody.calls.Load() != 1 {
		t.Fatal("backpressure missed custody")
	}
}

func TestConcurrentControlsSerializeOnWire(t *testing.T) {
	f := newFixture(t, time.Second)
	prepareRunning(t, f)
	const count = 24
	peerDone := make(chan error, 1)
	go func() {
		decoder := bridgeproto.NewDecoder(f.input)
		for i := uint64(3); i < count+3; i++ {
			frame, err := decoder.Decode()
			if err != nil {
				peerDone <- err
				return
			}
			if frame.Kind != bridgeproto.Input || frame.Sequence != i || frame.Request != i {
				peerDone <- bridgeproto.ErrProtocol
				return
			}
		}
		peerDone <- nil
	}()
	var wg sync.WaitGroup
	for range count {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, err := f.owner.Send(context.Background(), Command{Kind: bridgeproto.Input, Data: &bridgeproto.Data{Stream: "stdin", Bytes: []byte("x")}})
			if err != nil {
				t.Error(err)
			}
		}()
	}
	wg.Wait()
	if err := <-peerDone; err != nil {
		t.Fatal(err)
	}
}

func TestCleanupFailureNeverBecomesProtocolSuccess(t *testing.T) {
	f := newFixture(t, time.Second)
	f.custody.fail = true
	if err := f.owner.Close(context.Background()); !errors.Is(err, ErrCleanup) || strings.Contains(err.Error(), "diagnostic") {
		t.Fatalf("cleanup error leaked or was lost: %v", err)
	}
	if f.custody.calls.Load() != 1 {
		t.Fatal("cleanup did not run")
	}
}

func TestPeerEOFAndDiagnosticOverflowStopCustody(t *testing.T) {
	for _, name := range []string{"eof", "diagnostic-overflow"} {
		t.Run(name, func(t *testing.T) {
			f := newFixture(t, time.Second)
			if name == "eof" {
				_ = f.output.Close()
			} else {
				go func() { _, _ = f.diagnostics.Write(make([]byte, (64<<10)+1)) }()
			}
			ctx, cancel := context.WithTimeout(context.Background(), time.Second)
			defer cancel()
			_, err := f.owner.Receive(ctx)
			if name == "eof" && !errors.Is(err, io.EOF) || name != "eof" && !errors.Is(err, ErrBackpressure) {
				t.Fatalf("lost peer loss: %v", err)
			}
			if f.custody.calls.Load() != 1 {
				t.Fatal("missing cleanup")
			}
		})
	}
}

func TestCancellationClosesRealPipeReaders(t *testing.T) {
	f := newFixture(t, time.Second)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := f.owner.Receive(ctx); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancel: %v", err)
	}
	if err := f.owner.Close(context.Background()); !errors.Is(err, context.Canceled) {
		t.Fatalf("close lost cancel: %v", err)
	}
	if f.custody.calls.Load() != 1 {
		t.Fatal("cancel missed custody")
	}
}

func TestCanceledReceiveDoesNotDeliverQueuedEvent(t *testing.T) {
	f := newFixture(t, time.Second)
	// Queue an already-admitted event, then deterministically cancel before
	// Receive. Buffered output must not bypass the caller's revocation.
	f.owner.events <- f.bridgeFrame(1, 1, bridgeproto.Prepared)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := f.owner.Receive(ctx); !errors.Is(err, context.Canceled) {
		t.Fatalf("queued event bypassed cancellation: %v", err)
	}
	if err := f.owner.Close(context.Background()); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
	if f.custody.calls.Load() != 1 {
		t.Fatal("queued cancellation missed native cleanup")
	}
}

func TestCanceledConstructorDoesNotAcceptResources(t *testing.T) {
	f := newFixture(t, time.Second)
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	cancel()
	// It is deliberately invalid to transfer these live resources again;
	// canceled-context refusal happens before any resource is touched.
	owner, err := New(ctx, f.binding, f.owner.pipes, Limits{time.Second, time.Second})
	if owner != nil || !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled constructor: %v", err)
	}
	if f.custody.calls.Load() != 0 || f.owner.isStopping() {
		t.Fatal("canceled constructor took caller ownership")
	}
}

func TestZeroOwnerRefusesWithoutActivity(t *testing.T) {
	for _, owner := range []*Owner{nil, {}} {
		if _, err := owner.Send(context.Background(), Command{Kind: bridgeproto.Launch}); !errors.Is(err, ErrClosed) {
			t.Fatal(err)
		}
		if _, err := owner.Receive(context.Background()); !errors.Is(err, ErrClosed) {
			t.Fatal(err)
		}
		if err := owner.Close(context.Background()); !errors.Is(err, ErrClosed) {
			t.Fatal(err)
		}
	}
}

func TestCanceledParentDoesNotDeliverQueuedEvent(t *testing.T) {
	f := newFixture(t, time.Second)
	// Deliberately suppress the asynchronous callback to model its scheduling
	// lag. Receive must observe the parent directly before delivering a frame.
	if !f.owner.stopParent() {
		t.Fatal("parent callback already ran")
	}
	parent, cancel := context.WithCancel(f.owner.parent)
	f.owner.parent = parent
	f.owner.events <- f.bridgeFrame(1, 1, bridgeproto.Prepared)
	cancel()
	if _, err := f.owner.Receive(context.Background()); !errors.Is(err, context.Canceled) {
		t.Fatalf("queued event bypassed parent cancel: %v", err)
	}
	if err := f.owner.Close(context.Background()); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
	if f.custody.calls.Load() != 1 {
		t.Fatal("parent cancellation missed cleanup")
	}
}

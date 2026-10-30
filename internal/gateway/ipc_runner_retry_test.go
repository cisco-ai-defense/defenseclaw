// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"context"
	"errors"
	"sync/atomic"
	"testing"
	"time"
)

type flakyIPCRunner struct {
	failures int32
	calls    atomic.Int32
	serving  chan struct{}
}

func (r *flakyIPCRunner) Run(ctx context.Context) error {
	if r.calls.Add(1) <= r.failures {
		return errors.New("ipc: SetNamedSecurityInfo: Access is denied.")
	}
	close(r.serving)
	<-ctx.Done()
	return nil
}

func TestRunIPCWithRetryKeepsRetryingABindFailure(t *testing.T) {
	previousInitial, previousMax := ipcRetryInitialDelay, ipcRetryMaxDelay
	ipcRetryInitialDelay, ipcRetryMaxDelay = time.Millisecond, 4*time.Millisecond
	t.Cleanup(func() { ipcRetryInitialDelay, ipcRetryMaxDelay = previousInitial, previousMax })

	runner := &flakyIPCRunner{failures: 3, serving: make(chan struct{})}
	sidecar := &Sidecar{}
	sidecar.SetIPCRunner(runner)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		sidecar.runIPCWithRetry(ctx)
		close(done)
	}()
	select {
	case <-runner.serving:
	case <-time.After(5 * time.Second):
		t.Fatalf("IPC server was not retried into service; calls=%d", runner.calls.Load())
	}
	cancel()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("runIPCWithRetry did not return after cancellation")
	}
	if got := runner.calls.Load(); got != 4 {
		t.Fatalf("Run calls = %d, want 4", got)
	}
}

// servedThenFailingIPCRunner binds and serves, then fails, on every attempt.
type servedThenFailingIPCRunner struct {
	attempts int32
	calls    atomic.Int32
	done     chan struct{}
}

func (r *servedThenFailingIPCRunner) Run(ctx context.Context) error {
	MarkIPCServing(ctx)
	if r.calls.Add(1) == r.attempts {
		close(r.done)
		<-ctx.Done()
		return nil
	}
	return errors.New("ipc: serve: connection reset")
}

func TestRunIPCWithRetryResetsBackoffOnceTheServerServed(t *testing.T) {
	previousInitial, previousMax := ipcRetryInitialDelay, ipcRetryMaxDelay
	// Without a reset, 15 consecutive failures would sleep 1ms+2ms+...+16s.
	ipcRetryInitialDelay, ipcRetryMaxDelay = time.Millisecond, time.Minute
	t.Cleanup(func() { ipcRetryInitialDelay, ipcRetryMaxDelay = previousInitial, previousMax })

	runner := &servedThenFailingIPCRunner{attempts: 16, done: make(chan struct{})}
	sidecar := &Sidecar{}
	sidecar.SetIPCRunner(runner)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	finished := make(chan struct{})
	go func() {
		sidecar.runIPCWithRetry(ctx)
		close(finished)
	}()
	select {
	case <-runner.done:
	case <-time.After(5 * time.Second):
		t.Fatalf("retry delay was not reset after the server served; calls=%d", runner.calls.Load())
	}
	cancel()
	select {
	case <-finished:
	case <-time.After(5 * time.Second):
		t.Fatal("runIPCWithRetry did not return after cancellation")
	}
}

func TestMarkIPCServingIsANoOpOutsideTheRetryLoop(t *testing.T) {
	MarkIPCServing(context.Background())
}

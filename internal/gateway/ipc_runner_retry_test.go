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

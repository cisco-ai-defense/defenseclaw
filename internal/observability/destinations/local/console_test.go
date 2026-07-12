// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// SPDX-License-Identifier: Apache-2.0

package local

import (
	"bytes"
	"context"
	"errors"
	"io"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/observability/delivery"
)

func TestConsoleWritesOneInjectionSafeProjectedJSONLine(t *testing.T) {
	var output bytes.Buffer
	adapter, err := NewConsole(&output)
	if err != nil {
		t.Fatal(err)
	}
	dispatcher := newTestDispatcher(t, "console-safe", adapter, 8*1024*1024, 4)

	projected := " {\n \"message\":\"first\\nsecond\\u001b[31m\", \"csi\":\"\u009b31m\", \"bidi\":\"\u202eabc\" } \r\n"
	enqueue(t, dispatcher, "console-record", projected)
	drainAndCloseDispatcher(t, dispatcher)
	closeContext, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if err := adapter.Close(closeContext); err != nil {
		t.Fatal(err)
	}

	got := output.String()
	if strings.Count(got, "\n") != 1 || !strings.HasSuffix(got, "\n") {
		t.Fatalf("console output must be exactly one line: %q", got)
	}
	for _, forbidden := range []string{"\r", "\x1b", "\u009b", "\u202e"} {
		if strings.Contains(got, forbidden) {
			t.Fatalf("console output contains raw terminal control %q: %q", forbidden, got)
		}
	}
	for _, escaped := range []string{`\n`, `\u001b`, `\u009b`, `\u202e`} {
		if !strings.Contains(got, escaped) {
			t.Fatalf("console output missing safe escape %q: %q", escaped, got)
		}
	}
	if strings.Contains(got, `first\nsecond`) == false {
		t.Fatalf("projected message was not derived into console output: %q", got)
	}
}

func TestConsoleFIFOAndCloseDoesNotOwnWriter(t *testing.T) {
	writer := &closeTrackingWriter{}
	adapter, err := NewConsole(writer)
	if err != nil {
		t.Fatal(err)
	}
	dispatcher := newTestDispatcher(t, "console-fifo", adapter, 8*1024*1024, 4)
	for index, body := range []string{`{"index":1}`, `{"index":2}`, `{"index":3}`} {
		enqueue(t, dispatcher, "fifo-"+string(rune('a'+index)), body)
	}
	drainAndCloseDispatcher(t, dispatcher)
	if got, want := writer.String(), "{\"index\":1}\n{\"index\":2}\n{\"index\":3}\n"; got != want {
		t.Fatalf("FIFO output = %q, want %q", got, want)
	}
	if err := adapter.Close(context.Background()); err != nil {
		t.Fatal(err)
	}
	if writer.closed.Load() {
		t.Fatal("console adapter closed its supplied writer")
	}
}

func TestConsoleRejectsMalformedProjectionBeforeWriting(t *testing.T) {
	var output bytes.Buffer
	adapter, err := NewConsole(&output)
	if err != nil {
		t.Fatal(err)
	}
	dispatcher := newTestDispatcher(t, "console-invalid", adapter, 8*1024*1024, 4)
	enqueue(t, dispatcher, "invalid-json", "{not-json")
	drainAndCloseDispatcher(t, dispatcher)
	if got := dispatcher.Counters(); got.Rejected != 1 || got.Retried != 0 || got.Delivered != 0 {
		t.Fatalf("malformed counters = %+v", got)
	}
	if output.Len() != 0 {
		t.Fatalf("malformed projection wrote %q", output.String())
	}
}

func TestConsoleFailureOutcomesAreBoundedAndRetryable(t *testing.T) {
	writer := &failingWriter{}
	adapter, err := NewConsole(writer)
	if err != nil {
		t.Fatal(err)
	}
	dispatcher := newTestDispatcher(t, "console-failure", adapter, 8*1024*1024, 1)
	enqueue(t, dispatcher, "write-failure", `{"message":"content must not enter errors"}`)
	drainAndCloseDispatcher(t, dispatcher)
	if got := dispatcher.Counters(); got.Retried != 2 || got.Rejected != 1 || got.Delivered != 0 {
		t.Fatalf("failure counters = %+v", got)
	}
	if writer.calls.Load() != 3 {
		t.Fatalf("write attempts = %d, want 3", writer.calls.Load())
	}
}

func TestConsoleCloseIsContextBoundedByInflightWrite(t *testing.T) {
	writer := &blockingWriter{started: make(chan struct{}), release: make(chan struct{})}
	adapter, err := NewConsole(writer)
	if err != nil {
		t.Fatal(err)
	}
	dispatcher := newTestDispatcher(t, "console-blocked", adapter, 8*1024*1024, 1)
	enqueue(t, dispatcher, "blocked-write", `{"message":"blocked"}`)
	select {
	case <-writer.started:
	case <-time.After(time.Second):
		t.Fatal("console write did not start")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Millisecond)
	defer cancel()
	if err := adapter.Close(ctx); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("Close error = %v, want deadline", err)
	}
	close(writer.release)
	drainAndCloseDispatcher(t, dispatcher)
	if err := adapter.Close(context.Background()); err != nil {
		t.Fatal(err)
	}
}

func TestConsoleEncodedSizeIsConservativeAndOverflowSafe(t *testing.T) {
	adapter, err := NewConsole(io.Discard)
	if err != nil {
		t.Fatal(err)
	}
	if size, ok := adapter.EncodedSize([]int{1, 2}); !ok || size != 20 {
		t.Fatalf("EncodedSize = (%d,%t), want (20,true)", size, ok)
	}
	if _, ok := adapter.EncodedSize([]int{-1}); ok {
		t.Fatal("negative projected size accepted")
	}
	if _, ok := adapter.EncodedSize([]int{maxInt}); ok {
		t.Fatal("overflowing projected size accepted")
	}
}

type closeTrackingWriter struct {
	bytes.Buffer
	closed atomic.Bool
}

func (writer *closeTrackingWriter) Close() error {
	writer.closed.Store(true)
	return nil
}

type failingWriter struct{ calls atomic.Int64 }

func (writer *failingWriter) Write([]byte) (int, error) {
	writer.calls.Add(1)
	return 0, errors.New("untrusted writer detail")
}

type blockingWriter struct {
	started chan struct{}
	release chan struct{}
	once    atomic.Bool
}

func (writer *blockingWriter) Write(payload []byte) (int, error) {
	if writer.once.CompareAndSwap(false, true) {
		close(writer.started)
	}
	<-writer.release
	return len(payload), nil
}

func newTestDispatcher(t *testing.T, name string, adapter delivery.Adapter, maxBytes, maxBatchItems int) *delivery.Dispatcher {
	t.Helper()
	dispatcher, err := delivery.NewDispatcher(delivery.Config{
		Destination: name, Enabled: true,
		MaxQueueItems: 16, MaxQueueBytes: maxBytes,
		MaxBatchItems: maxBatchItems, MaxBatchBytes: maxBytes,
		ScheduledDelay: 5 * time.Millisecond, AttemptTimeout: time.Second,
		Retry: delivery.RetryPolicy{
			MaxAttempts: 3, InitialBackoff: time.Millisecond, MaxBackoff: time.Millisecond,
			Jitter: func(delay time.Duration, _ int) time.Duration { return delay },
		},
	}, adapter)
	if err != nil {
		t.Fatal(err)
	}
	dispatcher.Activate()
	return dispatcher
}

func enqueue(t *testing.T, dispatcher *delivery.Dispatcher, id, body string) {
	t.Helper()
	payload, err := delivery.NewPayload([]byte(body), delivery.RoutingIdentity{
		RecordID: id, Bucket: "model.io", Signal: "logs", EventName: "model.response",
	})
	if err != nil {
		t.Fatal(err)
	}
	if result := dispatcher.Enqueue(payload); !result.Accepted() {
		t.Fatalf("enqueue = %+v", result)
	}
}

func drainAndCloseDispatcher(t *testing.T, dispatcher *delivery.Dispatcher) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := dispatcher.Drain(ctx); err != nil {
		t.Fatalf("Drain: %v", err)
	}
	if err := dispatcher.Close(ctx); err != nil {
		t.Fatalf("Close: %v", err)
	}
}

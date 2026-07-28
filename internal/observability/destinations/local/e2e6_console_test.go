// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package local

import (
	"bytes"
	"context"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/observability/delivery"
)

type e2e6AdapterFixture struct {
	adapter delivery.Adapter
	started <-chan struct{}
	release func()
	output  func() ([]byte, error)
	close   func(context.Context) error
}

type e2e6BlockingWriter struct {
	started chan struct{}
	release <-chan struct{}
	once    sync.Once
	mu      sync.Mutex
	buffer  bytes.Buffer
}

func (writer *e2e6BlockingWriter) Write(value []byte) (int, error) {
	writer.once.Do(func() { close(writer.started) })
	<-writer.release
	writer.mu.Lock()
	defer writer.mu.Unlock()
	return writer.buffer.Write(value)
}

func (writer *e2e6BlockingWriter) bytes() []byte {
	writer.mu.Lock()
	defer writer.mu.Unlock()
	return append([]byte(nil), writer.buffer.Bytes()...)
}

type e2e6SynchronizedWriter struct {
	mu     sync.Mutex
	buffer bytes.Buffer
}

func (writer *e2e6SynchronizedWriter) Write(value []byte) (int, error) {
	writer.mu.Lock()
	defer writer.mu.Unlock()
	return writer.buffer.Write(value)
}

func (writer *e2e6SynchronizedWriter) bytes() []byte {
	writer.mu.Lock()
	defer writer.mu.Unlock()
	return append([]byte(nil), writer.buffer.Bytes()...)
}

func TestE2E6ActualBlockedConsoleCountAndBytePressure(t *testing.T) {
	runE2E6ActualLocalAdapterPressure(t, func(t *testing.T) e2e6AdapterFixture {
		t.Helper()
		release := make(chan struct{})
		writer := &e2e6BlockingWriter{started: make(chan struct{}), release: release}
		adapter, err := NewConsole(writer)
		if err != nil {
			t.Fatal(err)
		}
		var once sync.Once
		return e2e6AdapterFixture{
			adapter: adapter, started: writer.started,
			release: func() { once.Do(func() { close(release) }) },
			output:  func() ([]byte, error) { return writer.bytes(), nil },
			close:   adapter.Close,
		}
	})
}

func runE2E6ActualLocalAdapterPressure(
	t *testing.T,
	newBlocked func(*testing.T) e2e6AdapterFixture,
) {
	t.Helper()
	for _, test := range []struct {
		name       string
		maxItems   int
		maxBytes   int
		wantReason delivery.EnqueueReason
	}{
		{name: "count", maxItems: 2, maxBytes: 1024, wantReason: delivery.ReasonCountLimit},
		{name: "projected_bytes", maxItems: 4, maxBytes: 18, wantReason: delivery.ReasonByteLimit},
	} {
		t.Run(test.name, func(t *testing.T) {
			blocked := newBlocked(t)
			blockedDispatcher := newE2E6LocalDispatcher(
				t, "blocked-local", blocked.adapter, test.maxItems, test.maxBytes,
			)
			siblingWriter := &e2e6SynchronizedWriter{}
			siblingAdapter, err := NewConsole(siblingWriter)
			if err != nil {
				t.Fatal(err)
			}
			siblingDispatcher := newE2E6LocalDispatcher(
				t, "healthy-sibling", siblingAdapter, 8, 1024,
			)
			t.Cleanup(func() {
				blocked.release()
				ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
				defer cancel()
				_ = blockedDispatcher.Close(ctx)
				_ = siblingDispatcher.Close(ctx)
				_ = blocked.close(ctx)
				_ = siblingAdapter.Close(ctx)
			})

			bodies := []string{`{"seq":1}`, `{"seq":2}`, `{"seq":3}`}
			if result := blockedDispatcher.Enqueue(e2e6LocalPayload(t, "blocked-1", bodies[0])); !result.Accepted() {
				t.Fatalf("blocked first=%+v", result)
			}
			if result := siblingDispatcher.Enqueue(e2e6LocalPayload(t, "sibling-1", bodies[0])); !result.Accepted() {
				t.Fatalf("sibling first=%+v", result)
			}
			if blocked.started != nil {
				select {
				case <-blocked.started:
				case <-time.After(5 * time.Second):
					t.Fatal("actual blocked adapter did not start")
				}
			}
			waitE2E6Local(t, func() bool {
				_, _, inFlight, _ := blockedDispatcher.QueueUsage()
				return inFlight == 1
			})
			if result := blockedDispatcher.Enqueue(e2e6LocalPayload(t, "blocked-2", bodies[1])); !result.Accepted() {
				t.Fatalf("blocked second=%+v", result)
			}
			if result := siblingDispatcher.Enqueue(e2e6LocalPayload(t, "sibling-2", bodies[1])); !result.Accepted() {
				t.Fatalf("sibling second=%+v", result)
			}
			dropped := blockedDispatcher.Enqueue(e2e6LocalPayload(t, "blocked-3", bodies[2]))
			if dropped.Disposition != delivery.EnqueueDropped || dropped.Reason != test.wantReason {
				t.Fatalf("blocked newest=%+v want=%s", dropped, test.wantReason)
			}
			if result := siblingDispatcher.Enqueue(e2e6LocalPayload(t, "sibling-3", bodies[2])); !result.Accepted() {
				t.Fatalf("sibling third=%+v", result)
			}
			waitE2E6Local(t, func() bool { return siblingDispatcher.Counters().Delivered == 3 })
			degraded := blockedDispatcher.DeliveryHealthSnapshot()
			if degraded.State != delivery.HealthDegraded ||
				degraded.Reason != string(delivery.HealthReasonQueueFull) ||
				degraded.Counters.Accepted != 2 || degraded.Counters.Dropped != 1 ||
				degraded.Queue == nil || degraded.Queue.Items != 2 {
				t.Fatalf("blocked degraded health=%+v", degraded)
			}
			if got := e2e6OutputLines(t, siblingWriter.bytes(), nil); !reflect.DeepEqual(got, bodies) {
				t.Fatalf("sibling FIFO=%q want=%q", got, bodies)
			}

			blocked.release()
			waitE2E6Local(t, func() bool {
				snapshot := blockedDispatcher.DeliveryHealthSnapshot()
				return snapshot.State == delivery.HealthHealthy &&
					snapshot.Reason == string(delivery.HealthReasonRecovered) &&
					snapshot.Counters.Delivered == 2
			})
			recovered := blockedDispatcher.DeliveryHealthSnapshot()
			if recovered.LastFailure.IsZero() || recovered.LastSuccess.IsZero() ||
				recovered.LastSuccess.Before(recovered.LastFailure) {
				t.Fatalf("blocked recovered health=%+v", recovered)
			}
			output, err := blocked.output()
			if err != nil {
				t.Fatal(err)
			}
			if got, want := e2e6OutputLines(t, output, nil), bodies[:2]; !reflect.DeepEqual(got, want) {
				t.Fatalf("blocked retained FIFO=%q want=%q", got, want)
			}
			if strings.Contains(string(output), bodies[2]) {
				t.Fatal("drop-newest payload reached blocked adapter")
			}
		})
	}
}

func newE2E6LocalDispatcher(
	t *testing.T,
	name string,
	adapter delivery.Adapter,
	maxItems, maxBytes int,
) *delivery.Dispatcher {
	t.Helper()
	dispatcher, err := delivery.NewDispatcher(delivery.Config{
		Destination: name, Generation: 1, Signal: "logs", Enabled: true,
		MaxQueueItems: maxItems, MaxQueueBytes: maxBytes,
		MaxBatchItems: 1, MaxBatchBytes: 1024,
		AttemptTimeout: time.Second,
		Retry: delivery.RetryPolicy{
			MaxAttempts: 1,
		},
	}, adapter)
	if err != nil {
		t.Fatal(err)
	}
	dispatcher.Activate()
	return dispatcher
}

func e2e6LocalPayload(t *testing.T, id, body string) delivery.Payload {
	t.Helper()
	payload, err := delivery.NewPayload([]byte(body), delivery.RoutingIdentity{
		RecordID: id, Bucket: "model.io", Signal: "logs", EventName: "model.response",
	})
	if err != nil {
		t.Fatal(err)
	}
	return payload
}

func e2e6OutputLines(t *testing.T, output []byte, err error) []string {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
	trimmed := strings.TrimSpace(string(output))
	if trimmed == "" {
		return nil
	}
	return strings.Split(trimmed, "\n")
}

func waitE2E6Local(t *testing.T, condition func() bool) {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for !condition() {
		if time.Now().After(deadline) {
			t.Fatal("E2E-6 condition did not become true")
		}
		time.Sleep(time.Millisecond)
	}
}

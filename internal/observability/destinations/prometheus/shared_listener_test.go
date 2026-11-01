// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
// SPDX-License-Identifier: Apache-2.0

package prometheus

import (
	"context"
	"net"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"

	"go.opentelemetry.io/otel/metric"
	sdkmetric "go.opentelemetry.io/otel/sdk/metric"
)

// GAP-2072: a reload that keeps a Prometheus destination on its listen
// address prepares the successor generation while the active one still
// serves. The successor must bind (join the process socket), serve the next
// scrape, keep serving after the old generation drains, and the port must be
// free once both are gone.
func TestSuccessorGenerationServesTheSameListenAddressWhileTheOldOneDrains(t *testing.T) {
	address := freeAddress(t)
	source := prometheusSource("metrics")
	source.Listen = address
	plan, _ := compilePrometheus(t, source, true)

	firstReaders, err := PreparePlanReaders(context.Background(), plan, 1, deltaSpec(), Options{})
	if err != nil || len(firstReaders) != 1 {
		t.Fatalf("first readers=%d err=%v", len(firstReaders), err)
	}
	first := firstReaders[0].(*Reader)
	firstProvider := sdkmetric.NewMeterProvider(sdkmetric.WithReader(first))
	firstCounter, _ := firstProvider.Meter("generation-one").Int64Counter("defenseclaw.scan.count", metric.WithUnit("{scan}"))
	firstCounter.Add(context.Background(), 1)

	secondReaders, err := PreparePlanReaders(context.Background(), plan, 2, deltaSpec(), Options{})
	if err != nil || len(secondReaders) != 1 {
		t.Fatalf("successor on the same address: readers=%d err=%v", len(secondReaders), err)
	}
	second := secondReaders[0].(*Reader)
	secondProvider := sdkmetric.NewMeterProvider(sdkmetric.WithReader(second))
	t.Cleanup(func() { _ = secondProvider.Shutdown(context.Background()) })
	secondCounter, _ := secondProvider.Meter("generation-two").Int64Counter("defenseclaw.scan.count", metric.WithUnit("{scan}"))
	secondCounter.Add(context.Background(), 5)
	if second.Addr().String() != address {
		t.Fatalf("successor address=%s want %s", second.Addr(), address)
	}
	if value := scrapeMetricValue(t, second, "defenseclaw_scan_count_total"); value != 5 {
		t.Fatalf("scrape during overlap served generation value %v, want the successor's 5", value)
	}

	if err := firstProvider.Shutdown(context.Background()); err != nil {
		t.Fatal(err)
	}
	if value := scrapeMetricValue(t, second, "defenseclaw_scan_count_total"); value != 5 {
		t.Fatalf("scrape after the old generation drained=%v, want 5", value)
	}

	if err := secondProvider.Shutdown(context.Background()); err != nil {
		t.Fatal(err)
	}
	if _, err := testHTTPClient().Get("http://" + address + "/metrics"); err == nil {
		t.Fatal("the shared socket still accepted scrapes after every generation closed")
	}
	listener, err := net.Listen("tcp", address)
	if err != nil {
		t.Fatalf("the shared socket was not released: %v", err)
	}
	_ = listener.Close()
}

// Two destinations of one generation still cannot share a listen address.
func TestOneGenerationCannotUseOneListenAddressTwice(t *testing.T) {
	address := freeAddress(t)
	source := prometheusSource("metrics")
	source.Listen = address
	first := newTestFactory(t, source, nil, nil)
	second := newTestFactory(t, source, nil, nil)
	value, err := first.Prepare(7, deltaSpec())
	if err != nil {
		t.Fatal(err)
	}
	reader := value.(*Reader)
	t.Cleanup(func() { _ = reader.Shutdown(context.Background()) })
	if _, err := second.Prepare(7, deltaSpec()); !IsError(err, ErrorListenFailed) || strings.Contains(err.Error(), address) {
		t.Fatalf("same-generation duplicate error=%v", err)
	}
	if status, _ := scrape(t, reader); status != http.StatusOK {
		t.Fatalf("refused duplicate disturbed the bound reader: status=%d", status)
	}
}

// temporaryAcceptError is the shape of EMFILE/ENFILE from Accept under file
// descriptor pressure: Temporary, not a Timeout.
type temporaryAcceptError struct{}

func (temporaryAcceptError) Error() string   { return "accept: too many open files" }
func (temporaryAcceptError) Timeout() bool   { return false }
func (temporaryAcceptError) Temporary() bool { return true }

// flakyBaseListener returns failures temporary Accept errors, then serves
// the real socket.
type flakyBaseListener struct {
	net.Listener
	mu       sync.Mutex
	failures int
}

func (listener *flakyBaseListener) Accept() (net.Conn, error) {
	listener.mu.Lock()
	if listener.failures > 0 {
		listener.failures--
		listener.mu.Unlock()
		return nil, &net.OpError{Op: "accept", Net: "tcp", Err: temporaryAcceptError{}}
	}
	listener.mu.Unlock()
	return listener.Listener.Accept()
}

// A burst of file descriptor exhaustion must not kill the shared socket for
// this and every later generation: the hub retries a temporary Accept error
// the way http.Server does and hands the next connection to the generation.
func TestSharedListenerSurvivesATemporaryAcceptError(t *testing.T) {
	set := &listenerSet{hubs: make(map[string]*listenerHub)}
	address := freeAddress(t)
	listen := func(ctx context.Context, network, address string) (net.Listener, error) {
		base, err := (&net.ListenConfig{}).Listen(ctx, network, address)
		if err != nil {
			return nil, err
		}
		return &flakyBaseListener{Listener: base, failures: 3}, nil
	}
	view, err := set.acquire(context.Background(), listen, address, 1)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = view.Close() })

	accepted := make(chan error, 1)
	go func() {
		conn, acceptErr := view.Accept()
		if conn != nil {
			_ = conn.Close()
		}
		accepted <- acceptErr
	}()
	client, err := net.DialTimeout("tcp", address, 2*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	select {
	case err := <-accepted:
		if err != nil {
			t.Fatalf("a temporary Accept error killed the shared socket: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("the connection was never handed to the generation after a temporary Accept error")
	}

	successor, err := set.acquire(context.Background(), listen, address, 2)
	if err != nil {
		t.Fatalf("successor could not join the recovered socket: %v", err)
	}
	t.Cleanup(func() { _ = successor.Close() })
	select {
	case <-successor.(*sharedListener).hub.failed:
		t.Fatal("successor joined a failed hub")
	default:
	}
}

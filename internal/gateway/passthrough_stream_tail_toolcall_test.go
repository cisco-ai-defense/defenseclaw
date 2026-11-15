// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"
)

// streamReaderGoroutines counts the running upstream reader goroutines of
// passthrough streams (the goroutines passthroughStream.run starts).
func streamReaderGoroutines() int {
	buf := make([]byte, 1<<20)
	for {
		n := runtime.Stack(buf, true)
		if n < len(buf) {
			buf = buf[:n]
			break
		}
		buf = make([]byte, 2*len(buf))
	}
	count := 0
	for _, g := range strings.Split(string(buf), "\n\n") {
		if strings.Contains(g, "created by github.com/defenseclaw/defenseclaw/internal/gateway.(*passthroughStream).run") {
			count++
		}
	}
	return count
}

// waitStreamReaders fails the test when more than want reader goroutines
// are still running after the handler returned.
func waitStreamReaders(t *testing.T, want int) {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for {
		n := streamReaderGoroutines()
		if n <= want {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("%d passthrough stream reader goroutines still run after the handler returned, want %d", n, want)
		}
		time.Sleep(20 * time.Millisecond)
	}
}

// streamTailFront serves the proxy's passthrough route and closes served
// when the handler has returned.
func streamTailFront(t *testing.T, proxy *GuardrailProxy) (*httptest.Server, <-chan struct{}) {
	t.Helper()
	served := make(chan struct{})
	var once sync.Once
	front := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer once.Do(func() { close(served) })
		proxy.handlePassthrough(w, r)
	}))
	t.Cleanup(front.Close)
	return front, served
}

// streamTailClientRead reads resp.Body on its own goroutine; the returned
// func is what was read so far.
func streamTailClientRead(resp *http.Response) func() string {
	var mu sync.Mutex
	var sb strings.Builder
	go func() {
		buf := make([]byte, 4096)
		for {
			n, err := resp.Body.Read(buf)
			mu.Lock()
			sb.Write(buf[:n])
			mu.Unlock()
			if err != nil {
				return
			}
		}
	}()
	return func() string {
		mu.Lock()
		defer mu.Unlock()
		return sb.String()
	}
}

// The tail hold and the tool-call hold together (rel-1-0-10:GAP-0212 on
// substrate-1 GAP-0189): the hold's time bounds apply only to the events the
// tool-call hold lets out. An upstream that stalls inside an open tool call,
// in the middle of an event, sends the text before the call on time
// (streamHoldMaxAge), but no byte of the call: not after streamHoldMaxAge,
// and not after streamHoldMaxPartialAge either (no TRUNCATED release of the
// unfinished event). The held call waits for its verdict, and the stream
// still ends when the request context does.
func TestStreamTailHeldToolCallWaitsForItsVerdict(t *testing.T) {
	f := streamTailFormatNamed(t, "anthropic")
	const callID = "toolu_p16held"
	toolStart := "event: content_block_start\ndata: " + streamTailJSON(map[string]any{"type": "content_block_start", "index": 1,
		"content_block": map[string]any{"type": "tool_use", "id": callID, "name": "run_command", "input": map[string]any{}}}) + "\n\n"
	toolDelta := func(s string) string {
		return "event: content_block_delta\ndata: " + streamTailJSON(map[string]any{"type": "content_block_delta", "index": 1,
			"delta": map[string]any{"type": "input_json_delta", "partial_json": s}}) + "\n\n"
	}
	textStop := "event: content_block_stop\ndata: {\"type\":\"content_block_stop\",\"index\":0}\n\n"
	unfinished := toolDelta(`"ls -la"}`)
	body := f.head + f.delta(streamTailProse(1440)) + textStop + toolStart + toolDelta(`{"command":`) + unfinished[:len(unfinished)/2]
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", f.ctype)
		w.WriteHeader(http.StatusOK)
		_, _ = io.WriteString(w, body)
		w.(http.Flusher).Flush()
		<-r.Context().Done()
	}))
	defer up.Close()
	insp := &streamTailInspector{mockInspector: newMockInspector(), final: true, mid: true}
	proxy := streamTailProxy(t, f.provider, insp, "action")
	readers := streamReaderGoroutines()
	front, served := streamTailFront(t, proxy)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	log := captureStderr(t, func() {
		resp, err := http.DefaultClient.Do(streamTailRequest(t, f, front.URL, up.URL).WithContext(ctx))
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		received := streamTailClientRead(resp)
		// The text block and its stop event are not held behind the call:
		// they arrive within the hold's time bound.
		until := time.Now().Add(streamHoldMaxAge + 2*time.Second)
		for !strings.Contains(received(), textStop) {
			if time.Now().After(until) {
				t.Fatalf("the events before the tool call were not sent within the hold's bound: %d bytes", len(received()))
			}
			time.Sleep(10 * time.Millisecond)
		}
		// Past both time bounds of the tail hold, no byte of the call.
		time.Sleep(streamHoldMaxPartialAge + time.Second)
		if got := received(); strings.Contains(got, callID) || strings.Contains(got, "input_json_delta") || strings.Contains(got, `"ls -la"`) {
			t.Fatalf("tool-call bytes reached the client before the call's verdict: %q", got[strings.Index(got, textStop):])
		}
		cancel()
		select {
		case <-served:
		case <-time.After(3 * time.Second):
			t.Fatal("the stream did not end with the request context")
		}
	})
	if strings.Contains(log, "PASSTHROUGH-STREAM-TRUNCATED") || strings.Contains(log, "PASSTHROUGH-STREAM-BLOCK") {
		t.Fatalf("the held call took a tail bound: %s", log)
	}
	waitStreamReaders(t, readers)
}

// The upstream reader goroutine of a passthrough stream ends with the
// handler however the stream ends: the upstream ends (also inside an
// event), a block cuts the stream while the upstream stays open, or the
// client goes away from an idle upstream.
func TestPassthroughStreamReaderEndsWithTheHandler(t *testing.T) {
	for _, f := range streamTailFormats {
		t.Run(f.name+"/upstream-ends", func(t *testing.T) {
			readers := streamReaderGoroutines()
			up, whole := streamTailUpstream(t, f, streamTailDeltas(2400, 24), 0, nil)
			insp := &streamTailInspector{mockInspector: newMockInspector(), final: true, mid: true}
			out, _ := streamTailServe(t, streamTailProxy(t, f.provider, insp, "action"), f, up.URL)
			if out != whole {
				t.Fatalf("stream changed: got %d bytes, want %d", len(out), len(whole))
			}
			waitStreamReaders(t, readers)
		})
		t.Run(f.name+"/upstream-ends-inside-an-event", func(t *testing.T) {
			readers := streamReaderGoroutines()
			d := f.delta("cut short here")
			up := streamTailRawUpstream(t, f, f.head+f.delta(streamTailProse(1440))+d[:len(d)/2], 4096)
			insp := &streamTailInspector{mockInspector: newMockInspector(), final: true, mid: true}
			_, _ = streamTailServe(t, streamTailProxy(t, f.provider, insp, "action"), f, up.URL)
			waitStreamReaders(t, readers)
		})
		t.Run(f.name+"/block-with-the-upstream-open", func(t *testing.T) {
			readers := streamReaderGoroutines()
			stall := make(chan struct{})
			defer close(stall)
			up, _ := streamTailUpstream(t, f, streamTailDeltas(1500, 24, "and "+streamTailMarker), 0, stall)
			insp := &streamTailInspector{mockInspector: newMockInspector(), final: true, mid: true}
			done := make(chan string, 1)
			go func() {
				out, _ := streamTailServe(t, streamTailProxy(t, f.provider, insp, "action"), f, up.URL)
				done <- out
			}()
			select {
			case out := <-done:
				if strings.Contains(streamTailReceivedText(f, out), streamTailMarker) {
					t.Fatal("the marker reached the client")
				}
			case <-time.After(streamHoldMaxAge + 3*time.Second):
				t.Fatal("a mid-stream block did not end the handler while the upstream stays open")
			}
			waitStreamReaders(t, readers)
		})
		t.Run(f.name+"/client-goes-away", func(t *testing.T) {
			readers := streamReaderGoroutines()
			stall := make(chan struct{})
			defer close(stall)
			up, _ := streamTailUpstream(t, f, streamTailDeltas(1500, 24), 0, stall)
			insp := &streamTailInspector{mockInspector: newMockInspector(), final: true, mid: true}
			front, served := streamTailFront(t, streamTailProxy(t, f.provider, insp, "action"))
			ctx, cancel := context.WithCancel(context.Background())
			resp, err := http.DefaultClient.Do(streamTailRequest(t, f, front.URL, up.URL).WithContext(ctx))
			if err != nil {
				cancel()
				t.Fatal(err)
			}
			received := streamTailClientRead(resp)
			until := time.Now().Add(streamHoldMaxAge + 2*time.Second)
			for len(received()) == 0 && time.Now().Before(until) {
				time.Sleep(10 * time.Millisecond)
			}
			cancel()
			_ = resp.Body.Close()
			select {
			case <-served:
			case <-time.After(3 * time.Second):
				t.Fatal("the handler did not end when the client went away")
			}
			waitStreamReaders(t, readers)
		})
	}
}

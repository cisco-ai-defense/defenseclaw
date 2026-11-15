// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"
)

// A busy proxy is not a quiet upstream. When the handler spends longer
// than streamHoldMaxPartialAge on one read (a long event under load, a slow
// mid-stream check) while the upstream goes on sending, the stall bound
// does not fire on the event in progress: the read that waits goes first.
// Before, the expired stall timer and the waiting read were both ready and
// select picked one at random. A false TRUNCATED alert followed (a block in
// strict). Eight streams at once, so that coin flip shows.
func TestStreamTailBusyProxyIsNotAQuietUpstream(t *testing.T) {
	f := streamTailFormatNamed(t, "anthropic")
	pre := f.head + f.delta(streamTailProse(1440))
	d := f.delta("words that come in two reads")
	want := pre + d + f.tail + f.terminal
	type run struct {
		proxy *GuardrailProxy
		up    *httptest.Server
	}
	runs := make([]run, 8)
	for i := range runs {
		up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", f.ctype)
			w.WriteHeader(http.StatusOK)
			fl := w.(http.Flusher)
			for _, part := range []string{pre, d[:len(d)/2], d[len(d)/2:] + f.tail + f.terminal} {
				_, _ = io.WriteString(w, part)
				fl.Flush()
				select {
				case <-time.After(300 * time.Millisecond):
				case <-r.Context().Done():
					return
				}
			}
		}))
		t.Cleanup(up.Close)
		insp := &streamTailInspector{mockInspector: newMockInspector(), final: true, mid: true}
		proxy := streamTailProxy(t, f.provider, insp, "action")
		var once sync.Once
		// The handler is busy right after the read that leaves half an
		// event in progress; the upstream sends the rest meanwhile.
		proxy.streamReadForTest = func(total int) {
			if total > len(pre) {
				once.Do(func() { time.Sleep(streamHoldMaxPartialAge + 500*time.Millisecond) })
			}
		}
		runs[i] = run{proxy: proxy, up: up}
	}
	outs := make([]string, len(runs))
	var wg sync.WaitGroup
	for i, r := range runs {
		req := streamTailRequest(t, f, "", r.up.URL)
		wg.Add(1)
		go func() {
			defer wg.Done()
			rec := httptest.NewRecorder()
			r.proxy.handlePassthrough(rec, req)
			outs[i] = rec.Body.String()
		}()
	}
	wg.Wait()
	for i, r := range runs {
		alerts, err := r.proxy.store.ListAlerts(50)
		if err != nil {
			t.Fatal(err)
		}
		if strings.Contains(fmt.Sprintf("%+v", alerts), "bounded_truncated") {
			t.Errorf("stream %d: a busy proxy was taken for a quiet upstream (TRUNCATED): %+v", i, alerts)
		}
		if outs[i] != want {
			t.Errorf("stream %d changed: got %d bytes, want %d", i, len(outs[i]), len(want))
		}
	}
}

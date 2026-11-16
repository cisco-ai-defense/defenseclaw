// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"net/http/httptrace"
	"net/textproto"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/gateway/connector/hookexec"
)

// postCountingProgress sends one hook call to handler over a real loopback
// connection and counts the 102 reports it gets before the answer.
func postCountingProgress(t *testing.T, handler http.HandlerFunc, askForProgress bool) (reports int32, status int, body string) {
	t.Helper()
	server := httptest.NewServer(handler)
	defer server.Close()
	var count atomic.Int32
	ctx := httptrace.WithClientTrace(context.Background(), &httptrace.ClientTrace{
		Got1xxResponse: func(code int, _ textproto.MIMEHeader) error {
			if code == hookexec.HookProgressStatus {
				count.Add(1)
			}
			return nil
		},
	})
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, server.URL+"/api/v1/codex/hook", strings.NewReader(`{}`))
	if err != nil {
		t.Fatal(err)
	}
	if askForProgress {
		req.Header.Set(hookexec.HookProgressHeader, "1")
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	data, _ := io.ReadAll(resp.Body)
	return count.Load(), resp.StatusCode, string(data)
}

// A decision that waits on a remote scanner reports it once, before the
// answer, so the hook keeps its whole budget for the scanner (GAP-0155).
func TestHookProgressIsReportedOnceBeforeARemoteScannerWait(t *testing.T) {
	reports, status, body := postCountingProgress(t, func(w http.ResponseWriter, r *http.Request) {
		w, r, done := withHookProgress(w, r)
		defer done()
		resume := yieldHookRunSlot(r.Context())
		resume()
		reportHookProgress(r.Context())
		_, _ = w.Write([]byte(`{"action":"allow"}`))
		// After the answer a report is never sent.
		reportHookProgress(r.Context())
	}, true)
	if reports != 1 || status != http.StatusOK || body != `{"action":"allow"}` {
		t.Fatalf("reports=%d status=%d body=%q, want one report and the answer", reports, status, body)
	}
}

// A client that does not ask for progress reports never gets one.
func TestHookProgressIsSentOnlyWhenAsked(t *testing.T) {
	reports, status, _ := postCountingProgress(t, func(w http.ResponseWriter, r *http.Request) {
		w, r, done := withHookProgress(w, r)
		defer done()
		reportHookProgress(r.Context())
		_, _ = w.Write([]byte(`{}`))
	}, false)
	if reports != 0 || status != http.StatusOK {
		t.Fatalf("reports=%d status=%d, want none", reports, status)
	}
}

// The request metrics record the final status, not the 102 report, also
// when the answer is a body written without a status.
func TestHookProgressKeepsTheRecordedStatusFinal(t *testing.T) {
	var recorded atomic.Int32
	_, status, _ := postCountingProgress(t, func(w http.ResponseWriter, r *http.Request) {
		sw := &statusWriter{ResponseWriter: w, status: http.StatusOK}
		inner, r, done := withHookProgress(sw, r)
		reportHookProgress(r.Context())
		_, _ = inner.Write([]byte(`{}`))
		done()
		recorded.Store(int32(sw.status))
	}, true)
	if status != http.StatusOK || recorded.Load() != http.StatusOK {
		t.Fatalf("status=%d recorded=%d, want 200 for both", status, recorded.Load())
	}
}

// The in-process recorders keep the answer, not the 102 report.
func TestInProcessRecordersIgnoreTheProgressReport(t *testing.T) {
	acp := &acpSignedResponse{header: make(http.Header)}
	acp.WriteHeader(hookexec.HookProgressStatus)
	acp.WriteHeader(http.StatusForbidden)
	if acp.status != http.StatusForbidden {
		t.Fatalf("acp status = %d, want 403", acp.status)
	}
	recorder := &idempotencyRecorder{ResponseWriter: httptest.NewRecorder()}
	recorder.WriteHeader(hookexec.HookProgressStatus)
	recorder.WriteHeader(http.StatusConflict)
	if recorder.status != http.StatusConflict {
		t.Fatalf("idempotency status = %d, want 409", recorder.status)
	}
}

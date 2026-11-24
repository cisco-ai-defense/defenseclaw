// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

// GAP-0011 part 2: past the cliff every hook call ran at once (447
// goroutines at 35 calls/s, PROF-0011B) and calls whose hook had already
// given up kept working. Hook calls now take one of a bounded number of
// admission slots before the gateway authenticates and evaluates them; a
// call whose request ends while it waits for a slot is dropped there,
// answered 503 and recorded as a rejection, and never evaluated.
func TestGAP0011HookAdmissionBoundsCallsAndDropsAbandonedOnes(t *testing.T) {
	previous := gatewayHookAdmission
	gatewayHookAdmission = newHookAdmission(2)
	t.Cleanup(func() { gatewayHookAdmission = previous })

	a := &APIServer{}
	first, ok := a.admitHookCall(httptest.NewRecorder(), httptest.NewRequest(http.MethodPost, "/api/v1/hooks/codex", nil), "codex")
	if !ok {
		t.Fatal("first call not admitted")
	}
	second, ok := a.admitHookCall(httptest.NewRecorder(), httptest.NewRequest(http.MethodPost, "/api/v1/hooks/codex", nil), "codex")
	if !ok {
		t.Fatal("second call not admitted")
	}

	// A third call waits; its hook gives up (the request context ends).
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	recorder := httptest.NewRecorder()
	start := time.Now()
	if _, ok := a.admitHookCall(recorder, httptest.NewRequest(http.MethodPost, "/api/v1/hooks/codex", nil).WithContext(ctx), "codex"); ok {
		t.Fatal("a third call was admitted past the bound")
	}
	if waited := time.Since(start); waited > 2*time.Second {
		t.Fatalf("the abandoned call waited %s after its request ended", waited)
	}
	if recorder.Code != http.StatusServiceUnavailable {
		t.Fatalf("abandoned call answered %d, want 503", recorder.Code)
	}

	// A waiting call is admitted as soon as a slot is released.
	admitted := make(chan bool, 1)
	go func() {
		release, ok := a.admitHookCall(httptest.NewRecorder(), httptest.NewRequest(http.MethodPost, "/api/v1/hooks/codex", nil), "codex")
		if ok {
			release()
		}
		admitted <- ok
	}()
	time.Sleep(20 * time.Millisecond)
	first()
	select {
	case ok := <-admitted:
		if !ok {
			t.Fatal("the waiting call was not admitted after a release")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("the waiting call was not admitted after a release")
	}
	second()
	if limit := hookAdmissionLimit(); limit < 32 {
		t.Fatalf("hook admission limit %d is below the floor of 32", limit)
	}
}

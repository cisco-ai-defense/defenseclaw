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

func TestRV518CanceledParkedHookKeepsHostAdmissionBound(t *testing.T) {
	const path = "/api/v1/claude-code/hook"
	api := &APIServer{}
	api.hookCallerLimits = hookCallerLimiter{rate: 1000, burst: 1000, globalInFlight: 1}
	ctx, cancel := context.WithCancel(t.Context())
	req, release := api.admitHookCaller(httptest.NewRecorder(), httptest.NewRequest(http.MethodPost, path, nil).WithContext(ctx), "first", path)
	if release == nil {
		t.Fatal("first hook refused")
	}
	defer release()
	resume := parkHookCaller(req.Context())
	defer resume()
	cancel()
	deadline := time.Now().Add(time.Second)
	for {
		api.hookCallerLimits.mu.Lock()
		total := api.hookCallerLimits.total
		api.hookCallerLimits.mu.Unlock()
		if total == 0 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("canceled hook did not release its admission")
		}
		time.Sleep(time.Millisecond)
	}
	_, second := api.admitHookCaller(httptest.NewRecorder(), httptest.NewRequest(http.MethodPost, path, nil), "second", path)
	if second == nil {
		t.Fatal("first live hook refused")
	}
	defer second()
	_, third := api.admitHookCaller(httptest.NewRecorder(), httptest.NewRequest(http.MethodPost, path, nil), "third", path)
	if third != nil {
		third()
		t.Fatal("two live hooks admitted with globalInFlight=1 while canceled parked hook had not resumed")
	}
}

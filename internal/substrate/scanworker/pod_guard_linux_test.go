// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package scanworker

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/processutil"
)

func TestPodWorkerRefusesItsOwnScannerPeer(t *testing.T) {
	w := &Worker{Pod: &processutil.PodRunner{}}
	h := w.Handler()
	for _, pid := range []int32{2, 1, -1} {
		r := httptest.NewRequest(http.MethodGet, "/v1/health", nil)
		r = r.WithContext(context.WithValue(r.Context(), peerKey{}, pid))
		rw := httptest.NewRecorder()
		h.ServeHTTP(rw, r)
		if rw.Code != http.StatusForbidden {
			t.Errorf("peer PID %d health status = %d, want 403", pid, rw.Code)
		}
	}
	r := httptest.NewRequest(http.MethodGet, "/v1/health", nil)
	r = r.WithContext(context.WithValue(r.Context(), peerKey{}, int32(0)))
	rw := httptest.NewRecorder()
	h.ServeHTTP(rw, r)
	if rw.Code != http.StatusOK {
		t.Errorf("gateway peer health status = %d, want 200", rw.Code)
	}
}

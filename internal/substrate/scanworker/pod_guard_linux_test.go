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
	r := httptest.NewRequest(http.MethodGet, "/v1/health", nil)
	r = r.WithContext(context.WithValue(r.Context(), peerKey{}, int32(2)))
	rw := httptest.NewRecorder()
	w.Handler().ServeHTTP(rw, r)
	if rw.Code != http.StatusForbidden {
		t.Fatalf("scanner peer health status = %d, want 403", rw.Code)
	}
}

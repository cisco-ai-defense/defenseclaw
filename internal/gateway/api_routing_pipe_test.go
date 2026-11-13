// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/managed/refusalpipe"
)

func TestRoutingPipeCallerKeyIsTheSID(t *testing.T) {
	const sid = "S-1-5-21-1-2-3-1001"
	r := httptest.NewRequest(http.MethodGet, "/api/v1/routing/budgets", nil).WithContext(withRoutingPipeCaller(context.Background(), sid))
	got, ok := routingPipeCallerFromContext(r.Context())
	if !ok || got != sid {
		t.Fatalf("pipe caller %q %v", got, ok)
	}
	if _, ok := routingPipeCallerFromContext(context.Background()); ok {
		t.Fatal("no pipe caller on other requests")
	}
	a := &APIServer{}
	if a.routingPipeAnswer(context.Background(), sid, "/api/v1/routing/test") != nil {
		t.Fatal("the dry run is not served on the pipe")
	}
	if a.routingPipeAnswer(context.Background(), "", "/api/v1/routing/budgets") != nil {
		t.Fatal("no SID, no answer")
	}
	w := &routingPipeResponse{header: http.Header{}, status: 200}
	_, _ = w.Write(make([]byte, refusalpipe.MaxRoutingAnswerBytes))
	if !w.over {
		t.Fatal("an answer over the pipe limit is refused")
	}
}

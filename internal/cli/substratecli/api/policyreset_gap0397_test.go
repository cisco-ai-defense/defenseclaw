// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package api

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

// GAP-0397: policy reset posts to the route the gateway serves,
// POST /api/v1/substrate/actors/{atespace}/{name}/policy/reset, with the
// reason in the body; every reset was a 404 before.
func TestPolicyResetUsesTheGatewayRouteGAP0397(t *testing.T) {
	var gotMethod, gotPath, gotReason string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotMethod, gotPath = r.Method, r.URL.Path
		var in map[string]string
		_ = json.NewDecoder(r.Body).Decode(&in)
		gotReason = in["reason"]
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusAccepted)
		_, _ = w.Write([]byte(`{"status":"requested"}`))
	}))
	defer srv.Close()
	c, err := New(Options{Base: srv.URL, HTTP: srv.Client(), Token: func(context.Context) (string, error) { return "t", nil }})
	if err != nil {
		t.Fatal(err)
	}
	out, err := c.PolicyReset(context.Background(), "dc-eng/agent-1", "conflict reviewed")
	if err != nil {
		t.Fatal(err)
	}
	if gotMethod != http.MethodPost || gotPath != "/api/v1/substrate/actors/dc-eng/agent-1/policy/reset" || gotReason != "conflict reviewed" {
		t.Fatalf("%s %s reason %q, want POST /api/v1/substrate/actors/dc-eng/agent-1/policy/reset", gotMethod, gotPath, gotReason)
	}
	if out["status"] != "requested" {
		t.Errorf("answer %v", out)
	}
}

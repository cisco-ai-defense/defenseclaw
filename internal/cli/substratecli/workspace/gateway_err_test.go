// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package workspace

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// A refusal by the cluster gateway in front of the relay says who refused
// and what to do, not the raw JSON (seen live: run on a cluster whose
// gateway has no attach route, GAP-0157).
func TestGatewayRefusalSaysWhatToDo(t *testing.T) {
	for reason, want := range map[string]string{
		"attach_unavailable": "the cluster cannot connect you to agents yet",
		"relay_unreachable":  "it may still be starting",
		"no_actor":           "defenseclaw substrate list",
		"busy_now":           "the cluster refused the status request (HTTP 503: busy now)",
	} {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusServiceUnavailable)
			_, _ = io.WriteString(w, `{"error":"Service Unavailable","reason":"`+reason+`"}`)
		}))
		c := NewClient(srv.Client(), srv.URL, func(context.Context) (string, error) { return "t", nil })
		_, err := c.DetectRoot(t.Context())
		srv.Close()
		if err == nil {
			t.Fatalf("%s: no error", reason)
		}
		msg := err.Error()
		if !strings.Contains(msg, want) || strings.Contains(msg, "{") || strings.Contains(msg, "the actor refused") {
			t.Errorf("%s: %q, want %q and no raw JSON", reason, msg, want)
		}
	}
	// A relay refusal (plain text) still names the actor.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusForbidden)
		_, _ = io.WriteString(w, "relay: not your session")
	}))
	defer srv.Close()
	c := NewClient(srv.Client(), srv.URL, func(context.Context) (string, error) { return "t", nil })
	if _, err := c.DetectRoot(t.Context()); err == nil || !strings.Contains(err.Error(), "the actor refused the status request (HTTP 403): not your session") {
		t.Errorf("relay refusal: %v", err)
	}
}

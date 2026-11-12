// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	substrateapi "github.com/defenseclaw/defenseclaw/internal/cli/substratecli/api"
)

// TestLauncherWritesPassTheAdminCSRFGate runs the launcher's API client
// against the real CSRF middleware of the admin listener (GAP-0102): every
// write it makes, a DELETE with no body included, must get through.
func TestLauncherWritesPassTheAdminCSRFGate(t *testing.T) {
	api, _ := tokenAuthTestServer(t, "unused")
	var seen []string
	srv := httptest.NewServer(api.apiCSRFProtect(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seen = append(seen, r.Method+" "+r.URL.Path)
		w.Header().Set("Content-Type", "application/json")
		if r.Method == http.MethodGet {
			_, _ = w.Write([]byte(`{"actors":[],"asks":[]}`))
			return
		}
		_, _ = w.Write([]byte(`{}`))
	})))
	defer srv.Close()
	c, err := substrateapi.New(substrateapi.Options{Base: srv.URL, Token: func(context.Context) (string, error) { return "t", nil }})
	if err != nil {
		t.Fatal(err)
	}
	ctx := t.Context()
	calls := map[string]func() error{
		"create": func() error {
			_, err := c.Create(ctx, substrateapi.CreateRequest{Profile: "p", Template: "t"})
			return err
		},
		"delete":    func() error { return c.Delete(ctx, "eng-web", "a1") },
		"decide":    func() error { return c.Decide(ctx, "ask-1", "approve", false, "") },
		"setsecret": func() error { return c.SetSecret(ctx, "NPM_TOKEN", "v") },
		"rmsecret":  func() error { return c.RemoveSecret(ctx, "NPM_TOKEN") },
		"session":   func() error { _, err := c.SessionCert(ctx, "eng-web", "a1", 0); return err },
		"list":      func() error { _, err := c.List(ctx, substrateapi.ListOptions{}); return err },
	}
	for name, call := range calls {
		if err := call(); err != nil {
			t.Errorf("%s was refused by the CSRF gate: %v", name, err)
		}
	}
	if len(seen) != len(calls) {
		t.Errorf("the handler saw %d of %d calls: %v", len(seen), len(calls), seen)
	}
}

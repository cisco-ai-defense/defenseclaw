// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// SPDX-License-Identifier: Apache-2.0

package dashboard

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestHandler_ServesIndexAtRoot(t *testing.T) {
	h := Handler()
	ts := httptest.NewServer(h)
	defer ts.Close()

	resp, err := ts.Client().Get(ts.URL + "/")
	if err != nil {
		t.Fatalf("GET /: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("GET /: status = %d, want 200", resp.StatusCode)
	}
	body, _ := io.ReadAll(resp.Body)
	if !strings.Contains(string(body), "<dc-app>") {
		t.Errorf("GET /: body missing <dc-app> tag; got %q", truncate(string(body), 120))
	}
	if ct := resp.Header.Get("Content-Type"); !strings.HasPrefix(ct, "text/html") {
		t.Errorf("GET /: Content-Type = %q, want text/html", ct)
	}
	if csp := resp.Header.Get("Content-Security-Policy"); csp == "" {
		t.Error("GET /: missing Content-Security-Policy header")
	}
}

func TestHandler_SpaFallbackForUnknownPaths(t *testing.T) {
	h := Handler()
	ts := httptest.NewServer(h)
	defer ts.Close()

	// Deep-link paths like /alerts should return the SPA shell (the client-
	// side router handles the hash).
	for _, path := range []string{"/alerts", "/skills", "/some/deep/path"} {
		resp, err := ts.Client().Get(ts.URL + path)
		if err != nil {
			t.Fatalf("GET %s: %v", path, err)
		}
		body, _ := io.ReadAll(resp.Body)
		resp.Body.Close()

		if resp.StatusCode != http.StatusOK {
			t.Errorf("GET %s: status = %d, want 200", path, resp.StatusCode)
		}
		if !strings.Contains(string(body), "<dc-app>") {
			t.Errorf("GET %s: SPA fallback did not return index.html", path)
		}
	}
}

func TestHandler_AssetsGetLongCache(t *testing.T) {
	h := Handler()
	ts := httptest.NewServer(h)
	defer ts.Close()

	// Make a request to root to discover the index.html, then find the
	// hashed asset filenames it references.
	resp, err := ts.Client().Get(ts.URL + "/")
	if err != nil {
		t.Fatalf("GET /: %v", err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()

	// Find the first /assets/ URL referenced in the index.
	idx := strings.Index(string(body), "/assets/")
	if idx < 0 {
		t.Skip("index.html has no /assets/ references (dashboard unbuilt)")
	}
	end := idx
	for end < len(body) && body[end] != '"' && body[end] != '\'' {
		end++
	}
	asset := string(body[idx:end])

	resp2, err := ts.Client().Get(ts.URL + asset)
	if err != nil {
		t.Fatalf("GET %s: %v", asset, err)
	}
	defer resp2.Body.Close()
	if resp2.StatusCode != http.StatusOK {
		t.Fatalf("GET %s: status = %d, want 200", asset, resp2.StatusCode)
	}
	cc := resp2.Header.Get("Cache-Control")
	if !strings.Contains(cc, "immutable") {
		t.Errorf("GET %s: Cache-Control = %q, want immutable", asset, cc)
	}
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "…"
}

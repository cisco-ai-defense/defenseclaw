// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package managedaid

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/observability/destinations/push"
)

func receiptFixture(hash, nonce string) ManifestReceipt {
	return ManifestReceipt{Version: 1, Nonce: nonce, Scope: "sha256:" + strings.Repeat("b", 64), Revision: "sha256:" + strings.Repeat("c", 64), ManifestHash: hash, State: "incomplete", PartsTotal: 3, Parts: []ManifestPartReceipt{{1, "sha256:" + strings.Repeat("d", 64)}, {3, "sha256:" + strings.Repeat("e", 64)}}, MissingParts: []int{2}}
}

func receiptTestClient(t *testing.T, handler http.HandlerFunc) (*ManifestReceiptClient, *testResolver) {
	t.Helper()
	server := httptest.NewTLSServer(handler)
	t.Cleanup(server.Close)
	resolver := &testResolver{provider: &testProvider{token: "receipt-test-token", fresh: "fresh-receipt-test-token"}}
	client, err := NewManifestReceiptClient(t.Context(), server.URL+config.ObservabilityV8ManagedAIDIngestPath, resolver, push.NetworkOptions{AllowPrivateNetworks: true}, nil)
	if err != nil {
		t.Fatal(err)
	}
	transport := server.Client()
	transport.CheckRedirect = client.adapter.client.CheckRedirect
	client.adapter.client = transport
	return client, resolver
}

func TestManifestReceiptHTTPBindsFreshNonceAndManagedCredentials(t *testing.T) {
	var nonces []string
	hash := "sha256:" + strings.Repeat("a", 64)
	client, resolver := receiptTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || r.URL.Path != "/api/v1/inspect/defense_claw/skill-manifest-receipts" || r.Header.Get("Authorization") != "Bearer receipt-test-token" || r.Header.Get("Cache-Control") != "no-store" || r.Header.Get("Content-Type") != "application/json" {
			t.Errorf("invalid managed request method/path/headers")
		}
		data, _ := io.ReadAll(io.LimitReader(r.Body, 4097))
		if len(data) > 4096 || strings.Contains(string(data), "tenant") || strings.Contains(string(data), "content") {
			t.Error("unbounded/identity/content-bearing request")
		}
		var request struct {
			Version             int `json:"version"`
			Nonce, ManifestHash string
			ExpectedParts       int `json:"expected_parts"`
		}
		var raw map[string]json.RawMessage
		if json.Unmarshal(data, &raw) != nil {
			t.Error("invalid request")
		}
		_ = json.Unmarshal(raw["nonce"], &request.Nonce)
		_ = json.Unmarshal(raw["manifest_hash"], &request.ManifestHash)
		_ = json.Unmarshal(raw["expected_parts"], &request.ExpectedParts)
		if request.ManifestHash != hash || request.ExpectedParts != 3 || len(raw) != 4 {
			t.Error("wrong receipt scope request")
		}
		nonces = append(nonces, request.Nonce)
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Cache-Control", "no-store")
		_ = json.NewEncoder(w).Encode(receiptFixture(hash, request.Nonce))
	})
	if resolver.calls.Load() != 0 {
		t.Fatal("constructor resolved credentials")
	}
	for range 2 {
		got, err := client.ReadManifestReceipt(t.Context(), hash, 3)
		if err != nil || got.State != "incomplete" || len(got.MissingParts) != 1 || got.MissingParts[0] != 2 {
			t.Fatalf("receipt=%+v err=%v", got, err)
		}
	}
	if len(nonces) != 2 || nonces[0] == nonces[1] {
		t.Fatal("request reused nonce")
	}
}

func TestManifestReceiptHTTPRejectsUntrustedOrUnboundedResponses(t *testing.T) {
	hash := "sha256:" + strings.Repeat("a", 64)
	tests := map[string]func(ManifestReceipt) string{
		"case alias":      func(r ManifestReceipt) string { return strings.Replace(marshalReceipt(r), `"version"`, `"VERSION"`, 1) },
		"part case alias": func(r ManifestReceipt) string { return strings.Replace(marshalReceipt(r), `"part"`, `"PART"`, 1) },
		"wrong nonce":     func(r ManifestReceipt) string { r.Nonce = strings.Repeat("f", 32); return marshalReceipt(r) },
		"wrong hash": func(r ManifestReceipt) string {
			r.ManifestHash = "sha256:" + strings.Repeat("f", 64)
			return marshalReceipt(r)
		},
		"duplicate top key": func(r ManifestReceipt) string { return strings.TrimSuffix(marshalReceipt(r), "}") + `,"version":1}` },
		"duplicate nested key": func(r ManifestReceipt) string {
			return strings.Replace(marshalReceipt(r), `"part":1`, `"part":1,"part":1`, 1)
		},
		"unknown identity": func(r ManifestReceipt) string {
			return strings.TrimSuffix(marshalReceipt(r), "}") + `,"tenant":"other"}`
		},
		"unknown part identity": func(r ManifestReceipt) string {
			return strings.Replace(marshalReceipt(r), `"part":1`, `"part":1,"device":"other"`, 1)
		},
		"trailing JSON": func(r ManifestReceipt) string { return marshalReceipt(r) + `{}` },
		"oversize": func(r ManifestReceipt) string {
			return strings.Repeat(" ", maxManifestReceiptResponse) + marshalReceipt(r)
		},
		"null parts":      func(r ManifestReceipt) string { r.Parts = nil; return marshalReceipt(r) },
		"null missing":    func(r ManifestReceipt) string { r.MissingParts = nil; return marshalReceipt(r) },
		"duplicate index": func(r ManifestReceipt) string { r.Parts[1].Part = 1; return marshalReceipt(r) },
		"unsorted index": func(r ManifestReceipt) string {
			r.Parts[0], r.Parts[1] = r.Parts[1], r.Parts[0]
			return marshalReceipt(r)
		},
		"missing mismatch": func(r ManifestReceipt) string { r.MissingParts = []int{1}; return marshalReceipt(r) },
		"complete prefix":  func(r ManifestReceipt) string { r.State = "complete"; return marshalReceipt(r) },
		"invalid digest": func(r ManifestReceipt) string {
			r.Parts[0].SHA256 = "sha256:" + strings.Repeat("A", 64)
			return marshalReceipt(r)
		},
		"conflict prefix": func(r ManifestReceipt) string { r.State = "conflict"; return marshalReceipt(r) },
	}
	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			client, _ := receiptTestClient(t, func(w http.ResponseWriter, r *http.Request) {
				var req map[string]any
				_ = json.NewDecoder(r.Body).Decode(&req)
				w.Header().Set("Content-Type", "application/json")
				_, _ = io.WriteString(w, mutate(receiptFixture(hash, req["nonce"].(string))))
			})
			if _, err := client.ReadManifestReceipt(t.Context(), hash, 3); !errors.Is(err, ErrReceiptInvalid) {
				t.Fatalf("err=%v; want bounded invalid", err)
			}
		})
	}
}
func marshalReceipt(r ManifestReceipt) string { data, _ := json.Marshal(r); return string(data) }

func TestManifestReceiptHTTPOldServerErrorsAndRedirectsNeverAcknowledge(t *testing.T) {
	hash := "sha256:" + strings.Repeat("a", 64)
	for _, status := range []int{301, 302, 307, 308, 400, 401, 403, 404, 405, 429, 500, 501, 503} {
		t.Run(http.StatusText(status), func(t *testing.T) {
			var calls atomic.Int64
			client, _ := receiptTestClient(t, func(w http.ResponseWriter, r *http.Request) {
				calls.Add(1)
				w.Header().Set("Location", "https://credential-leak.example.test/")
				w.WriteHeader(status)
				_, _ = io.WriteString(w, "SSO URL secret should never escape")
			})
			got, err := client.ReadManifestReceipt(t.Context(), hash, 3)
			want := ErrReceiptUnavailable
			if status == 404 || status == 405 || status == 501 {
				want = ErrReceiptUnsupported
			}
			if !errors.Is(err, want) || got.State != "" || strings.Contains(err.Error(), "SSO") || calls.Load() > 2 {
				t.Fatalf("receipt=%+v err=%v calls=%d", got, err, calls.Load())
			}
		})
	}
}

func TestManifestReceiptHTTPContextAndContentType(t *testing.T) {
	hash := "sha256:" + strings.Repeat("a", 64)
	client, _ := receiptTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		_, _ = io.WriteString(w, "login")
	})
	if _, err := client.ReadManifestReceipt(t.Context(), hash, 3); !errors.Is(err, ErrReceiptInvalid) {
		t.Fatalf("content-type err=%v", err)
	}
	ctx, cancel := context.WithDeadline(t.Context(), time.Now().Add(-time.Second))
	defer cancel()
	if _, err := client.ReadManifestReceipt(ctx, hash, 3); !errors.Is(err, ErrReceiptUnavailable) {
		t.Fatalf("deadline err=%v", err)
	}
}

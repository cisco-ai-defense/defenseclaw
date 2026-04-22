// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// corpusCase mirrors one row of test/testdata/llm-endpoints.json. The
// corpus is the shared contract between TS + Go shape detection; this
// test drives the Go side of that contract so a drift (e.g. a new
// provider added only to providers.json or only to the TS code) fails
// loudly in CI instead of silently passing traffic through as an
// egress bypass.
type corpusCase struct {
	Name           string          `json:"name"`
	URL            string          `json:"url"`
	Method         string          `json:"method"`
	Body           json.RawMessage `json:"body"`
	ExpectedBranch string          `json:"expected_branch"`
	Notes          string          `json:"notes,omitempty"`
}

type corpus struct {
	Positive []corpusCase `json:"positive"`
	Negative []corpusCase `json:"negative"`
}

func loadCorpus(t *testing.T) corpus {
	t.Helper()
	// Walk up from internal/gateway to the repo root so this test
	// survives being run via `go test ./...`.
	wd, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	var root string
	for dir := wd; dir != "/" && dir != ""; dir = filepath.Dir(dir) {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			root = dir
			break
		}
	}
	if root == "" {
		t.Fatalf("could not locate repo root from %s", wd)
	}
	path := filepath.Join(root, "test", "testdata", "llm-endpoints.json")
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read corpus: %v", err)
	}
	var c corpus
	if err := json.Unmarshal(raw, &c); err != nil {
		t.Fatalf("parse corpus: %v", err)
	}
	return c
}

// classifyURL returns the branch label Go-side shape detection would
// assign to a single corpus row. We run a parallel "known provider"
// check via providers.json + a shape check via isLLMPathSuffix +
// isLLMShapedBody to mirror what handlePassthrough does at runtime.
func classifyURL(t *testing.T, urlStr, method string, body json.RawMessage) string {
	t.Helper()
	if urlStr == "" {
		return "passthrough"
	}
	// known branch: hostname is on providers.json
	if isKnownProviderDomain(urlStr) {
		return "known"
	}
	// Safe method never intercepts.
	m := strings.ToUpper(method)
	if m == "GET" || m == "HEAD" || m == "OPTIONS" {
		return "passthrough"
	}
	// Known-safe allowlist beats both path and body shape.
	if isKnownSafeDomain(urlStr) {
		return "passthrough"
	}
	if isLLMPathSuffix(urlStr) {
		return "shape"
	}
	if len(body) > 0 && !bytesIsJSONNull(body) {
		if _, ok := isLLMShapedBody(body); ok {
			return "shape"
		}
	}
	return "passthrough"
}

func bytesIsJSONNull(b json.RawMessage) bool {
	s := strings.TrimSpace(string(b))
	return s == "null"
}

// TestProviderCoverageCorpus_Positive pins that every positive row in
// the canonical corpus produces either "known" (hostname match) or
// "shape" (path/body match). A row that slips to "passthrough" here
// is the exact silent-bypass failure this suite exists to catch.
func TestProviderCoverageCorpus_Positive(t *testing.T) {
	c := loadCorpus(t)
	if len(c.Positive) == 0 {
		t.Fatal("corpus positive[] is empty")
	}
	for _, row := range c.Positive {
		t.Run(row.Name, func(t *testing.T) {
			got := classifyURL(t, row.URL, row.Method, row.Body)
			if got == "passthrough" {
				t.Fatalf("%s: expected intercept, got passthrough (notes: %s)", row.URL, row.Notes)
			}
			if row.ExpectedBranch != "" && got != row.ExpectedBranch {
				t.Fatalf("%s: expected branch=%s, got %s", row.URL, row.ExpectedBranch, got)
			}
		})
	}
}

// TestProviderCoverageCorpus_Negative pins that every negative row is
// classified as passthrough. A false positive here produces bogus
// proxy overhead and breaks unrelated traffic (e.g. npm installs).
func TestProviderCoverageCorpus_Negative(t *testing.T) {
	c := loadCorpus(t)
	if len(c.Negative) == 0 {
		t.Fatal("corpus negative[] is empty")
	}
	for _, row := range c.Negative {
		t.Run(row.Name, func(t *testing.T) {
			got := classifyURL(t, row.URL, row.Method, row.Body)
			if got != "passthrough" {
				t.Fatalf("%s: expected passthrough, got %s (notes: %s)", row.URL, got, row.Notes)
			}
		})
	}
}

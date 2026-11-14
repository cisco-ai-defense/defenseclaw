// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build s7bench

package main

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/gateway"
)

const fillRealAnswer = `{"answers":{"disposition":{"type":"choice","choice":"allow","probabilities":{"allow":0.9,"confirm":0.05,"block":0.05}}}}`

func fillPost(t *testing.T, url, body string) (int, string) {
	t.Helper()
	resp, err := http.Post(url, "application/json", strings.NewReader(body))
	if err != nil {
		t.Fatalf("post: %v", err)
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, string(raw)
}

// A fill run answers every miss at once, however slow the upstream is, and still stores the real answer.
func TestDMFillAnswersAtOnceAndStoresTheRealAnswer(t *testing.T) {
	var upstream atomic.Int64
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		upstream.Add(1)
		time.Sleep(1500 * time.Millisecond) // past the product's whole hook answer window
		_, _ = w.Write([]byte(fillRealAnswer))
	}))
	defer srv.Close()
	dir := t.TempDir()
	url, c, err := startDMCache(srv.URL, config.DecisionModelProtocolGeminiDecisions, dir, false, true, 4, 0, 0, "", 0, "")
	if err != nil {
		t.Fatal(err)
	}
	bodies := []string{`{"n":1}`, `{"n":2}`, `{"n":3}`, `{"n":1}`} // one repeat: fetched once
	start := time.Now()
	for _, b := range bodies {
		st, got := fillPost(t, url, b)
		if st != http.StatusOK || got != dmFillStub {
			t.Fatalf("body %s: status %d answer %q, want the fill stub", b, st, got)
		}
	}
	if d := time.Since(start); d > time.Second {
		t.Fatalf("four misses took %v: the fill must not wait for the upstream", d)
	}
	if n := c.fillWait(io.Discard); n != 0 {
		t.Fatalf("fillWait: %d unanswered", n)
	}
	if got := upstream.Load(); got != 3 {
		t.Fatalf("upstream calls = %d, want 3 (one per distinct body)", got)
	}
	// The stub was never stored; the real answer was: a replay returns it.
	url2, c2, err := startDMCache(srv.URL, config.DecisionModelProtocolGeminiDecisions, dir, true, false, 4, 0, 0, "", 0, "")
	if err != nil {
		t.Fatal(err)
	}
	for _, b := range bodies {
		if st, got := fillPost(t, url2, b); st != http.StatusOK || got != fillRealAnswer {
			t.Fatalf("replay of %s: status %d answer %q, want the stored real answer", b, st, got)
		}
	}
	if c2.offlineMisses.Load() != 0 {
		t.Fatalf("replay missed %d", c2.offlineMisses.Load())
	}
}

// A request already stored answers with the real answer in a fill run, and is not sent again.
func TestDMFillUsesTheCacheAndRetriesRateLimits(t *testing.T) {
	var calls atomic.Int64
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if calls.Add(1) == 1 {
			w.Header().Set("Retry-After", "1")
			w.WriteHeader(http.StatusTooManyRequests)
			return
		}
		_, _ = w.Write([]byte(fillRealAnswer))
	}))
	defer srv.Close()
	dir := t.TempDir()
	url, c, err := startDMCache(srv.URL, "", dir, false, true, 1, 0, 0, "", 0, "")
	if err != nil {
		t.Fatal(err)
	}
	if st, got := fillPost(t, url, `{"k":1}`); st != 200 || got != dmFillStub {
		t.Fatalf("first answer %d %q", st, got)
	}
	if n := c.fillWait(io.Discard); n != 0 {
		t.Fatalf("a 429 with Retry-After must be waited out, %d unanswered", n)
	}
	if c.rateLimited.Load() != 1 || calls.Load() != 2 {
		t.Fatalf("rate_limited=%d upstream=%d, want 1 and 2", c.rateLimited.Load(), calls.Load())
	}
	if st, got := fillPost(t, url, `{"k":1}`); st != 200 || got != fillRealAnswer {
		t.Fatalf("a stored request must get the real answer in a fill run, got %d %q", st, got)
	}
	if calls.Load() != 2 {
		t.Fatalf("a stored request was sent again")
	}
}

// A request the upstream never answers is counted unanswered (the harness exits 4), never silently dropped.
func TestDMFillCountsUnanswered(t *testing.T) {
	dir := t.TempDir()
	budget := filepath.Join(t.TempDir(), "budget")
	url, c, err := startDMCache("http://127.0.0.1:1", "", dir, false, true, 1, 0, 0, budget, 1, "")
	if err != nil {
		t.Fatal(err)
	}
	// The budget file already holds its one request, so the first attempt finds the budget spent and the request stays unanswered.
	_ = os.WriteFile(budget, []byte("."), 0o644)
	fillPost(t, url, `{"u":1}`)
	if n := c.fillWait(io.Discard); n != 1 {
		t.Fatalf("unanswered = %d, want 1", n)
	}
}

func TestDMFillExcludesCacheOnly(t *testing.T) {
	if _, _, err := startDMCache("http://127.0.0.1:1", "", t.TempDir(), true, true, 1, 0, 0, "", 0, ""); err == nil {
		t.Fatal("-dm-fill with -dm-cache-only must be refused")
	}
}

// The fill stub is a valid answer for the product's parser, never a failure: it names a choice and its probabilities sum to one.
func TestDMFillStubIsAValidAnswer(t *testing.T) {
	var v struct {
		Answers struct {
			Disposition struct {
				Type, Choice  string
				Probabilities map[string]float64
			}
		}
	}
	if err := json.Unmarshal([]byte(dmFillStub), &v); err != nil {
		t.Fatal(err)
	}
	sum := 0.0
	for _, p := range v.Answers.Disposition.Probabilities {
		sum += p
	}
	if v.Answers.Disposition.Type != "choice" || v.Answers.Disposition.Choice != "confirm" || sum < 0.98 || sum > 1.02 {
		t.Fatalf("stub %+v is not a valid unsure choice", v)
	}
}

// The prompt surface scores the hook's answer; the text inspection is a diagnostic column only (rel-1-0-10:GAP-0554).
func TestPromptRecordScoresTheHookAnswer(t *testing.T) {
	hook := []byte(`{"action":"block","raw_action":"block","severity":"HIGH","reason":"detection-only x","findings":["TRUST-X:a"],"would_block":true,"rule_ids":["TRUST-X"]}`)
	insp := &gateway.ScanVerdict{Action: "allow", Severity: "NONE"}
	r := promptRecord("c1", "claudecode", 200, hook, insp, "")
	if r.Action != "block" || r.RawAction != "block" || r.Severity != "HIGH" || !r.WouldBlock || len(r.RuleIDs) != 1 || !r.DetOnly || r.Err != "" {
		t.Fatalf("scored fields are not the hook answer: %+v", r)
	}
	if r.Extra["scored_via"] != "hook" || r.Extra["inspect_action"] != "allow" || r.Extra["inspect_sev"] != "NONE" {
		t.Fatalf("diagnostic columns: %+v", r.Extra)
	}
	if r.Mapped != "prompt" || r.Tool != "UserPromptSubmit" || r.N != 1 {
		t.Fatalf("record shape changed: %+v", r)
	}
	// A hook that answers no JSON, or not 200, is an error row, never an allow.
	bad := promptRecord("c2", "cursor", 404, []byte(`not json`), insp, "cursor:404")
	if bad.Err == "" || bad.Action != "" || bad.Extra["connector_fallback"] != "cursor:404" {
		t.Fatalf("a refused hook must be an error row: %+v", bad)
	}
	if st := promptRecord("c3", "claudecode", 500, []byte(`{"action":"allow"}`), insp, ""); st.Err != "http 500" {
		t.Fatalf("status 500 must be an error row: %+v", st)
	}
	var raw bytes.Buffer
	if err := json.NewEncoder(&raw).Encode(r); err != nil || !strings.Contains(raw.String(), `"inspect_action"`) {
		t.Fatalf("record does not serialize the diagnostic column: %v %s", err, raw.String())
	}
}

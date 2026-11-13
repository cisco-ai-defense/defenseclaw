// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build s7bench

package main

// Decision-model answer cache for benchmarks (rel-1-0-10 S7 S1). Bench only:
// the product never caches decision-model answers. With -dm-cache-dir the
// harness starts a loopback relay in front of the real -dm-url and points
// decision_model.base_url at it. Every answer is stored under the sha256 of
// the exact request body the product sent (model + input/state + questions),
// so a later run replays it offline (-dm-cache-only) byte for byte. A miss
// goes upstream with the key from DEFENSECLAW_DECISION_MODEL_KEY; 429, 5xx
// and transport errors are retried with backoff so a benchmark records real
// answers, not rate-limit failures. Only the answer is stored, never the
// request, so the cache holds no corpus content.

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"math/rand/v2"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/config"
)

type dmCacheEntry struct {
	V      int             `json:"v"`
	Status int             `json:"status"`
	Body   json.RawMessage `json:"body"`
	Ms     int64           `json:"upstream_ms"`
	T      string          `json:"t"`
}

type dmCache struct {
	upstream, protocol, key, dir string
	only                         bool
	sem                          chan struct{}
	client                       *http.Client
	logMu                        sync.Mutex
	log                          *os.File
	flight                       sync.Map // sha -> *dmFlight
	bg                           chan struct{}
	background                   atomic.Int64
	// tpm paces upstream calls to this many input tokens per minute (0:
	// none); the key's quota is shared with other lanes.
	tpm, rpm int
	// budgetFile counts upstream requests across every harness process of
	// a run (one byte appended per request); at budget no request is sent.
	budgetFile string
	budget     int64
	paceMu     sync.Mutex
	paceNext time.Time

	hits, misses, upstreamCalls, rateLimited, failed, offlineMisses, stored atomic.Int64
}

type dmFlight struct {
	done  chan struct{}
	entry *dmCacheEntry
}

// startDMCache starts the relay and returns its loopback URL.
func startDMCache(upstream, protocol, dir string, only bool, inflight, tpm, rpm int, budgetFile string, budget int64, logPath string) (string, *dmCache, error) {
	if inflight < 1 {
		inflight = 8
	}
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return "", nil, err
	}
	c := &dmCache{upstream: upstream, protocol: protocol, key: os.Getenv("DEFENSECLAW_DECISION_MODEL_KEY"), dir: dir, only: only,
		sem: make(chan struct{}, inflight), bg: make(chan struct{}, 4), tpm: tpm, rpm: rpm, budgetFile: budgetFile, budget: budget,
		client: &http.Client{Timeout: 120 * time.Second,
			CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }},
	}
	if logPath != "" {
		_ = os.MkdirAll(filepath.Dir(logPath), 0o755)
		f, err := os.OpenFile(logPath, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o644)
		if err != nil {
			return "", nil, err
		}
		c.log = f
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return "", nil, err
	}
	go func() { _ = http.Serve(ln, c) }()
	return "http://" + ln.Addr().String() + "/v1beta/decisions", c, nil
}

func (c *dmCache) path(sha string) string { return filepath.Join(c.dir, sha[:2], sha+".json") }

func (c *dmCache) load(sha string) *dmCacheEntry {
	raw, err := os.ReadFile(c.path(sha))
	if err != nil {
		return nil
	}
	var e dmCacheEntry
	if json.Unmarshal(raw, &e) != nil || e.Status == 0 {
		return nil
	}
	return &e
}

func (c *dmCache) store(sha string, e *dmCacheEntry) {
	p := c.path(sha)
	_ = os.MkdirAll(filepath.Dir(p), 0o755)
	raw, _ := json.Marshal(e)
	tmp := fmt.Sprintf("%s.%d.%d.tmp", p, os.Getpid(), rand.Int64())
	if os.WriteFile(tmp, raw, 0o644) == nil && os.Rename(tmp, p) == nil {
		c.stored.Add(1)
		return
	}
	_ = os.Remove(tmp)
}

func (c *dmCache) logLine(v map[string]any) {
	if c.log == nil {
		return
	}
	v["t"] = time.Now().UTC().Format(time.RFC3339Nano)
	raw, _ := json.Marshal(v)
	c.logMu.Lock()
	_, _ = c.log.Write(append(raw, '\n'))
	c.logMu.Unlock()
}

func (c *dmCache) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	body, err := io.ReadAll(io.LimitReader(r.Body, 8<<20))
	if err != nil {
		http.Error(w, "read", http.StatusBadRequest)
		return
	}
	sum := sha256.Sum256(body)
	sha := hex.EncodeToString(sum[:])
	e := c.load(sha)
	if e != nil {
		c.hits.Add(1)
	} else if c.only {
		c.offlineMisses.Add(1)
		c.logLine(map[string]any{"sha": sha, "offline_miss": true})
		http.Error(w, "cache miss (offline replay)", http.StatusServiceUnavailable)
		return
	} else {
		e = c.fetchOnce(sha, body)
	}
	if e == nil {
		http.Error(w, "upstream failed", http.StatusBadGateway)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(e.Status)
	_, _ = w.Write(e.Body)
}

// fetchOnce collapses concurrent misses of one key in this process.
func (c *dmCache) fetchOnce(sha string, body []byte) *dmCacheEntry {
	f := &dmFlight{done: make(chan struct{})}
	if prev, loaded := c.flight.LoadOrStore(sha, f); loaded {
		pf := prev.(*dmFlight)
		<-pf.done
		c.hits.Add(1)
		return pf.entry
	}
	defer func() { close(f.done); c.flight.Delete(sha) }()
	c.misses.Add(1)
	f.entry = c.fetch(sha, body, dmInWindow)
	if f.entry == nil && !c.only {
		// The product has given up on this call (its hook window is a few
		// seconds); keep trying in the background so the answer is cached
		// for the next pass.
		select {
		case c.bg <- struct{}{}:
			c.background.Add(1)
			go func() {
				defer func() { <-c.bg }()
				_ = c.fetch(sha, body, dmBackground)
			}()
		default:
		}
	}
	return f.entry
}

// dmInWindow is how long a request may retry while the product waits (its
// hook answer window is 2 to 3.4 s); dmBackground is the retry time of a
// background completion.
const (
	dmInWindow   = 1200 * time.Millisecond
	dmBackground = 90 * time.Second
)


// takeBudget records one upstream request in the shared budget file and
// reports whether it is still within the budget.
func (c *dmCache) takeBudget() bool {
	if c.budgetFile == "" || c.budget <= 0 {
		return true
	}
	f, err := os.OpenFile(c.budgetFile, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o644)
	if err != nil {
		return false
	}
	defer f.Close()
	if _, err := f.Write([]byte{'.'}); err != nil {
		return false
	}
	st, err := f.Stat()
	return err == nil && st.Size() <= c.budget
}

// waitPace spaces calls so the estimated input tokens (request bytes / 4,
// questions included) stay under tpm per minute.
func (c *dmCache) waitPace(bodyBytes int) {
	if c.tpm <= 0 && c.rpm <= 0 {
		return
	}
	var cost time.Duration
	if c.tpm > 0 {
		cost = time.Duration(float64(time.Minute) * float64(max(bodyBytes/4, 1)) / float64(c.tpm))
	}
	if c.rpm > 0 {
		cost = max(cost, time.Minute/time.Duration(c.rpm))
	}
	c.paceMu.Lock()
	now := time.Now()
	if c.paceNext.Before(now) {
		c.paceNext = now
	}
	wait := time.Until(c.paceNext)
	c.paceNext = c.paceNext.Add(cost)
	c.paceMu.Unlock()
	if wait > 0 {
		time.Sleep(wait)
	}
}


func (c *dmCache) fetch(sha string, body []byte, window time.Duration) *dmCacheEntry {
	if window <= dmInWindow {
		c.sem <- struct{}{}
		defer func() { <-c.sem }()
	}
	start := time.Now()
	n429, attempts := 0, 0
	var lastStatus int
	var lastErr string
	for attempts < 12 && (attempts == 0 || time.Since(start) < window) {
		attempts++
		c.waitPace(len(body))
		if !c.takeBudget() {
			c.failed.Add(1)
			c.logLine(map[string]any{"sha": sha, "budget_exhausted": true})
			return nil
		}
		req, _ := http.NewRequest(http.MethodPost, c.upstream, bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		if c.key != "" {
			if c.protocol == config.DecisionModelProtocolGeminiDecisions {
				req.Header.Set("x-goog-api-key", c.key)
			} else {
				req.Header.Set("Authorization", "Bearer "+c.key)
			}
		}
		t0 := time.Now()
		c.upstreamCalls.Add(1)
		resp, err := c.client.Do(req)
		ms := time.Since(t0).Milliseconds()
		backoff := time.Duration(150*(1<<min(attempts-1, 7)))*time.Millisecond + time.Duration(rand.IntN(100))*time.Millisecond
		if window > dmInWindow {
			backoff = time.Duration(1000*(1<<min(attempts-1, 4)))*time.Millisecond + time.Duration(rand.IntN(500))*time.Millisecond
		}
		if err != nil {
			lastErr = "transport"
			time.Sleep(min(backoff, 30*time.Second))
			continue
		}
		raw, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
		resp.Body.Close()
		lastStatus = resp.StatusCode
		if resp.StatusCode == http.StatusTooManyRequests || resp.StatusCode >= 500 {
			if resp.StatusCode == http.StatusTooManyRequests {
				n429++
				c.rateLimited.Add(1)
				if s, err := strconv.Atoi(resp.Header.Get("Retry-After")); err == nil && s > 0 && window > dmInWindow {
					backoff = time.Duration(s) * time.Second
				}
			}
			time.Sleep(min(backoff, 30*time.Second))
			continue
		}
		e := &dmCacheEntry{V: 1, Status: resp.StatusCode, Body: raw, Ms: ms, T: time.Now().UTC().Format(time.RFC3339)}
		code, tokens := dmAnswerFacts(raw)
		c.logLine(map[string]any{"sha": sha, "status": resp.StatusCode, "attempts": attempts, "n429": n429, "upstream_ms": ms,
			"total_ms": time.Since(start).Milliseconds(), "input_tokens": tokens, "error_code": code})
		if json.Valid(raw) && (resp.StatusCode == http.StatusOK || resp.StatusCode == http.StatusBadRequest) {
			c.store(sha, e)
		} else {
			e.Body = json.RawMessage(`{}`)
		}
		return e
	}
	c.failed.Add(1)
	c.logLine(map[string]any{"sha": sha, "status": lastStatus, "attempts": attempts, "n429": n429, "gave_up": true, "err": lastErr,
		"total_ms": time.Since(start).Milliseconds()})
	return nil
}

// dmAnswerFacts reads the error code and the input token count of an answer.
func dmAnswerFacts(raw []byte) (string, int) {
	var v struct {
		Error struct {
			Code json.RawMessage `json:"code"`
		} `json:"error"`
		Usage struct {
			Input int `json:"total_input_tokens"`
		} `json:"usage"`
	}
	_ = json.Unmarshal(raw, &v)
	code := ""
	if len(v.Error.Code) > 0 {
		var s string
		if json.Unmarshal(v.Error.Code, &s) != nil {
			s = string(v.Error.Code)
		}
		code = s
	}
	return code, v.Usage.Input
}

func (c *dmCache) summary() string {
	// Give background completions a moment to land before the process exits.
	for i := 0; i < 600 && len(c.bg) > 0; i++ {
		time.Sleep(100 * time.Millisecond)
	}
	return fmt.Sprintf("dm-cache hits=%d misses=%d upstream_calls=%d rate_limited=%d gave_up=%d offline_misses=%d stored=%d background=%d",
		c.hits.Load(), c.misses.Load(), c.upstreamCalls.Load(), c.rateLimited.Load(), c.failed.Load(), c.offlineMisses.Load(), c.stored.Load(), c.background.Load())
}

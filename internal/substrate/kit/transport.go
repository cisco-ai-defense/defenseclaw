// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package kit

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"
)

// maxAnswerBytes caps a gateway answer.
const maxAnswerBytes = 2 << 20

// Request is one post to the actor listener.
type Request struct {
	// Path is the listener path (HookPathPrefix + connector, ...).
	Path string `json:"path"`
	// Header holds the request's DefenseClaw headers; the transport adds
	// the placeholder, client, content type and idempotency headers itself
	// and ignores any caller value for them.
	Header map[string]string `json:"header,omitempty"`
	Body   []byte            `json:"body,omitempty"`
}

// Response is the gateway's answer.
type Response struct {
	Status   int    `json:"status"`
	Body     []byte `json:"body,omitempty"`
	Attempts int    `json:"attempts"`
}

// ErrUnreachable wraps a failure to get any HTTP answer.
var ErrUnreachable = errors.New("defenseclaw gateway unreachable")

// Transport posts to the actor listener over kept-alive connections.
type Transport struct {
	cfg    Config
	base   *url.URL
	client *http.Client
	// newKey returns an idempotency key; tests replace it.
	newKey func() string
}

// NewTransport builds the transport. It makes no connection.
func NewTransport(cfg Config) (*Transport, error) {
	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	base, _ := url.Parse(strings.TrimRight(cfg.GatewayURL, "/"))
	roots, err := trustPool(cfg.CAFiles)
	if err != nil {
		return nil, err
	}
	dialer := &net.Dialer{Timeout: cfg.connectTimeout(), KeepAlive: 30 * time.Second}
	tr := &http.Transport{
		// Hook traffic never follows the workload's proxy variables: the
		// agent controls them. Substrate egress is transparent.
		Proxy:               nil,
		DialContext:         dialer.DialContext,
		TLSClientConfig:     &tls.Config{RootCAs: roots, MinVersion: tls.VersionTLS12},
		TLSHandshakeTimeout: cfg.connectTimeout() + time.Second,
		ForceAttemptHTTP2:   true,
		MaxIdleConns:        4,
		MaxIdleConnsPerHost: 4,
		IdleConnTimeout:     15 * time.Minute,
	}
	return &Transport{cfg: cfg, base: base, client: &http.Client{Transport: tr}, newKey: randomKey}, nil
}

func trustPool(files []string) (*x509.CertPool, error) {
	pool, err := x509.SystemCertPool()
	if err != nil || pool == nil {
		pool = x509.NewCertPool()
	}
	for _, f := range files {
		pem, err := os.ReadFile(f)
		if err != nil {
			// A projected bundle is mounted at actor start; a missing one
			// leaves the system roots, and an https gateway behind the
			// egress MITM then fails its handshake, closed.
			continue
		}
		pool.AppendCertsFromPEM(pem)
	}
	return pool, nil
}

func randomKey() string {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return ""
	}
	return hex.EncodeToString(b[:])
}

// reserved are the headers only the transport sets.
var reserved = map[string]bool{
	strings.ToLower(PlaceholderHeader): true, "authorization": true, "content-type": true,
	"x-defenseclaw-client": true, "idempotency-key": true, "x-defenseclaw-hook-idempotency-key": true,
	"host": true, "content-length": true, "x-defenseclaw-kit-version": true,
}

func (t *Transport) newRequest(ctx context.Context, method string, r Request, key string) (*http.Request, error) {
	if !strings.HasPrefix(r.Path, "/") || strings.Contains(r.Path, "..") || strings.ContainsAny(r.Path, "?#") {
		return nil, fmt.Errorf("actor kit: invalid gateway path %q", r.Path)
	}
	u := *t.base
	u.Path = strings.TrimRight(t.base.Path, "/") + r.Path
	var body io.Reader
	if r.Body != nil {
		body = bytes.NewReader(r.Body)
	}
	req, err := http.NewRequestWithContext(ctx, method, u.String(), body)
	if err != nil {
		return nil, err
	}
	for k, v := range r.Header {
		if reserved[strings.ToLower(k)] || strings.ContainsAny(v, "\r\n") {
			continue
		}
		req.Header.Set(k, v)
	}
	req.Header.Set(PlaceholderHeader, PlaceholderValue)
	req.Header.Set("X-DefenseClaw-Client", "actor-hook/"+t.cfg.KitVersion)
	req.Header.Set("X-DefenseClaw-Kit-Version", t.cfg.KitVersion)
	if r.Body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if key != "" {
		// Idempotency-Key also lets net/http replay the request on a fresh
		// connection when a kept-alive one turns out dead after a resume.
		req.Header.Set("X-DefenseClaw-Hook-Idempotency-Key", key)
		req.Header.Set("Idempotency-Key", key)
	}
	return req, nil
}

// Post sends r and retries once, with the same idempotency key, on a
// transport failure or a 502, 503 or 504. It returns ErrUnreachable (wrapped)
// when no attempt got an answer; a 5xx answer after the retry is returned as
// a Response.
func (t *Transport) Post(ctx context.Context, r Request) (Response, error) {
	key := t.newKey()
	budgets := []time.Duration{t.cfg.maxTime(), t.cfg.retryMaxTime()}
	if key == "" {
		// Without a key a retry could evaluate one event twice.
		budgets = budgets[:1]
	}
	var lastErr error
	var last Response
	for i, budget := range budgets {
		resp, err := t.once(ctx, r, key, budget)
		resp.Attempts = i + 1
		if err == nil && resp.Status != 502 && resp.Status != 503 && resp.Status != 504 {
			return resp, nil
		}
		if err == nil {
			last, lastErr = resp, nil
		} else {
			lastErr = err
		}
		if ctx.Err() != nil {
			break
		}
	}
	if lastErr != nil {
		return Response{Attempts: len(budgets)}, fmt.Errorf("%w: %v", ErrUnreachable, lastErr)
	}
	return last, nil
}

func (t *Transport) once(ctx context.Context, r Request, key string, budget time.Duration) (Response, error) {
	ctx, cancel := context.WithTimeout(ctx, budget)
	defer cancel()
	req, err := t.newRequest(ctx, http.MethodPost, r, key)
	if err != nil {
		return Response{}, err
	}
	resp, err := t.client.Do(req)
	if err != nil {
		return Response{}, err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxAnswerBytes+1))
	if err != nil {
		return Response{}, err
	}
	if len(body) > maxAnswerBytes {
		return Response{Status: resp.StatusCode}, errors.New("gateway answer too large")
	}
	return Response{Status: resp.StatusCode, Body: body}, nil
}

// Warm opens (or re-opens) a connection to the actor listener so the next
// hook does not pay for TCP and TLS through egress. Any HTTP answer counts.
func (t *Transport) Warm(ctx context.Context, connector string) error {
	ctx, cancel := context.WithTimeout(ctx, t.cfg.maxTime())
	defer cancel()
	req, err := t.newRequest(ctx, http.MethodGet, Request{Path: HookPathPrefix + connector}, "")
	if err != nil {
		return err
	}
	req.Header.Set(WarmHeader, "1")
	resp, err := t.client.Do(req)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrUnreachable, err)
	}
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 64<<10))
	resp.Body.Close()
	return nil
}

// Client is the transport's HTTP client (same trust, no proxy), for other
// kit callers of the actor listener such as the relay's token check.
func (t *Transport) Client() *http.Client { return t.client }

// Reset drops kept-alive connections (after a resume they lead nowhere).
func (t *Transport) Reset() { t.client.CloseIdleConnections() }

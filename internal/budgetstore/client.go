// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package budgetstore

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/routingadmin"
)

// Client is the device side of the store: a routingadmin.SpendCounter over
// HTTPS. It sends charge keys, days and amounts only.
type Client struct {
	base *url.URL
	keys Keys
	http *http.Client
	mu   sync.Mutex
	seq  uint64
}

var _ routingadmin.SpendCounter = (*Client)(nil)

// NewClient returns the client of rawURL (https only). caPEM, when set, is
// the only trusted CA (a private store certificate); otherwise the system
// roots. Proxies from the environment are never used and redirects are
// refused, so requests reach only the configured host.
func NewClient(rawURL string, keys Keys, caPEM []byte, timeout time.Duration) (*Client, error) {
	u, err := url.Parse(strings.TrimSpace(rawURL))
	if err != nil || u.Scheme != "https" || u.Host == "" || u.User != nil || (u.Path != "" && u.Path != "/") || u.RawQuery != "" {
		return nil, errors.New("budget store url must be https://host[:port] with no path, query or credentials")
	}
	tlsConfig := &tls.Config{MinVersion: tls.VersionTLS12}
	if len(caPEM) > 0 {
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(caPEM) {
			return nil, errors.New("budget store ca_file holds no PEM certificate")
		}
		tlsConfig.RootCAs = pool
	}
	if timeout <= 0 {
		timeout = 2 * time.Second
	}
	transport := &http.Transport{Proxy: nil, TLSClientConfig: tlsConfig, ForceAttemptHTTP2: true,
		MaxIdleConns: 2, IdleConnTimeout: time.Minute, TLSHandshakeTimeout: timeout}
	return &Client{
		base: &url.URL{Scheme: "https", Host: u.Host},
		keys: keys,
		http: &http.Client{Transport: transport, Timeout: timeout,
			CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }},
		seq: randomSeqStart(),
	}, nil
}

// Push sends this epoch's absolute totals.
func (c *Client) Push(ctx context.Context, epoch string, rows []routingadmin.SeedRow) error {
	c.mu.Lock()
	c.seq++
	seq := c.seq
	c.mu.Unlock()
	req := PushRequest{Epoch: epoch, Seq: seq, Rows: make([]Row, 0, len(rows))}
	for _, r := range rows {
		if ValidKey(r.Key) {
			req.Rows = append(req.Rows, Row{Day: r.Day, Key: r.Key, USD: r.USD})
		}
	}
	return c.do(ctx, PathPush, req, nil)
}

// Totals reads every other epoch's spend for keys since the given day.
func (c *Client) Totals(ctx context.Context, epoch string, since time.Time, keys []string) ([]routingadmin.SeedRow, error) {
	req := TotalsRequest{Epoch: epoch, Since: since.UTC().Format(time.DateOnly)}
	for _, k := range keys {
		if ValidKey(k) {
			req.Keys = append(req.Keys, k)
		}
	}
	if len(req.Keys) == 0 {
		return nil, nil
	}
	var resp TotalsResponse
	if err := c.do(ctx, PathTotals, req, &resp); err != nil {
		return nil, err
	}
	out := make([]routingadmin.SeedRow, 0, len(resp.Rows))
	for _, r := range resp.Rows {
		if ValidKey(r.Key) && validDay(r.Day) && validUSD(r.USD) {
			out = append(out, routingadmin.SeedRow{Day: r.Day, Key: r.Key, USD: r.USD})
		}
	}
	return out, nil
}

func (c *Client) do(ctx context.Context, path string, in, out any) error {
	body, err := json.Marshal(in)
	if err != nil {
		return err
	}
	if len(body) > MaxBodyBytes {
		return errors.New("budget store request too large")
	}
	u := *c.base
	u.Path = path
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, u.String(), bytes.NewReader(body))
	if err != nil {
		return err
	}
	now := time.Now()
	sig := c.keys.Sign(http.MethodPost, path, now, body)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set(HeaderTime, fmt.Sprint(now.Unix()))
	req.Header.Set(HeaderSignature, sig)
	resp, err := c.http.Do(req)
	if err != nil {
		return errors.New("budget store unreachable")
	}
	defer resp.Body.Close()
	data, _ := io.ReadAll(io.LimitReader(resp.Body, MaxBodyBytes))
	if resp.StatusCode != http.StatusUnauthorized && !c.keys.VerifyResponse(sig, resp.StatusCode, data, resp.Header.Get(HeaderResponse)) {
		// Not the store's answer (a TLS-inspecting middlebox or a forged
		// response): use none of it.
		return errors.New("budget store answer is not signed by the store")
	}
	if resp.StatusCode != http.StatusOK {
		var e ErrorResponse
		_ = json.Unmarshal(data, &e)
		code := e.Error
		if code == "" {
			code = http.StatusText(resp.StatusCode)
		}
		return fmt.Errorf("budget store refused the request: %s", code)
	}
	if out != nil {
		if err := json.Unmarshal(data, out); err != nil {
			return errors.New("budget store answered without JSON")
		}
	}
	return nil
}

// randomSeqStart starts the push sequence at a random point in the lower
// half of the range, so a clock step cannot make it repeat.
func randomSeqStart() uint64 {
	var b [8]byte
	_, _ = rand.Read(b[:])
	return binary.BigEndian.Uint64(b[:]) >> 2
}

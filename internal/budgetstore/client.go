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
	"sync/atomic"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/routingadmin"
)

// Client is the device side of the store: a routingadmin.SpendCounter over
// HTTPS with the device's own credential.
type Client struct {
	base *url.URL
	key  DeviceKey
	http *http.Client
}

var _ routingadmin.SpendCounter = (*Client)(nil)

// pushSeq is the push sequence of this process: one counter for every client
// built, so a rebuilt client (a reload) never goes below the store's last
// sequence of this process's writer.
var pushSeq atomic.Uint64

func init() {
	var b [8]byte
	_, _ = rand.Read(b[:])
	pushSeq.Store(binary.BigEndian.Uint64(b[:]) >> 2)
}

// NewClient returns the client of rawURL (https only) for one device. caPEM,
// when set, is the only trusted CA; otherwise the system roots. Proxies from
// the environment are never used and redirects are refused.
func NewClient(rawURL string, key DeviceKey, caPEM []byte, timeout time.Duration) (*Client, error) {
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
		key:  key,
		http: &http.Client{Transport: transport, Timeout: timeout,
			CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }},
	}, nil
}

// WriterID is the device id: a new credential is a new writer at the store
// (routingadmin starts a new epoch when it changes).
func (c *Client) WriterID() string { return c.key.ID() }

// Push sends this writer's absolute totals.
func (c *Client) Push(ctx context.Context, epoch string, rows []routingadmin.SeedRow) error {
	req := PushRequest{Epoch: epoch, Seq: pushSeq.Add(1), Rows: make([]Row, 0, len(rows))}
	for _, r := range rows {
		if ValidKey(r.Key) {
			req.Rows = append(req.Rows, Row{Day: r.Day, Key: r.Key, USD: r.USD})
		}
	}
	if len(req.Rows) == 0 {
		return nil
	}
	return c.do(ctx, PathPush, req, nil)
}

// Totals reads the fleet spend of keys since the given day: numbers for the
// device's own users, and an over-the-limit row (ExceededUSD today) for each
// pooled key the store says is exceeded.
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
	asked := map[string]bool{}
	for _, k := range req.Keys {
		asked[k] = true
	}
	out := make([]routingadmin.SeedRow, 0, len(resp.Rows)+len(resp.Exceeded))
	for _, r := range resp.Rows {
		if asked[r.Key] && !pooled(r.Key) && validDay(r.Day) && validUSD(r.USD) {
			out = append(out, routingadmin.SeedRow{Day: r.Day, Key: r.Key, USD: r.USD})
		}
	}
	today := time.Now().UTC().Format(time.DateOnly)
	for _, k := range resp.Exceeded {
		if asked[k] && pooled(k) {
			out = append(out, routingadmin.SeedRow{Day: today, Key: k, USD: ExceededUSD})
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
	sig := c.key.Sign(http.MethodPost, path, now, body)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set(HeaderDevice, c.key.ID())
	req.Header.Set(HeaderTime, fmt.Sprint(now.Unix()))
	req.Header.Set(HeaderSignature, sig)
	resp, err := c.http.Do(req)
	if err != nil {
		return errors.New("budget store unreachable")
	}
	defer resp.Body.Close()
	data, _ := io.ReadAll(io.LimitReader(resp.Body, MaxResponseBytes))
	if resp.StatusCode == http.StatusOK && !c.key.VerifyResponse(sig, resp.StatusCode, data, resp.Header.Get(HeaderResponse)) {
		return errors.New("budget store answer is not signed by the store (a proxy between the device and the store?)")
	}
	if resp.StatusCode == http.StatusUnauthorized {
		return errors.New("budget store refused this device: unknown or revoked device credential, or the clocks differ by more than 5 minutes")
	}
	if resp.StatusCode != http.StatusOK {
		var e ErrorResponse
		_ = json.Unmarshal(data, &e)
		if e.Error == "unknown_budget" && len(e.Budgets) > 0 {
			return fmt.Errorf("budget store does not know budget %s: copy the bundle's routing.admin.budgets into the store's config.yaml and restart it", strings.Join(e.Budgets, ", "))
		}
		if e.Error == "key_not_allowed" {
			return errors.New("budget store refused a key this device's credential does not name (a budget or user added since the credential was issued: issue the device again)")
		}
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

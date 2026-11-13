// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
// SPDX-License-Identifier: Apache-2.0

// Package api is the launcher's client of the DefenseClaw admin listener on
// Agent Substrate (/api/v1/substrate/...). Every call carries the person's
// OIDC token; the gateway answers each person only with their own data.
package api

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/cli/substratecli/safetext"
)

const (
	prefix       = "/api/v1/substrate/"
	maxResponse  = 8 << 20
	defaultTimes = 30 * time.Second
	// clientTag is the X-DefenseClaw-Client value of the launcher.
	clientTag = "substrate-launcher"
)

// SetClientHeaders marks a request as coming from the launcher: the client
// tag the admin listener requires on every write (its CSRF gate, GAP-0102).
// It goes on every request, so a GET that becomes a write needs no change.
// The API client and the attach tunnel both call it. The JSON content type
// is set by the API client only: the attach route takes the relay types.
func SetClientHeaders(h http.Header) { h.Set("X-DefenseClaw-Client", clientTag) }

// TokenFunc returns the bearer for one request.
type TokenFunc func(ctx context.Context) (string, error)

// Options builds a Client.
type Options struct {
	// Base is the admin listener origin, for example https://admin.example.test:9443.
	Base string
	// CAFile adds a trusted CA (PEM) to the system roots.
	CAFile string
	Token  TokenFunc
	// HTTP replaces the transport (tests).
	HTTP *http.Client
	// Timeout bounds one request (default 30 s).
	Timeout time.Duration
	// UserAgent is sent on every request.
	UserAgent string
}

// Client talks to the admin listener.
type Client struct {
	base  *url.URL
	hc    *http.Client
	token TokenFunc
	ua    string
}

// New validates the options and returns a Client.
func New(o Options) (*Client, error) {
	u, err := url.Parse(strings.TrimRight(strings.TrimSpace(o.Base), "/"))
	if err != nil || u.Host == "" || (u.Scheme != "https" && u.Scheme != "http") {
		return nil, errors.New("the admin URL is not valid; it looks like https://HOST:PORT")
	}
	if u.User != nil {
		return nil, errors.New("the admin URL must not carry a user name or password")
	}
	if u.Scheme == "http" && !isLoopback(u.Hostname()) {
		return nil, errors.New("the admin URL must use https (plain http is only allowed for localhost)")
	}
	if o.Token == nil {
		return nil, errors.New("no token source is set")
	}
	hc := o.HTTP
	if hc == nil {
		tr := http.DefaultTransport.(*http.Transport).Clone()
		tr.TLSClientConfig = &tls.Config{MinVersion: tls.VersionTLS12}
		if o.CAFile != "" {
			pool, err := x509.SystemCertPool()
			if err != nil || pool == nil {
				pool = x509.NewCertPool()
			}
			pem, err := os.ReadFile(o.CAFile)
			if err != nil {
				return nil, fmt.Errorf("cannot read the CA file: %w", err)
			}
			if !pool.AppendCertsFromPEM(pem) {
				return nil, errors.New("the CA file holds no certificate")
			}
			tr.TLSClientConfig.RootCAs = pool
		}
		to := o.Timeout
		if to <= 0 {
			to = defaultTimes
		}
		hc = &http.Client{Transport: tr, Timeout: to}
	}
	// A redirect would carry the bearer to another host; the admin
	// listener never redirects.
	hc.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	ua := o.UserAgent
	if ua == "" {
		ua = "defenseclaw-substrate-launcher"
	}
	return &Client{base: u, hc: hc, token: o.Token, ua: ua}, nil
}

func isLoopback(h string) bool {
	return h == "localhost" || h == "127.0.0.1" || h == "::1"
}

// Error is a refusal from the admin listener.
type Error struct {
	Status int
	// Reason is the gateway's closed reason (for example profile_not_allowed).
	Reason string
	Path   string
	// Refusal, Detail, Actor and ActorUID come with an actor_refused answer:
	// the controller's refusal code and reason, and the refused actor.
	Refusal  string
	Detail   string
	Actor    string
	ActorUID string
}

func (e *Error) Error() string {
	if r := safetext.Line(e.Reason); r != "" {
		return fmt.Sprintf("the cluster answered %d (%s)", e.Status, r)
	}
	return fmt.Sprintf("the cluster answered %d", e.Status)
}

// NotImplemented reports a 501: the cluster does not serve this call yet.
func (e *Error) NotImplemented() bool { return e.Status == http.StatusNotImplemented }

// Unauthorized reports a 401: the token was not accepted.
func (e *Error) Unauthorized() bool { return e.Status == http.StatusUnauthorized }

// AsError returns the *Error inside err.
func AsError(err error) (*Error, bool) {
	var e *Error
	if errors.As(err, &e) {
		return e, true
	}
	return nil, false
}

func (c *Client) do(ctx context.Context, method, path string, q url.Values, in, out any) error {
	var body io.Reader
	if in != nil {
		b, err := json.Marshal(in)
		if err != nil {
			return err
		}
		body = bytes.NewReader(b)
	}
	u := *c.base
	u.Path = prefix + strings.TrimLeft(path, "/")
	u.RawQuery = q.Encode()
	tok := ""
	if ctx.Value(noTokenKey{}) == nil {
		var err error
		if tok, err = c.token(ctx); err != nil {
			return err
		}
	}
	req, err := http.NewRequestWithContext(ctx, method, u.String(), body)
	if err != nil {
		return err
	}
	if tok != "" {
		req.Header.Set("Authorization", "Bearer "+tok)
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", c.ua)
	// The admin listener refuses a write that does not carry the client tag
	// and a JSON content type, even a DELETE with no body (its CSRF gate).
	SetClientHeaders(req.Header)
	if method != http.MethodGet && method != http.MethodHead {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := c.hc.Do(req)
	if err != nil {
		return friendlyTransport(c.base.Host, redactErr(err, tok))
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, maxResponse+1))
	if err != nil {
		return redactErr(err, tok)
	}
	if len(raw) > maxResponse {
		return errors.New("the cluster answer is too large")
	}
	if resp.StatusCode >= 300 {
		e := &Error{Status: resp.StatusCode, Path: path}
		var d struct {
			Reason   string `json:"reason"`
			Refusal  string `json:"refusal"`
			Detail   string `json:"detail"`
			Actor    string `json:"actor"`
			ActorUID string `json:"actor_uid"`
		}
		if json.Unmarshal(raw, &d) == nil {
			e.Reason = d.Reason
			e.Refusal, e.Detail, e.Actor, e.ActorUID = d.Refusal, d.Detail, d.Actor, d.ActorUID
		}
		return e
	}
	if out == nil || len(bytes.TrimSpace(raw)) == 0 {
		return nil
	}
	if err := json.Unmarshal(raw, out); err != nil {
		return fmt.Errorf("the cluster answer is not what this version expects: %w", err)
	}
	return nil
}

// noTokenKey marks a call that is made before anyone is signed in.
type noTokenKey struct{}

// Info is the answer of GET /info: how the cluster signs people in. The
// route takes no sign-in.
type Info struct {
	// SignIn is oidc, kubernetes or none.
	SignIn   string `json:"sign_in"`
	Issuer   string `json:"issuer,omitempty"`
	ClientID string `json:"client_id,omitempty"`
	// Attach reports that the cluster can attach launchers to agents.
	Attach bool `json:"attach"`
}

// Info asks the cluster how people sign in to it. It sends no token.
func (c *Client) Info(ctx context.Context) (Info, error) {
	var in Info
	err := c.do(context.WithValue(ctx, noTokenKey{}, true), http.MethodGet, "info", nil, nil, &in)
	in.SignIn = strings.ToLower(strings.TrimSpace(in.SignIn))
	in.Issuer, in.ClientID = strings.TrimSpace(in.Issuer), strings.TrimSpace(in.ClientID)
	return in, err
}

// redactErr keeps a token out of a transport error text.
func redactErr(err error, tok string) error {
	if tok != "" && strings.Contains(err.Error(), tok) {
		return errors.New(strings.ReplaceAll(err.Error(), tok, "[token]"))
	}
	return err
}

// StatusCode lets the attach package tell a refusal from a failure.
func (e *Error) StatusCode() int { return e.Status }

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
	"github.com/defenseclaw/defenseclaw/internal/config"
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
	// Message is the gateway's explanation, sent with a sign-in refusal
	// (subscription_signin_refused, agent_hook_tamper_refused), one line.
	Message string
	// Retryable marks a refusal whose cause may pass (a template
	// attestation that could not be checked now, GAP-0181).
	Retryable bool
	// RelayCertCleared comes with recover's not_crashed answer: the
	// gateway cleared the agent's relay certificate record (GAP-0930).
	RelayCertCleared bool
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

// longCallKey carries a longer request bound for one call (withLongCall).
type longCallKey struct{}

// withLongCall gives the request made with ctx up to d instead of the
// client's timeout.
func withLongCall(ctx context.Context, d time.Duration) context.Context {
	return context.WithValue(ctx, longCallKey{}, d)
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
	hc := c.hc
	if d, ok := ctx.Value(longCallKey{}).(time.Duration); ok && hc.Timeout > 0 && d > hc.Timeout {
		// A call that waits on the cluster (a durable snapshot) gets
		// its own bound instead of the client's (GAP-0410).
		long := *hc
		long.Timeout = d
		hc = &long
	}
	resp, err := hc.Do(req)
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
			Message  string `json:"message"`
			Retry    bool   `json:"retryable"`
			Cleared  bool   `json:"relay_cert_record_cleared"`
		}
		if json.Unmarshal(raw, &d) == nil {
			e.Reason = d.Reason
			e.Refusal, e.Detail, e.Actor, e.ActorUID, e.Retryable = d.Refusal, d.Detail, d.Actor, d.ActorUID, d.Retry
			e.Message = safetext.Line(d.Message)
			e.RelayCertCleared = d.Cleared
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
	// ActorTokens is set while the gateway refuses every agent's token
	// (the key set cannot be read, a wrong issuer): no hook or model call
	// of any agent runs (GAP-0194).
	ActorTokens *ActorTokens `json:"actor_tokens,omitempty"`
	// EgressCallout is who holds Substrate's egress callout slot (nil from
	// a gateway that does not report it, GAP-0497).
	EgressCallout *EgressCallout `json:"egress_callout,omitempty"`
}

// EgressCallout is the /info egress_callout member.
type EgressCallout struct {
	// State is defenseclaw, other, none or unknown.
	State string `json:"state"`
	// FailMode is closed, open or off.
	FailMode  string   `json:"fail_mode"`
	ChecksOff []string `json:"checks_off,omitempty"`
	Since     string   `json:"since,omitempty"`
}

// Replaced reports that the DefenseClaw callout does not hold the slot:
// another callout does, or none is registered.
func (e *EgressCallout) Replaced() bool {
	return e != nil && (e.State == "other" || e.State == "none")
}

// ActorTokens is the /info actor_tokens member.
type ActorTokens struct {
	State  string `json:"state"`
	Reason string `json:"reason"`
	Since  string `json:"since"`
}

// Refusing reports a cluster-wide refusal seen at or after t.
func (a *ActorTokens) Refusing(t time.Time) bool {
	if a == nil || a.State != "refusing" {
		return false
	}
	since, err := time.Parse(time.RFC3339, a.Since)
	return err != nil || !since.Before(t.Truncate(time.Second))
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

// LauncherSettings holds the cluster's limits and defaults for the launcher.
type LauncherSettings struct {
	WorkspaceMaxBytes int64 `json:"workspace_max_bytes"`
	// KeyReplay is substrate.launcher.key_replay (ask, on or off); ""
	// from a gateway that predates it.
	KeyReplay string `json:"key_replay,omitempty"`
	// Files are the admin switches of push and sync; nil from a gateway
	// that predates them.
	Files *LauncherFiles `json:"files,omitempty"`
	// Git is substrate.git (B2 2.5); nil from a gateway that predates it.
	Git *LauncherGit `json:"git,omitempty"`
	// UploadScan is substrate.launcher.upload_scan; nil from a gateway that
	// predates it, which keeps holding files with secrets back.
	UploadScan *LauncherUploadScan `json:"upload_scan,omitempty"`
}

// LauncherGit is substrate.git as the gateway reports it: the effective
// https rewrite map and the submodule and LFS switches of run --clone.
type LauncherGit struct {
	HTTPSRewrite []config.SubstrateGitRewrite `json:"https_rewrite"`
	Submodules   bool                         `json:"submodules"`
	LFS          bool                         `json:"lfs"`
	// PushBranch is the cluster's substrate.git.push_branch (allow, ask or
	// deny; "" from a gateway before 1.0.11).
	PushBranch string `json:"push_branch_effective,omitempty"`
}

// LauncherUploadScan is substrate.launcher.upload_scan as the gateway
// reports it, defaults filled in.
type LauncherUploadScan struct {
	MaxFileBytes    int64  `json:"max_file_bytes"`
	TimeBudget      string `json:"time_budget"`
	SecretAction    string `json:"secret_action"`
	PlaceholderForm string `json:"placeholder_form"`
}

// LauncherFiles is substrate.files as the gateway reports it.
type LauncherFiles struct {
	Push bool `json:"push"`
	Sync bool `json:"sync"`
}

// Launcher reads settings from the signed-in admin listener. A gateway
// predating this route returns 404.
func (c *Client) Launcher(ctx context.Context) (LauncherSettings, error) {
	var settings LauncherSettings
	err := c.do(ctx, http.MethodGet, "launcher", nil, nil, &settings)
	return settings, err
}

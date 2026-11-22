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

package auth

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os/exec"
	"runtime"
	"strings"
	"time"
)

const (
	deviceGrant       = "urn:ietf:params:oauth:grant-type:device_code"
	defaultInterval   = 5 * time.Second
	slowDownStep      = 5 * time.Second
	defaultCodeExpiry = 10 * time.Minute
	maxNetFailures    = 3
)

var (
	errDeclined    = errors.New("sign-in was declined")
	errCodeExpired = errors.New("the code expired; run login again")
)

// LoginOptions tunes DeviceLogin. Zero values are fine: output is
// discarded, the OS opener is used, a client trusting the system roots
// plus IssuerCAFile is built, and real time is used.
type LoginOptions struct {
	NoBrowser   bool
	Out         io.Writer
	OpenURL     func(string) error
	HTTPClient  *http.Client
	Interactive bool
	Now         func() time.Time
	Sleep       func(context.Context, time.Duration) error
}

type deviceAuth struct {
	DeviceCode              string  `json:"device_code"`
	UserCode                string  `json:"user_code"`
	VerificationURI         string  `json:"verification_uri"`
	VerificationURIComplete string  `json:"verification_uri_complete"`
	ExpiresIn               flexInt `json:"expires_in"`
	Interval                flexInt `json:"interval"`
}

// DeviceLogin runs the OAuth 2.0 device authorization grant (RFC 8628)
// as a public client and returns the person token. It prints the page to
// open and the code on o.Out, and opens a browser only when o.Interactive
// is set and o.NoBrowser is not. Cancelling ctx stops the wait.
func DeviceLogin(ctx context.Context, c Context, o LoginOptions) (*Token, error) {
	if err := c.Validate(true); err != nil {
		return nil, err
	}
	out := o.Out
	if out == nil {
		out = io.Discard
	}
	now := o.Now
	if now == nil {
		now = time.Now
	}
	sleep := o.Sleep
	if sleep == nil {
		sleep = sleepCtx
	}
	hc := o.HTTPClient
	if hc == nil {
		var err error
		if hc, err = newHTTPClient(c.IssuerCAFile); err != nil {
			return nil, fmt.Errorf("issuer_ca_file: %w", err)
		}
	}
	d, err := discover(ctx, hc, c.Issuer, true)
	if err != nil {
		return nil, err
	}
	scopes := c.Scopes
	if len(scopes) == 0 {
		scopes = DefaultScopes()
	}
	status, body, err := postForm(ctx, hc, d.DeviceEndpoint, url.Values{
		"client_id": {c.ClientID},
		"scope":     {strings.Join(scopes, " ")},
	})
	if err != nil {
		return nil, fmt.Errorf("start the sign-in: %w", err)
	}
	if status != http.StatusOK {
		return nil, fmt.Errorf("the issuer refused to start a sign-in (HTTP %d%s); check --client-id and that the client allows the device sign-in", status, parseOAuthError(body).suffix())
	}
	var da deviceAuth
	if err := json.Unmarshal(body, &da); err != nil || da.DeviceCode == "" || da.UserCode == "" || da.VerificationURI == "" {
		return nil, errors.New("the issuer's device sign-in answer is not complete (needs device_code, user_code and verification_uri)")
	}
	if err := checkURL("verification_uri", da.VerificationURI, true); err != nil {
		return nil, fmt.Errorf("the issuer's %w", err)
	}
	link, complete := da.VerificationURI, false
	if da.VerificationURIComplete != "" && checkURL("verification_uri_complete", da.VerificationURIComplete, true) == nil {
		link, complete = da.VerificationURIComplete, true
	}
	expiresIn := time.Duration(da.ExpiresIn) * time.Second
	if expiresIn <= 0 {
		expiresIn = defaultCodeExpiry
	}
	interval := time.Duration(da.Interval) * time.Second
	if interval <= 0 {
		interval = defaultInterval
	}
	deadline := now().Add(expiresIn)
	userCode := clean(da.UserCode, 64)

	fmt.Fprintf(out, "To sign in, open this page in a browser:\n\n    %s\n\n", link)
	if complete {
		fmt.Fprintf(out, "Check that the page shows the code %s.\n", userCode)
	} else {
		fmt.Fprintf(out, "Then enter the code: %s\n", userCode)
	}
	fmt.Fprintf(out, "The code expires in %s. Waiting for the sign-in (Ctrl-C to stop).\n", humanMinutes(expiresIn))
	if o.Interactive && !o.NoBrowser {
		open := o.OpenURL
		if open == nil {
			open = openBrowser
		}
		_ = open(link) // the page is already printed
	}

	netFailures := 0
	for {
		if err := sleep(ctx, interval); err != nil {
			return nil, fmt.Errorf("sign-in stopped: %w", err)
		}
		if !now().Before(deadline) {
			return nil, errCodeExpired
		}
		status, body, err := postForm(ctx, hc, d.TokenEndpoint, url.Values{
			"grant_type":  {deviceGrant},
			"device_code": {da.DeviceCode},
			"client_id":   {c.ClientID},
		})
		if err != nil {
			if ctx.Err() != nil {
				return nil, fmt.Errorf("sign-in stopped: %w", ctx.Err())
			}
			if netFailures++; netFailures >= maxNetFailures {
				return nil, fmt.Errorf("reach the issuer while waiting for the sign-in: %w", err)
			}
			continue
		}
		netFailures = 0
		if status == http.StatusOK {
			var tr tokenResponse
			if err := json.Unmarshal(body, &tr); err != nil || tr.AccessToken == "" {
				return nil, errors.New("the issuer's token answer has no access_token")
			}
			return tr.toToken(now(), nil), nil
		}
		oe := parseOAuthError(body, da.DeviceCode)
		switch oe.Code {
		case "authorization_pending":
		case "slow_down":
			interval += slowDownStep
		case "access_denied":
			return nil, errDeclined
		case "expired_token":
			return nil, errCodeExpired
		default:
			return nil, fmt.Errorf("sign-in failed (HTTP %d%s)", status, oe.suffix())
		}
	}
}

func humanMinutes(d time.Duration) string {
	m := int((d + time.Minute - 1) / time.Minute)
	if m <= 1 {
		return "1 minute"
	}
	return fmt.Sprintf("%d minutes", m)
}

func sleepCtx(ctx context.Context, d time.Duration) error {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-t.C:
		return nil
	}
}

// openBrowser starts the OS URL opener and does not wait for it.
func openBrowser(u string) error {
	var cmd *exec.Cmd
	switch runtime.GOOS {
	case "darwin":
		cmd = exec.Command("open", u)
	case "windows":
		cmd = exec.Command("rundll32", "url.dll,FileProtocolHandler", u)
	default:
		cmd = exec.Command("xdg-open", u)
	}
	if err := cmd.Start(); err != nil {
		return err
	}
	go func() { _ = cmd.Wait() }()
	return nil
}

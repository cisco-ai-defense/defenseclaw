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
	"unicode"
)

const (
	maxBody        = 1 << 20
	requestTimeout = 15 * time.Second
)

// newHTTPClient trusts the system roots plus caFile (PEM) and refuses
// redirects that leave https (loopback http excepted).
func newHTTPClient(caFile string) (*http.Client, error) {
	pool, err := x509.SystemCertPool()
	if err != nil || pool == nil {
		pool = x509.NewCertPool()
	}
	if caFile != "" {
		pem, err := os.ReadFile(caFile)
		if err != nil {
			return nil, fmt.Errorf("read the CA file: %w", err)
		}
		if !pool.AppendCertsFromPEM(pem) {
			return nil, fmt.Errorf("%s holds no PEM certificate", caFile)
		}
	}
	tr := http.DefaultTransport.(*http.Transport).Clone()
	tr.TLSClientConfig = &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS12}
	return &http.Client{
		Transport: tr,
		Timeout:   requestTimeout,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) >= 5 {
				return errors.New("too many redirects")
			}
			return checkURL("redirect target", req.URL.String(), true)
		},
	}, nil
}

// do sends req with a 15 s timeout and reads at most 1 MiB of the body.
func do(ctx context.Context, hc *http.Client, req *http.Request) (int, []byte, error) {
	ctx, cancel := context.WithTimeout(ctx, requestTimeout)
	defer cancel()
	resp, err := hc.Do(req.WithContext(ctx))
	if err != nil {
		return 0, nil, err
	}
	defer resp.Body.Close()
	b, err := io.ReadAll(io.LimitReader(resp.Body, maxBody+1))
	if err != nil {
		return 0, nil, fmt.Errorf("read the response from %s: %w", req.URL.Host, err)
	}
	if len(b) > maxBody {
		return 0, nil, fmt.Errorf("the response from %s is larger than 1 MiB", req.URL.Host)
	}
	return resp.StatusCode, b, nil
}

func postForm(ctx context.Context, hc *http.Client, endpoint string, form url.Values) (int, []byte, error) {
	req, err := http.NewRequest(http.MethodPost, endpoint, strings.NewReader(form.Encode()))
	if err != nil {
		return 0, nil, errors.New("the endpoint URL is not valid")
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")
	return do(ctx, hc, req)
}

func get(ctx context.Context, hc *http.Client, endpoint string, hdr http.Header) (int, []byte, error) {
	req, err := http.NewRequest(http.MethodGet, endpoint, nil)
	if err != nil {
		return 0, nil, errors.New("the endpoint URL is not valid")
	}
	for k, v := range hdr {
		req.Header[k] = v
	}
	req.Header.Set("Accept", "application/json")
	return do(ctx, hc, req)
}

// oauthError is an RFC 6749 error body.
type oauthError struct {
	Code        string `json:"error"`
	Description string `json:"error_description"`
}

// parseOAuthError reads an error body, blanking any of secrets the issuer
// echoed before the text is shortened.
func parseOAuthError(b []byte, secrets ...string) oauthError {
	var e oauthError
	_ = json.Unmarshal(b, &e)
	for _, s := range secrets {
		if len(s) >= 4 {
			e.Code = strings.ReplaceAll(e.Code, s, "[redacted]")
			e.Description = strings.ReplaceAll(e.Description, s, "[redacted]")
		}
	}
	e.Code = clean(e.Code, 64)
	e.Description = clean(e.Description, 200)
	return e
}

// suffix renders ": code: description" for an error message.
func (e oauthError) suffix() string {
	switch {
	case e.Code != "" && e.Description != "":
		return ": " + e.Code + ": " + e.Description
	case e.Code != "":
		return ": " + e.Code
	}
	return ""
}

// clean keeps printable text, cut to n runes.
func clean(s string, n int) string {
	var b strings.Builder
	for _, r := range s {
		if b.Len() >= n {
			b.WriteString("...")
			break
		}
		if unicode.IsPrint(r) {
			b.WriteRune(r)
		}
	}
	return b.String()
}

// discovery is the part of the OIDC discovery document we use.
type discovery struct {
	Issuer             string `json:"issuer"`
	DeviceEndpoint     string `json:"device_authorization_endpoint"`
	TokenEndpoint      string `json:"token_endpoint"`
	RevocationEndpoint string `json:"revocation_endpoint"`
}

func discover(ctx context.Context, hc *http.Client, issuer string, needDevice bool) (*discovery, error) {
	if err := checkURL("issuer", issuer, false); err != nil {
		return nil, err
	}
	u := strings.TrimSuffix(issuer, "/") + "/.well-known/openid-configuration"
	status, body, err := get(ctx, hc, u, nil)
	if err != nil {
		return nil, fmt.Errorf("reach the issuer: %w", err)
	}
	if status != http.StatusOK {
		return nil, fmt.Errorf("the issuer %s did not serve its discovery document (HTTP %d); check --issuer", issuer, status)
	}
	var d discovery
	if err := json.Unmarshal(body, &d); err != nil {
		return nil, fmt.Errorf("the discovery document of %s is not valid JSON", issuer)
	}
	if d.Issuer != issuer {
		return nil, fmt.Errorf("refusing the issuer: its discovery document names %q, but the context issuer is %q; they must match exactly (check --issuer)", clean(d.Issuer, 200), issuer)
	}
	if d.TokenEndpoint == "" {
		return nil, fmt.Errorf("the discovery document of %s has no token_endpoint", issuer)
	}
	if err := checkURL("token_endpoint", d.TokenEndpoint, true); err != nil {
		return nil, fmt.Errorf("the issuer's %w", err)
	}
	if needDevice {
		if d.DeviceEndpoint == "" {
			return nil, fmt.Errorf("the issuer %s does not offer the device sign-in (no device_authorization_endpoint)", issuer)
		}
		if err := checkURL("device_authorization_endpoint", d.DeviceEndpoint, true); err != nil {
			return nil, fmt.Errorf("the issuer's %w", err)
		}
	}
	if d.RevocationEndpoint != "" && checkURL("revocation_endpoint", d.RevocationEndpoint, true) != nil {
		d.RevocationEndpoint = ""
	}
	return &d, nil
}

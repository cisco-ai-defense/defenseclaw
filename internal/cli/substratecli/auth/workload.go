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
	"io/fs"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"
)

// k8sTokenPath is DefaultK8sTokenPath; tests point it elsewhere.
var k8sTokenPath = DefaultK8sTokenPath

// WorkloadOptions selects the CI workload token. TokenFile wins over the
// environment; Env defaults to os.Getenv.
type WorkloadOptions struct {
	TokenFile  string
	HTTPClient *http.Client
	Env        func(string) string
}

const workloadPlaces = "1) --token-file, 2) " + EnvWorkloadTokenFile +
	", 3) GitHub Actions OIDC (" + EnvGitHubRequestURL + " and " + EnvGitHubRequestToken +
	"; the job needs permissions: id-token: write), 4) the Kubernetes service-account token (" +
	EnvK8sTokenFile + " or " + DefaultK8sTokenPath + ")"

// WorkloadLogin checks that a workload token can be read now and returns
// it (Kind "workload"). Nothing is stored.
func WorkloadLogin(ctx context.Context, c Context, o WorkloadOptions) (*Token, error) {
	raw, err := readWorkload(ctx, c, o, time.Now())
	if err != nil {
		return nil, err
	}
	return workloadToken(raw), nil
}

func workloadToken(raw string) *Token {
	t := &Token{AccessToken: raw, Kind: KindWorkload, Expiry: jwtExpiry(raw)}
	t.fillClaims()
	return t
}

// readWorkload returns a fresh workload token from the first source that
// is set: the option file, the env file, GitHub Actions, Kubernetes.
func readWorkload(ctx context.Context, c Context, o WorkloadOptions, now time.Time) (string, error) {
	env := o.Env
	if env == nil {
		env = os.Getenv
	}
	if o.TokenFile != "" {
		return readTokenFile(o.TokenFile, "the token file "+o.TokenFile, now)
	}
	if p := strings.TrimSpace(env(EnvWorkloadTokenFile)); p != "" {
		return readTokenFile(p, EnvWorkloadTokenFile+" ("+p+")", now)
	}
	ghURL, ghTok := strings.TrimSpace(env(EnvGitHubRequestURL)), strings.TrimSpace(env(EnvGitHubRequestToken))
	if ghURL != "" || ghTok != "" {
		if ghURL == "" || ghTok == "" {
			return "", fmt.Errorf("GitHub Actions OIDC needs both %s and %s; give the job permissions: id-token: write", EnvGitHubRequestURL, EnvGitHubRequestToken)
		}
		return githubToken(ctx, c, o.HTTPClient, ghURL, ghTok, now)
	}
	if p := strings.TrimSpace(env(EnvK8sTokenFile)); p != "" {
		return readTokenFile(p, EnvK8sTokenFile+" ("+p+")", now)
	}
	if _, err := os.Stat(k8sTokenPath); err == nil {
		return readTokenFile(k8sTokenPath, "the Kubernetes service-account token "+k8sTokenPath, now)
	}
	return "", errors.New("no workload token found; looked at " + workloadPlaces)
}

func readTokenFile(path, what string, now time.Time) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return "", fmt.Errorf("%s does not exist", what)
		}
		return "", fmt.Errorf("%s cannot be read: %v", what, errors.Unwrap(err))
	}
	defer f.Close()
	b, err := io.ReadAll(io.LimitReader(f, maxBody+1))
	if err != nil {
		return "", fmt.Errorf("%s cannot be read", what)
	}
	if len(b) > maxBody {
		return "", fmt.Errorf("%s is larger than 1 MiB", what)
	}
	return checkWorkload(strings.TrimSpace(string(b)), what, now)
}

func checkWorkload(raw, what string, now time.Time) (string, error) {
	if raw == "" {
		return "", fmt.Errorf("%s is empty", what)
	}
	if strings.ContainsAny(raw, " \t\r\n") {
		return "", fmt.Errorf("%s does not hold a single token", what)
	}
	if exp := jwtExpiry(raw); !exp.IsZero() && !exp.After(now) {
		return "", fmt.Errorf("the workload token from %s expired at %s; mint a fresh one", what, exp.UTC().Format(time.RFC3339))
	}
	return raw, nil
}

func githubToken(ctx context.Context, c Context, hc *http.Client, reqURL, reqTok string, now time.Time) (string, error) {
	const what = "GitHub Actions OIDC"
	if err := checkURL(EnvGitHubRequestURL, reqURL, true); err != nil {
		return "", err
	}
	if hc == nil {
		var err error
		if hc, err = newHTTPClient(""); err != nil {
			return "", err
		}
	}
	aud := c.WorkloadAudience
	if aud == "" {
		aud = DefaultWorkloadAudience
	}
	sep := "&"
	if !strings.Contains(reqURL, "?") {
		sep = "?"
	}
	status, body, err := get(ctx, hc, reqURL+sep+"audience="+url.QueryEscape(aud), http.Header{"Authorization": {"bearer " + reqTok}})
	if err != nil {
		return "", fmt.Errorf("%s request failed: %w", what, err)
	}
	if status != http.StatusOK {
		return "", fmt.Errorf("%s request failed (HTTP %d); check that the job has permissions: id-token: write", what, status)
	}
	var v struct {
		Value string `json:"value"`
	}
	if json.Unmarshal(body, &v) != nil {
		return "", fmt.Errorf("%s answer is not valid JSON", what)
	}
	return checkWorkload(strings.TrimSpace(v.Value), what, now)
}

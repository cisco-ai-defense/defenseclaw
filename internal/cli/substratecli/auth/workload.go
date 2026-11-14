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
	"strconv"
	"strings"
	"time"
)

// WorkloadOptions selects the CI workload token. TokenFile wins over the
// environment; Env defaults to os.Getenv.
type WorkloadOptions struct {
	TokenFile  string
	HTTPClient *http.Client
	Env        func(string) string
}

// workloadAudience is the audience a workload token must carry for c.
func (c Context) workloadAudience() string {
	if a := strings.TrimSpace(c.WorkloadAudience); a != "" {
		return a
	}
	return DefaultWorkloadAudience
}

// workloadPlaces lists where a workload token is looked for. There is no
// default Kubernetes path: the pod's service-account token is minted for
// the Kubernetes API server, not for DefenseClaw, so only a projected
// token with the DefenseClaw audience, named explicitly, is used.
func workloadPlaces(aud string) string {
	return "1) --token-file, 2) " + EnvWorkloadTokenFile +
		", 3) GitHub Actions OIDC (" + EnvGitHubRequestURL + " and " + EnvGitHubRequestToken +
		"; the job needs permissions: id-token: write), 4) " + EnvK8sTokenFile +
		" (a projected Kubernetes service-account token with audience " + strconv.Quote(aud) + ")"
}

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
// is set: the option file, the env file, GitHub Actions, the Kubernetes
// projected-token file. Every token is checked by checkWorkload before it
// is returned.
func readWorkload(ctx context.Context, c Context, o WorkloadOptions, now time.Time) (string, error) {
	env := o.Env
	if env == nil {
		env = os.Getenv
	}
	aud := c.workloadAudience()
	if o.TokenFile != "" {
		return readTokenFile(o.TokenFile, "the token file "+o.TokenFile, aud, now)
	}
	if p := strings.TrimSpace(env(EnvWorkloadTokenFile)); p != "" {
		return readTokenFile(p, EnvWorkloadTokenFile+" ("+p+")", aud, now)
	}
	ghURL, ghTok := strings.TrimSpace(env(EnvGitHubRequestURL)), strings.TrimSpace(env(EnvGitHubRequestToken))
	if ghURL != "" || ghTok != "" {
		if ghURL == "" || ghTok == "" {
			return "", fmt.Errorf("GitHub Actions OIDC needs both %s and %s; give the job permissions: id-token: write", EnvGitHubRequestURL, EnvGitHubRequestToken)
		}
		return githubToken(ctx, o.HTTPClient, ghURL, ghTok, aud, now)
	}
	if p := strings.TrimSpace(env(EnvK8sTokenFile)); p != "" {
		return readTokenFile(p, EnvK8sTokenFile+" ("+p+")", aud, now)
	}
	return "", errors.New("no workload token found; looked at " + workloadPlaces(aud))
}

func readTokenFile(path, what, aud string, now time.Time) (string, error) {
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
	return checkWorkload(strings.TrimSpace(string(b)), what, aud, now)
}

// audienceFix says how to get a token for the audience aud.
func audienceFix(aud string) string {
	return fmt.Sprintf("mint the token for the audience %q: GitHub Actions is asked for the context's workload_audience (or %s) automatically; in Kubernetes mount a projected service-account token with audience %q and set %s to its path",
		aud, EnvWorkloadAudience, aud, EnvK8sTokenFile)
}

// quoteAudiences prints at most five audiences, quoted and shortened.
func quoteAudiences(list []string) string {
	const limit = 5
	var q []string
	for i, a := range list {
		if i == limit {
			q = append(q, fmt.Sprintf("and %d more", len(list)-limit))
			break
		}
		q = append(q, strconv.Quote(clean(a, 80)))
	}
	return strings.Join(q, ", ")
}

// checkWorkload decides whether raw may be sent to the admin listener.
// The claims are read WITHOUT verification: the gateway verifies the
// signature. They are read here only so the launcher refuses a token
// that is not meant for DefenseClaw (another service's token would
// otherwise be handed to the admin listener). Errors never carry the
// token, only the audiences it names.
func checkWorkload(raw, what, aud string, now time.Time) (string, error) {
	if raw == "" {
		return "", fmt.Errorf("%s is empty", what)
	}
	if strings.ContainsAny(raw, " \t\r\n") {
		return "", fmt.Errorf("%s does not hold a single token", what)
	}
	if parts := strings.Split(raw, "."); len(parts) != 3 || parts[0] == "" || parts[1] == "" {
		return "", fmt.Errorf("the workload token from %s is not a JWT (three parts separated by dots); DefenseClaw takes an OIDC ID token; %s", what, audienceFix(aud))
	}
	c, ok := parseClaims(raw)
	if !ok {
		return "", fmt.Errorf("the workload token from %s has no readable claims (its middle part is not base64url-encoded JSON); %s", what, audienceFix(aud))
	}
	if exp := c.expiry(); !exp.IsZero() && !exp.After(now) {
		return "", fmt.Errorf("the workload token from %s expired at %s; mint a fresh one", what, exp.UTC().Format(time.RFC3339))
	}
	got := c.audiences()
	if len(got) == 0 {
		return "", fmt.Errorf("the workload token from %s has no aud (audience) claim, so it is not sent; DefenseClaw expects the audience %q; %s", what, aud, audienceFix(aud))
	}
	for _, a := range got {
		if a == aud {
			return raw, nil
		}
	}
	return "", fmt.Errorf("the workload token from %s is for the audience %s, not %q, so it is not sent; %s", what, quoteAudiences(got), aud, audienceFix(aud))
}

func githubToken(ctx context.Context, hc *http.Client, reqURL, reqTok, aud string, now time.Time) (string, error) {
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
	return checkWorkload(strings.TrimSpace(v.Value), what, aud, now)
}

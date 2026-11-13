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

package regauth

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	awsconfig "github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/ecr"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/substrate/attest"
)

// ECR token timing: a token is valid for 12 hours; it is replaced half an
// hour before it expires, and a failed fetch is not retried for 30 seconds
// (every verification in that window fails retryable, never anonymously).
const (
	ecrRefreshBefore = 30 * time.Minute
	ecrRetryAfter    = 30 * time.Second
	ecrFetchTimeout  = 30 * time.Second
)

// ECRFetcher gets an ECR login for a region: the user, the password and
// when it expires.
type ECRFetcher func(ctx context.Context, region string, fips bool) (user, password string, expires time.Time, err error)

// ECR logs in to the listed Amazon ECR registry hosts with
// ecr:GetAuthorizationToken, using the AWS SDK default credential chain
// (on EKS: IRSA or EKS Pod Identity on the pod's ServiceAccount). A host
// that is not listed gets no login, even another ECR host.
type ECR struct {
	hosts map[string]ecrHost
	fetch ECRFetcher
	now   func() time.Time

	mu    sync.Mutex
	cache map[string]ecrToken
}

type ecrHost struct {
	region string
	fips   bool
}

type ecrToken struct {
	cred    attest.Credential
	expires time.Time
	err     error
	at      time.Time
	// failedAt is the last failed refresh of a token that is still valid.
	failedAt time.Time
}

// NewECR returns the source for hosts (config.ParseECRRegistryHost form;
// other names are ignored, config validation refuses them). A nil fetch is
// the AWS SDK.
func NewECR(hosts []string, fetch ECRFetcher) *ECR {
	if fetch == nil {
		fetch = sdkECRLogin
	}
	e := &ECR{hosts: map[string]ecrHost{}, fetch: fetch, now: time.Now, cache: map[string]ecrToken{}}
	for _, h := range hosts {
		h = strings.ToLower(strings.TrimSpace(h))
		if _, region, fips, ok := config.ParseECRRegistryHost(h); ok {
			e.hosts[h] = ecrHost{region: region, fips: fips}
		}
	}
	return e
}

// Credential implements attest.CredentialSource.
func (e *ECR) Credential(ctx context.Context, host string) (attest.Credential, bool, error) {
	host = strings.ToLower(host)
	h, ok := e.hosts[host]
	if !ok {
		return attest.Credential{}, false, nil
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	now := e.now()
	t, have := e.cache[host]
	switch {
	case have && t.err == nil && now.Before(t.expires.Add(-ecrRefreshBefore)):
		return t.cred, true, nil
	case have && t.err == nil && now.Before(t.expires) && now.Sub(t.failedAt) < ecrRetryAfter:
		return t.cred, true, nil
	case have && t.err != nil && now.Sub(t.at) < ecrRetryAfter:
		return attest.Credential{}, false, t.err
	}
	fctx, cancel := context.WithTimeout(ctx, ecrFetchTimeout)
	defer cancel()
	user, pass, exp, err := e.fetch(fctx, h.region, h.fips)
	if err == nil && (user == "" || pass == "") {
		err = errors.New("the authorization data is empty")
	}
	if err != nil {
		// A token that is still valid outlives a failed refresh.
		if have && t.err == nil && now.Before(t.expires) {
			t.failedAt = now
			e.cache[host] = t
			return t.cred, true, nil
		}
		err = fmt.Errorf("amazon ECR login for %s: %w", host, err)
		e.cache[host] = ecrToken{err: err, at: now}
		return attest.Credential{}, false, err
	}
	if exp.IsZero() {
		exp = now.Add(time.Hour)
	}
	c := attest.Credential{Username: user, Password: pass}
	e.cache[host] = ecrToken{cred: c, expires: exp, at: now}
	return c, true, nil
}

// sdkECRLogin is ecr:GetAuthorizationToken through the default chain.
func sdkECRLogin(ctx context.Context, region string, fips bool) (string, string, time.Time, error) {
	opts := []func(*awsconfig.LoadOptions) error{awsconfig.WithRegion(region)}
	if fips {
		opts = append(opts, awsconfig.WithUseFIPSEndpoint(aws.FIPSEndpointStateEnabled))
	}
	cfg, err := awsconfig.LoadDefaultConfig(ctx, opts...)
	if err != nil {
		return "", "", time.Time{}, err
	}
	out, err := ecr.NewFromConfig(cfg).GetAuthorizationToken(ctx, &ecr.GetAuthorizationTokenInput{})
	if err != nil {
		return "", "", time.Time{}, err
	}
	if len(out.AuthorizationData) == 0 || out.AuthorizationData[0].AuthorizationToken == nil {
		return "", "", time.Time{}, errors.New("no authorization data")
	}
	ad := out.AuthorizationData[0]
	raw, err := base64.StdEncoding.DecodeString(aws.ToString(ad.AuthorizationToken))
	if err != nil {
		return "", "", time.Time{}, errors.New("the authorization token is not base64")
	}
	user, pass, ok := strings.Cut(string(raw), ":")
	if !ok {
		return "", "", time.Time{}, errors.New("the authorization token is not user:password")
	}
	return user, pass, aws.ToTime(ad.ExpiresAt), nil
}

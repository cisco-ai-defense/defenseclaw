// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package regauth

import (
	"context"
	"encoding/base64"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/substrate/attest"
)

const marker = "MARKER-PASSWORD-f11"

func b64(s string) string { return base64.StdEncoding.EncodeToString([]byte(s)) }

func TestParseDockerConfig(t *testing.T) {
	got, err := ParseDockerConfig([]byte(`{"auths": {
		"https://index.docker.io/v1/": {"auth": "` + b64("hubuser:"+marker) + `"},
		"Registry.Example.com:5000": {"username": "u", "password": "` + marker + `"},
		"https://ghcr.io/v2/": {"auth": "` + b64("gh:"+marker) + `"},
		"token-only.example.com": {"identitytoken": "x"}
	}, "credsStore": "desktop"}`))
	if err != nil {
		t.Fatal(err)
	}
	if c := got["registry-1.docker.io"]; c.Username != "hubuser" || c.Password != marker || len(c.TokenHosts) != 1 || c.TokenHosts[0] != "auth.docker.io" {
		t.Fatalf("Docker Hub login = %v %v", c, c.TokenHosts)
	}
	if c := got["registry.example.com:5000"]; c.Username != "u" || c.Password != marker || len(c.TokenHosts) != 0 {
		t.Fatalf("host with port = %v", c)
	}
	if c := got["ghcr.io"]; c.Username != "gh" {
		t.Fatalf("URL key = %v", c)
	}
	if _, ok := got["token-only.example.com"]; ok {
		t.Fatal("an identity-token-only entry is not a login")
	}
	if len(got) != 3 {
		t.Fatalf("logins for %d hosts, want 3", len(got))
	}

	for name, in := range map[string]string{
		"not json":    `{"auths": ` + marker,
		"bad base64":  `{"auths": {"r.example.com": {"auth": "!!` + marker + `"}}}`,
		"no colon":    `{"auths": {"r.example.com": {"auth": "` + b64(marker) + `"}}}`,
		"empty key":   `{"auths": {"": {"auth": "` + b64("u:"+marker) + `"}}}`,
		"wrong shape": `{"auths": ["` + marker + `"]}`,
	} {
		t.Run(name, func(t *testing.T) {
			_, err := ParseDockerConfig([]byte(in))
			if err == nil {
				t.Fatal("want an error")
			}
			if strings.Contains(err.Error(), marker) {
				t.Fatalf("the error quotes the file: %v", err)
			}
		})
	}
}

func TestDockerConfigFileRereadsAndFailsClosed(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "config.json")
	d := &DockerConfigFile{Path: p}
	ctx := context.Background()

	if _, ok, err := d.Credential(ctx, "r.example.com"); ok || err != nil {
		t.Fatalf("a missing file is anonymous: %v %v", ok, err)
	}
	write := func(body string, at time.Time) {
		t.Helper()
		if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
		_ = os.Chtimes(p, at, at)
	}
	now := time.Now()
	write(`{"auths": {"r.example.com": {"auth": "`+b64("u1:"+marker)+`"}}}`, now)
	if c, ok, err := d.Credential(ctx, "R.example.com"); !ok || err != nil || c.Username != "u1" {
		t.Fatalf("first login = %v %v %v", c, ok, err)
	}
	if _, ok, _ := d.Credential(ctx, "other.example.com"); ok {
		t.Fatal("a host the file does not name got a login")
	}
	// A Secret update swaps the file: the new login applies.
	write(`{"auths": {"r.example.com": {"auth": "`+b64("u2:"+marker)+`"}}}`, now.Add(time.Minute))
	if c, _, _ := d.Credential(ctx, "r.example.com"); c.Username != "u2" {
		t.Fatalf("after the update = %v", c)
	}
	// A broken file fails every lookup (never a silent anonymous read).
	write(`{"auths": `, now.Add(2*time.Minute))
	if _, _, err := d.Credential(ctx, "r.example.com"); err == nil || strings.Contains(err.Error(), marker) {
		t.Fatalf("broken file: %v", err)
	}
	// Removed: anonymous again.
	_ = os.Remove(p)
	if _, ok, err := d.Credential(ctx, "r.example.com"); ok || err != nil {
		t.Fatalf("a removed file is anonymous: %v %v", ok, err)
	}
}

const testECRHost = "123456789012.dkr.ecr.us-east-1.amazonaws.com"

func TestECRLoginsOnlyListedHostsAndRefreshes(t *testing.T) {
	var mu sync.Mutex
	calls := 0
	clock := time.Date(2026, 11, 13, 0, 0, 0, 0, time.UTC)
	var fail error
	fetch := func(_ context.Context, region string, fips bool) (string, string, time.Time, error) {
		mu.Lock()
		defer mu.Unlock()
		calls++
		if region != "us-east-1" || fips {
			t.Errorf("fetch for region %q fips %v", region, fips)
		}
		if fail != nil {
			return "", "", time.Time{}, fail
		}
		return "AWS", marker + string(rune('a'+calls)), clock.Add(12 * time.Hour), nil
	}
	e := NewECR([]string{testECRHost, "not-an-ecr-host.example.com"}, fetch)
	e.now = func() time.Time { return clock }
	ctx := context.Background()

	for _, h := range []string{"999999999999.dkr.ecr.us-east-1.amazonaws.com", "not-an-ecr-host.example.com", "registry.example.com"} {
		if _, ok, err := e.Credential(ctx, h); ok || err != nil {
			t.Fatalf("unlisted host %s got a login (%v)", h, err)
		}
	}
	if calls != 0 {
		t.Fatal("an unlisted host made a token call")
	}
	c1, ok, err := e.Credential(ctx, testECRHost)
	if !ok || err != nil || c1.Username != "AWS" {
		t.Fatalf("login = %v %v %v", c1, ok, err)
	}
	clock = clock.Add(11 * time.Hour)
	if c, _, _ := e.Credential(ctx, testECRHost); c.Password != c1.Password || calls != 1 {
		t.Fatalf("the token was fetched again %d times before its refresh time", calls)
	}
	// Within 30 minutes of the expiry: refreshed.
	clock = clock.Add(31 * time.Minute)
	c2, _, _ := e.Credential(ctx, testECRHost)
	if calls != 2 || c2.Password == c1.Password {
		t.Fatalf("not refreshed before expiry: calls %d", calls)
	}
	// A failed refresh keeps a token that is still valid...
	fail = errors.New("sts unavailable")
	clock = clock.Add(11*time.Hour + 45*time.Minute)
	if c, ok, err := e.Credential(ctx, testECRHost); !ok || err != nil || c.Password != c2.Password {
		t.Fatalf("a valid token was dropped on a failed refresh: %v %v", ok, err)
	}
	// ...and past expiry fails the lookup, then waits before trying again.
	clock = clock.Add(time.Hour)
	if _, _, err := e.Credential(ctx, testECRHost); err == nil || strings.Contains(err.Error(), marker) {
		t.Fatalf("expired token and failed fetch: %v", err)
	}
	n := calls
	if _, _, err := e.Credential(ctx, testECRHost); err == nil || calls != n {
		t.Fatalf("retried within the back-off: %d calls", calls-n)
	}
	fail = nil
	clock = clock.Add(31 * time.Second)
	if _, ok, err := e.Credential(ctx, testECRHost); !ok || err != nil {
		t.Fatalf("after the back-off: %v %v", ok, err)
	}
}

func TestFromConfig(t *testing.T) {
	if s := FromConfig(config.SubstrateRegistryAuthConfig{}); s != nil {
		t.Fatalf("no registry_auth must be anonymous (nil), got %T", s)
	}
	if _, ok := FromConfig(config.SubstrateRegistryAuthConfig{DockerConfig: "/x/config.json"}).(*DockerConfigFile); !ok {
		t.Fatal("docker_config alone is the file source")
	}
	if _, ok := FromConfig(config.SubstrateRegistryAuthConfig{ECRHosts: []string{testECRHost}}).(*ECR); !ok {
		t.Fatal("ecr_hosts alone is the ECR source")
	}
	if _, ok := FromConfig(config.SubstrateRegistryAuthConfig{DockerConfig: "/x/config.json", ECRHosts: []string{testECRHost}}).(Chain); !ok {
		t.Fatal("both are a chain")
	}
}

// GAP-0190 end to end: an ECR-style registry that answers a Basic challenge
// gets the ECR token; another registry, reached by the same client, gets
// nothing (as in GAP-0052).
func TestGAP0190ECRTokenReachesOnlyItsRegistry(t *testing.T) {
	var mu sync.Mutex
	seen := map[string][]string{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		seen[r.Host] = append(seen[r.Host], r.Header.Get("Authorization"))
		mu.Unlock()
		if r.Header.Get("Authorization") == "Basic "+b64("AWS:"+marker) {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Www-Authenticate", `Basic realm="https://`+r.Host+`/",service="ecr.amazonaws.com"`)
		w.WriteHeader(http.StatusUnauthorized)
	}))
	defer srv.Close()
	addr := strings.TrimPrefix(srv.URL, "http://")
	// Every host name dials the test server; both names are plain HTTP here.
	hc := &http.Client{Transport: &http.Transport{DialContext: func(ctx context.Context, network, _ string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, network, addr)
	}}}
	const other = "222222222222.dkr.ecr.us-east-1.amazonaws.com"
	src := NewECR([]string{testECRHost}, func(context.Context, string, bool) (string, string, time.Time, error) {
		return "AWS", marker, time.Now().Add(12 * time.Hour), nil
	})
	reg := attest.NewRegistry(attest.RegistryOptions{PlainHTTP: []string{testECRHost, other}, Source: src, HTTPClient: hc})
	ctx := context.Background()
	if _, _, _, err := reg.Manifest(ctx, attest.Ref{Registry: testECRHost, Repo: "dc/claude", Tag: "t"}); !errors.Is(err, attest.ErrNotFound) {
		t.Fatalf("the listed ECR host should be read with the token: %v", err)
	}
	if _, _, _, err := reg.Manifest(ctx, attest.Ref{Registry: other, Repo: "dc/claude", Tag: "t"}); err == nil {
		t.Fatal("the unlisted registry must stay unauthenticated")
	}
	mu.Lock()
	defer mu.Unlock()
	if got := seen[testECRHost]; len(got) != 2 || got[0] != "" || got[1] == "" {
		t.Fatalf("listed host saw %q", got)
	}
	for _, h := range seen[other] {
		if h != "" {
			t.Fatalf("an unlisted registry got %q", h)
		}
	}
}

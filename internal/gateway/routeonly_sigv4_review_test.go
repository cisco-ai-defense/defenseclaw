// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"bytes"
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
)

// do sends a request with no AWS credential, like post, for any method.
func (f *sigv4Fixture) do(t *testing.T, method, path string) *httptest.ResponseRecorder {
	t.Helper()
	r := httptest.NewRequest(method, "http://127.0.0.1:18970"+path, bytes.NewReader([]byte(`{"messages":[{"role":"user","content":"hello"}]}`)))
	if method == http.MethodGet {
		r = httptest.NewRequest(method, "http://127.0.0.1:18970"+path, nil)
	}
	r.RemoteAddr = "127.0.0.1:50123"
	r.Header.Set("Content-Type", "application/json")
	r.Header.Set(routeTokenHeader, f.token)
	rec := httptest.NewRecorder()
	routeOnlyDispatch(func() *routeOnlyServer { return f.srv }, http.NotFoundHandler()).ServeHTTP(rec, r)
	return rec
}

// REVIEW-code-slice7 P2-1: only the four model calls are signed with the
// gateway identity; everything else is refused before any signing.
func TestRouteOnlySigV4SignsOnlyTheFourModelCalls(t *testing.T) {
	f := newSigV4Fixture(t)
	for _, c := range []struct{ method, path string }{
		{http.MethodPost, "/r/claudecode/async-invoke"},
		{http.MethodPost, "/r/claudecode/model/us.anthropic.claude-sonnet-4-5-v1:0/count-tokens"},
		{http.MethodPost, "/r/claudecode/guardrail/gr1/version/1/apply"},
		{http.MethodGet, "/r/claudecode/models"},
		{http.MethodGet, "/r/claudecode/model/m/invoke/models"},
		{http.MethodPost, "/r/claudecode/model/a/b/invoke"},
		{http.MethodPost, "/r/claudecode/model/m/invoke/"},
	} {
		rec := f.do(t, c.method, c.path)
		if rec.Code != http.StatusForbidden || !strings.Contains(rec.Body.String(), "permission_error") {
			t.Errorf("%s %s = %d %s, want a 403 before signing", c.method, c.path, rec.Code, rec.Body.String())
		}
	}
	if len(f.orig)+len(f.alt) != 0 {
		t.Fatalf("a refused path reached an upstream (%d)", len(f.orig)+len(f.alt))
	}
	for _, action := range []string{"converse", "converse-stream", "invoke", "invoke-with-response-stream"} {
		rec := f.do(t, http.MethodPost, "/r/claudecode/model/us.anthropic.claude-sonnet-4-5-v1:0/"+action)
		if rec.Code != http.StatusOK {
			t.Fatalf("%s = %d %s", action, rec.Code, rec.Body.String())
		}
		mustVerify(t, f.orig[len(f.orig)-1])
	}
}

// P2-1: the admin gate judges a signed model call.
func TestRouteOnlySigV4ModelCallsPassTheGate(t *testing.T) {
	f := newSigV4Fixture(t)
	f.srv.router.SetAdminEvaluator(denyOriginalAdmin{})
	rec := f.do(t, http.MethodPost, "/r/claudecode/model/us.anthropic.claude-sonnet-4-5-v1:0/invoke")
	if rec.Code != http.StatusForbidden || len(f.orig) != 0 {
		t.Fatalf("a gated original was signed and sent: %d orig=%d", rec.Code, len(f.orig))
	}
}

// P3-4: a full buffer budget is overloaded (retried), not 413 (prompt too long).
func TestRouteOnlySigV4BudgetFullIsOverloaded(t *testing.T) {
	f := newSigV4Fixture(t)
	f.srv.heldBytes = routeOnlyBufferBudget
	rec := f.post(t, "/r/claudecode"+sigv4FlowARN, "hello", nil)
	f.srv.heldBytes = 0
	if rec.Code != http.StatusServiceUnavailable || !strings.Contains(rec.Body.String(), "overloaded_error") || len(f.orig) != 0 {
		t.Fatalf("status %d body %s orig %d", rec.Code, rec.Body.String(), len(f.orig))
	}
}

// P3-8: presigned X-Amz-* query keys are dropped before signing.
func TestRouteOnlySigV4StripsPresignedQuery(t *testing.T) {
	f := newSigV4Fixture(t)
	rec := f.post(t, "/r/claudecode"+sigv4FlowARN+"?X-Amz-Algorithm=AWS4-HMAC-SHA256&X-Amz-Signature=00&x-amz-credential=AKID&keep=1", "hello", nil)
	if rec.Code != http.StatusOK || len(f.orig) != 1 {
		t.Fatalf("status %d orig %d", rec.Code, len(f.orig))
	}
	if f.orig[0].rawQuery != "keep=1" {
		t.Fatalf("upstream query %q, want keep=1", f.orig[0].rawQuery)
	}
	mustVerify(t, f.orig[0])
}

// P3-9: a routed backend that is not an AWS Bedrock host never gets the
// upstream AWS credential; the original is sent instead.
func TestRouteOnlySigV4NonAWSRoutedHostGetsNoCredential(t *testing.T) {
	f := newSigV4Fixture(t)
	bedrockSignableURL = func(raw string) bool { return strings.HasPrefix(raw, f.origURL) }
	rec := f.post(t, "/r/claudecode/model/us.anthropic.claude-sonnet-4-5-v1:0/invoke", "quick question: what is 2+2", nil)
	if rec.Code != http.StatusOK || len(f.alt) != 0 || len(f.orig) != 1 || rec.Header().Get("X-Semantic-Router") == "routed" {
		t.Fatalf("status %d alt %d orig %d router %q", rec.Code, len(f.alt), len(f.orig), rec.Header().Get("X-Semantic-Router"))
	}
	mustVerify(t, f.orig[0])
}

func TestBedrockSignableURLOnlyAWSHTTPS(t *testing.T) {
	for raw, want := range map[string]bool{
		"https://bedrock-runtime.us-east-1.amazonaws.com":                true,
		"https://vpce-0abc.bedrock-runtime.eu-west-3.vpce.amazonaws.com": true,
		"http://bedrock-runtime.us-east-1.amazonaws.com":                 false,
		"https://llm-gw.corp.example":                                    false,
		"http://127.0.0.1:4100":                                          false,
	} {
		if got := bedrockSignableURL(raw); got != want {
			t.Errorf("%s: signable %v", raw, got)
		}
	}
}

// P3-7: one stderr line per key a minute.
func TestRouteOnlyLogLimiterOncePerInterval(t *testing.T) {
	now := time.Date(2026, 11, 13, 0, 0, 0, 0, time.UTC)
	l := &routeOnlyLogLimiter{every: time.Minute, now: func() time.Time { return now }}
	if !l.allow("a") || l.allow("a") || !l.allow("b") {
		t.Fatal("first line per key must pass, the repeat must not")
	}
	now = now.Add(61 * time.Second)
	if !l.allow("a") {
		t.Fatal("the next interval must pass again")
	}
}

type countingCreds struct {
	calls   int
	expires time.Duration
}

func (c *countingCreds) Retrieve(context.Context) (aws.Credentials, error) {
	c.calls++
	return aws.Credentials{AccessKeyID: "AKID", SecretAccessKey: "s", CanExpire: true, Expires: time.Now().Add(c.expires)}, nil
}

// P3-5: a credential within a minute of its expiry is fetched again.
func TestBedrockCredentialsRefreshBeforeExpiry(t *testing.T) {
	soon := &countingCreds{expires: 20 * time.Second}
	cache := bedrockCredentialsCache(soon)
	for range 2 {
		if _, err := cache.Retrieve(context.Background()); err != nil {
			t.Fatal(err)
		}
	}
	if soon.calls != 2 {
		t.Fatalf("a credential 20s from expiry was reused (%d fetches)", soon.calls)
	}
	later := &countingCreds{expires: 10 * time.Minute}
	cache = bedrockCredentialsCache(later)
	for range 2 {
		_, _ = cache.Retrieve(context.Background())
	}
	if later.calls != 1 {
		t.Fatalf("a fresh credential was fetched %d times", later.calls)
	}
}

func TestStripAmzQuery(t *testing.T) {
	for in, want := range map[string]string{
		"":                                 "",
		"a=1&b=2":                          "a=1&b=2",
		"X-Amz-Signature=00&a=1":           "a=1",
		"x-amz-date=1&X-AMZ-EXPIRES=5":     "",
		"X-Amz-Credential=AKID%2Fx&beta=t": "beta=t",
	} {
		if got := stripAmzQuery(in); got != want {
			t.Errorf("%q -> %q, want %q", in, got, want)
		}
	}
}

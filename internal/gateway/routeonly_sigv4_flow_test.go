// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/config"
)

type sigv4Fixture struct {
	srv       *routeOnlyServer
	cfg       *config.Config
	token     string
	mu        sync.Mutex
	orig, alt []sigv4Wire
	altStatus int
	origURL   string
}

func newSigV4Fixture(t *testing.T) *sigv4Fixture {
	t.Helper()
	isolateAWSEnv(t)
	t.Setenv("DC_SIGV4_FLOW_AK", "AKIDGATEWAY")
	t.Setenv("DC_SIGV4_FLOW_SK", "gateway-secret")
	t.Setenv("DC_SIGV4_FLOW_ST", "gateway-session")
	f := &sigv4Fixture{altStatus: http.StatusOK}
	record := func(dst *[]sigv4Wire, status func() int) http.HandlerFunc {
		return func(w http.ResponseWriter, r *http.Request) {
			body, _ := io.ReadAll(r.Body)
			f.mu.Lock()
			*dst = append(*dst, sigv4Wire{method: r.Method, escapedPath: r.URL.EscapedPath(), rawQuery: r.URL.RawQuery, host: r.Host, header: r.Header.Clone(), body: body})
			f.mu.Unlock()
			w.Header().Set("Content-Type", "application/vnd.amazon.eventstream")
			w.WriteHeader(status())
			_, _ = w.Write([]byte("event-1"))
			w.(http.Flusher).Flush()
			_, _ = w.Write([]byte("event-2"))
		}
	}
	orig := httptest.NewServer(record(&f.orig, func() int { return http.StatusOK }))
	t.Cleanup(orig.Close)
	alt := httptest.NewServer(record(&f.alt, func() int { return f.altStatus }))
	t.Cleanup(alt.Close)
	f.origURL = orig.URL
	// The test upstreams are loopback HTTP servers, not AWS hosts.
	prevSignable := bedrockSignableURL
	bedrockSignableURL = func(string) bool { return true }
	t.Cleanup(func() { bedrockSignableURL = prevSignable })
	block := &config.RoutingBedrockAuthConfig{Region: "us-east-1", Auth: config.RoutingBedrockAuthIAMCredentials, AccessKeyEnv: "DC_SIGV4_FLOW_AK", SecretKeyEnv: "DC_SIGV4_FLOW_SK", SessionTokenEnv: "DC_SIGV4_FLOW_ST"}
	cfg := &config.Config{DataDir: t.TempDir()}
	cfg.Routing = config.RoutingConfig{
		Enabled: true, Classifier: config.RoutingClassifierRules,
		Models:    []config.RoutingModelBackend{{Name: "fast", Provider: "bedrock", Model: "us.anthropic.claude-haiku-4-5-v1:0", BaseURL: alt.URL, APIs: []string{config.RoutingAPIInvoke}}},
		Signals:   config.RoutingSignalConfig{Keywords: []config.RoutingKeywordSignal{{Name: "quick", Keywords: []string{"quick question"}}}},
		Decisions: []config.RoutingDecisionRule{{Name: "quick", Conditions: []config.RoutingCondition{{Type: "keyword", Name: "quick"}}, ModelRefs: []string{"fast"}}},
		RouteOnly: config.RoutingRouteOnlyConfig{Connectors: []string{"claudecode"}, Upstreams: map[string]config.RoutingUpstreamConfig{"claudecode": {BaseURL: orig.URL, API: config.RoutingAPIInvoke, Bedrock: block}}},
	}
	if err := cfg.Routing.Validate(); err != nil {
		t.Fatal(err)
	}
	f.cfg = cfg
	f.srv = newRouteOnlyServer(newEngineRouter(cfg, nil, ""), func() *config.Config { return f.cfg }, cfg.DataDir)
	tok, err := f.srv.tokens.Token("claudecode")
	if err != nil {
		t.Fatal(err)
	}
	f.token = tok
	prev := acpLoopbackPeerUID
	acpLoopbackPeerUID = func(*http.Request) (int, error) { return os.Getuid(), nil }
	t.Cleanup(func() { acpLoopbackPeerUID = prev })
	return f
}

// post sends what Claude Code sends with CLAUDE_CODE_SKIP_BEDROCK_AUTH=1:
// no AWS credential at all.
func (f *sigv4Fixture) post(t *testing.T, path, text string, mut func(*http.Request)) *httptest.ResponseRecorder {
	t.Helper()
	raw, _ := json.Marshal(map[string]any{"anthropic_version": "bedrock-2023-05-31", "max_tokens": 64, "messages": []any{map[string]any{"role": "user", "content": text}}})
	r := httptest.NewRequest(http.MethodPost, "http://127.0.0.1:18970"+path, bytes.NewReader(raw))
	r.RemoteAddr = "127.0.0.1:50123"
	r.Header.Set("Content-Type", "application/json")
	r.Header.Set(routeTokenHeader, f.token)
	if mut != nil {
		mut(r)
	}
	rec := httptest.NewRecorder()
	routeOnlyDispatch(func() *routeOnlyServer { return f.srv }, http.NotFoundHandler()).ServeHTTP(rec, r)
	return rec
}

const sigv4FlowARN = "/model/arn%3Aaws%3Abedrock%3Aus-east-1%3A111122223333%3Aapplication-inference-profile%2Fabc123/invoke-with-response-stream"

func mustVerify(t *testing.T, w sigv4Wire) string {
	t.Helper()
	scope, err := verifySigV4(w, "gateway-secret")
	if err != nil {
		t.Fatalf("%s: %v", w.escapedPath, err)
	}
	if scope[1] != "us-east-1" || scope[2] != "bedrock" || w.header.Get("X-Amz-Security-Token") != "gateway-session" {
		t.Fatalf("scope %v or session token wrong", scope)
	}
	return w.header.Get("Authorization")
}

func TestRouteOnlySigV4UnroutedARNIsSignedAndStreams(t *testing.T) {
	f := newSigV4Fixture(t)
	rec := f.post(t, "/r/claudecode"+sigv4FlowARN, "hello there", func(r *http.Request) { r.Header.Set("X-Amz-Security-Token", "agent-stale") })
	if rec.Code != http.StatusOK || rec.Body.String() != "event-1event-2" || len(f.orig) != 1 || len(f.alt) != 0 {
		t.Fatalf("status %d body %q orig %d alt %d", rec.Code, rec.Body.String(), len(f.orig), len(f.alt))
	}
	if f.orig[0].escapedPath != sigv4FlowARN {
		t.Fatalf("upstream path %q, want the escaped ARN", f.orig[0].escapedPath)
	}
	mustVerify(t, f.orig[0])
}

func TestRouteOnlySigV4RoutedAndRetryEachSignAnew(t *testing.T) {
	f := newSigV4Fixture(t)
	f.altStatus = http.StatusServiceUnavailable
	rec := f.post(t, "/r/claudecode/model/us.anthropic.claude-sonnet-4-5-v1:0/invoke-with-response-stream", "quick question: what is 2+2", nil)
	if rec.Code != http.StatusOK || len(f.alt) != 1 || len(f.orig) != 1 || rec.Header().Get("X-Semantic-Router") != "fallback" {
		t.Fatalf("status %d alt %d orig %d router %q", rec.Code, len(f.alt), len(f.orig), rec.Header().Get("X-Semantic-Router"))
	}
	if !strings.Contains(f.alt[0].escapedPath, "claude-haiku-4-5") || !strings.Contains(f.orig[0].escapedPath, "claude-sonnet-4-5") {
		t.Fatalf("paths: routed %q, retry %q", f.alt[0].escapedPath, f.orig[0].escapedPath)
	}
	if a, b := mustVerify(t, f.alt[0]), mustVerify(t, f.orig[0]); a == b {
		t.Fatal("the retry reused the routed signature")
	}
}

func TestRouteOnlySigV4RefusesAnAgentSignature(t *testing.T) {
	f := newSigV4Fixture(t)
	rec := f.post(t, "/r/claudecode"+sigv4FlowARN, "hello", func(r *http.Request) {
		r.Header.Set("Authorization", "AWS4-HMAC-SHA256 Credential=AKIDAGENT/20261112/us-east-1/bedrock/aws4_request, SignedHeaders=host;x-amz-date, Signature=00")
	})
	if rec.Code != http.StatusBadRequest || !strings.Contains(rec.Body.String(), "CLAUDE_CODE_SKIP_BEDROCK_AUTH") || len(f.orig)+len(f.alt) != 0 {
		t.Fatalf("status %d body %s upstream hits %d", rec.Code, rec.Body.String(), len(f.orig)+len(f.alt))
	}
}

func TestRouteOnlySigV4MissingCredentialIsAProviderError(t *testing.T) {
	f := newSigV4Fixture(t)
	t.Setenv("DC_SIGV4_FLOW_SK", "")
	rec := f.post(t, "/r/claudecode"+sigv4FlowARN, "hello", nil)
	if rec.Code != http.StatusBadGateway || !strings.Contains(rec.Body.String(), "gateway Bedrock signing failed") || len(f.orig) != 0 {
		t.Fatalf("status %d body %s", rec.Code, rec.Body.String())
	}
	if strings.Contains(rec.Body.String(), "DC_SIGV4_FLOW") {
		t.Fatal("the answer names gateway environment variables")
	}
}

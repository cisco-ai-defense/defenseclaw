package gateway

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// GAP-2213: an intercepted GET (OpenClaw model list, Ollama /api/tags)
// reaches its X-DC-Target-URL instead of getting an empty 200, and a GET to
// an unknown host is refused with a JSON error.
func TestPassthroughGETForwardsToKnownTarget(t *testing.T) {
	var gotAuth, gotQuery string
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet || r.URL.Path != "/api/v1/models" {
			t.Errorf("upstream got %s %s", r.Method, r.URL.Path)
		}
		gotAuth, gotQuery = r.Header.Get("Authorization"), r.URL.RawQuery
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"data":[{"id":"m1"}]}`))
	}))
	defer upstream.Close()
	proxy := newForwardingProxy(t, upstream.URL)

	get := func(target string) *httptest.ResponseRecorder {
		req := httptest.NewRequest(http.MethodGet, "/api/v1/models?x=1", nil)
		req.Header.Set("X-DC-Target-URL", target)
		req.Header.Set("X-AI-Auth", "Bearer sk-upstream")
		rec := httptest.NewRecorder()
		proxy.handlePassthrough(rec, req)
		return rec
	}

	rec := get(upstream.URL)
	if rec.Code != http.StatusOK || rec.Body.String() != `{"data":[{"id":"m1"}]}` {
		t.Fatalf("GET passthrough = %d %q, want the upstream body", rec.Code, rec.Body.String())
	}
	if gotAuth != "Bearer sk-upstream" || gotQuery != "x=1" {
		t.Fatalf("upstream auth=%q query=%q", gotAuth, gotQuery)
	}

	rec = get("https://unknown.invalid")
	if rec.Code != http.StatusForbidden || !strings.Contains(rec.Body.String(), "known LLM provider") {
		t.Fatalf("GET to an unknown host = %d %q, want 403 with a JSON error", rec.Code, rec.Body.String())
	}

	// A bare GET without a target (health probe) still answers 200.
	probe := httptest.NewRecorder()
	proxy.handlePassthrough(probe, httptest.NewRequest(http.MethodGet, "/", nil))
	if probe.Code != http.StatusOK {
		t.Fatalf("health probe = %d, want 200", probe.Code)
	}
}

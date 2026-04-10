package connector

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

// stubConnector is a test double that matches when detectFn returns true.
type stubConnector struct {
	name     string
	detectFn func(r *http.Request) bool
	authOK   bool
}

func (s *stubConnector) Name() string                  { return s.name }
func (s *stubConnector) Detect(r *http.Request) bool   { return s.detectFn(r) }
func (s *stubConnector) Authenticate(*http.Request) bool { return s.authOK }
func (s *stubConnector) Route(*http.Request, []byte) (*RoutingDecision, error) {
	return &RoutingDecision{ConnectorName: s.name}, nil
}

func TestRouterResolveFirstMatch(t *testing.T) {
	first := &stubConnector{name: "first", detectFn: func(*http.Request) bool { return true }}
	second := &stubConnector{name: "second", detectFn: func(*http.Request) bool { return true }}

	router := NewRouter(first, second)
	req := httptest.NewRequest(http.MethodPost, "/v1/chat/completions", nil)

	got := router.Resolve(req)
	if got == nil || got.Name() != "first" {
		t.Fatalf("expected first connector, got %v", got)
	}
}

func TestRouterResolveFallback(t *testing.T) {
	never := &stubConnector{name: "never", detectFn: func(*http.Request) bool { return false }}
	fallback := &stubConnector{name: "fallback", detectFn: func(*http.Request) bool { return true }}

	router := NewRouter(never)
	router.SetFallback(fallback)
	req := httptest.NewRequest(http.MethodPost, "/v1/chat/completions", nil)

	got := router.Resolve(req)
	if got == nil || got.Name() != "fallback" {
		t.Fatalf("expected fallback connector, got %v", got)
	}
}

func TestRouterResolveNilWhenEmpty(t *testing.T) {
	router := NewRouter()
	req := httptest.NewRequest(http.MethodPost, "/v1/chat/completions", nil)

	got := router.Resolve(req)
	if got != nil {
		t.Fatalf("expected nil, got %v", got.Name())
	}
}

func TestRouterResolveSkipsNonMatching(t *testing.T) {
	noMatch := &stubConnector{name: "nope", detectFn: func(*http.Request) bool { return false }}
	match := &stubConnector{name: "yes", detectFn: func(*http.Request) bool { return true }}

	router := NewRouter(noMatch, match)
	req := httptest.NewRequest(http.MethodPost, "/v1/chat/completions", nil)

	got := router.Resolve(req)
	if got == nil || got.Name() != "yes" {
		t.Fatalf("expected 'yes' connector, got %v", got)
	}
}

func TestRouterConnectorNames(t *testing.T) {
	a := &stubConnector{name: "openclaw", detectFn: func(*http.Request) bool { return false }}
	b := &stubConnector{name: "zeptoclaw", detectFn: func(*http.Request) bool { return false }}
	fb := &stubConnector{name: "generic", detectFn: func(*http.Request) bool { return true }}

	router := NewRouter(a, b)
	router.SetFallback(fb)

	names := router.ConnectorNames()
	if len(names) != 3 {
		t.Fatalf("expected 3 names, got %d: %v", len(names), names)
	}
	if names[0] != "openclaw" || names[1] != "zeptoclaw" || names[2] != "generic (fallback)" {
		t.Fatalf("unexpected names: %v", names)
	}
}

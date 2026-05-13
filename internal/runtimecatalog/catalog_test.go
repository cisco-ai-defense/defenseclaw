package runtimecatalog

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestStaticCatalogExactAndPrefixLookup(t *testing.T) {
	cat := NewStaticCatalog([]Entry{{ResourceID: "api:/reports", Owner: "finance", SensitivityDomain: "finance"}})
	got, err := cat.Lookup(context.Background(), "api", "/reports/q4")
	if err != nil {
		t.Fatalf("lookup: %v", err)
	}
	if got.Owner != "finance" || got.SensitivityDomain != "finance" {
		t.Fatalf("unexpected entry: %+v", got)
	}
}

func TestLoadStaticCatalogWrapped(t *testing.T) {
	cat, err := LoadStaticCatalog([]byte(`{"resources":[{"resource_type":"database","resource_path":"customers","pii_fields":["email"]}]}`))
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	got, err := cat.Lookup(context.Background(), "database", "customers")
	if err != nil {
		t.Fatalf("lookup: %v", err)
	}
	if got.ResourceID != "database:customers" || got.PIIFields[0] != "email" {
		t.Fatalf("unexpected entry: %+v", got)
	}
}

func TestInferResourceFromToolInput(t *testing.T) {
	got := InferResource("sql.query", map[string]any{"query": "select * from customers where id = 1"})
	if got.ID != "database:customers" {
		t.Fatalf("unexpected SQL resource: %+v", got)
	}
	got = InferResource("http.get", map[string]any{"url": "https://example.test/reports/q4?x=1"})
	if got.ID != "api:/reports/q4" {
		t.Fatalf("unexpected URL resource: %+v", got)
	}
}

func TestHTTPClientLookup(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("resource_type") != "api" || r.URL.Query().Get("resource_path") != "/reports" {
			t.Fatalf("unexpected query: %s", r.URL.RawQuery)
		}
		_, _ = w.Write([]byte(`{"resource_id":"api:/reports","owner":"platform"}`))
	}))
	defer srv.Close()
	got, err := NewHTTPClient(srv.URL).Lookup(context.Background(), "api", "/reports")
	if err != nil {
		t.Fatalf("lookup: %v", err)
	}
	if got.Owner != "platform" || got.ResourceType != "api" {
		t.Fatalf("unexpected entry: %+v", got)
	}
}

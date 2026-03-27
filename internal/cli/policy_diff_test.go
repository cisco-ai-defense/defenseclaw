package cli

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func TestDiscoverRequiredEndpoints_WithChannels(t *testing.T) {
	dir := t.TempDir()
	cfg := map[string]interface{}{
		"channels": map[string]interface{}{
			"slack":    map[string]interface{}{},
			"telegram": map[string]interface{}{},
		},
	}
	p := writeJSON(t, dir, cfg)

	eps := discoverRequiredEndpoints(p)

	// slack has 2 endpoints, telegram has 1
	if len(eps) != 3 {
		t.Fatalf("expected 3 endpoints, got %d: %+v", len(eps), eps)
	}

	hosts := map[string]bool{}
	for _, ep := range eps {
		hosts[ep.Host] = true
	}
	for _, want := range []string{"**.slack.com", "hooks.slack.com", "**.telegram.org"} {
		if !hosts[want] {
			t.Errorf("missing expected host %q", want)
		}
	}
}

func TestDiscoverRequiredEndpoints_WithProviders(t *testing.T) {
	dir := t.TempDir()
	cfg := map[string]interface{}{
		"models": map[string]interface{}{
			"providers": map[string]interface{}{
				"openai": map[string]interface{}{
					"baseUrl": "https://api.openai.com/v1",
				},
			},
		},
	}
	p := writeJSON(t, dir, cfg)

	eps := discoverRequiredEndpoints(p)

	if len(eps) != 1 {
		t.Fatalf("expected 1 endpoint, got %d: %+v", len(eps), eps)
	}
	if eps[0].Host != "api.openai.com" {
		t.Errorf("expected host api.openai.com, got %q", eps[0].Host)
	}
	if eps[0].Port != 443 {
		t.Errorf("expected port 443, got %d", eps[0].Port)
	}
}

func TestDiscoverRequiredEndpoints_SkipsLiteLLM(t *testing.T) {
	dir := t.TempDir()
	cfg := map[string]interface{}{
		"models": map[string]interface{}{
			"providers": map[string]interface{}{
				"litellm": map[string]interface{}{
					"baseUrl": "http://127.0.0.1:4000",
				},
			},
		},
	}
	p := writeJSON(t, dir, cfg)

	eps := discoverRequiredEndpoints(p)

	if len(eps) != 0 {
		t.Fatalf("expected 0 endpoints for litellm, got %d: %+v", len(eps), eps)
	}
}

func TestDiscoverRequiredEndpoints_SkipsLocalhost(t *testing.T) {
	dir := t.TempDir()
	cfg := map[string]interface{}{
		"models": map[string]interface{}{
			"providers": map[string]interface{}{
				"local": map[string]interface{}{
					"baseUrl": "http://localhost:8080/api",
				},
			},
		},
	}
	p := writeJSON(t, dir, cfg)

	eps := discoverRequiredEndpoints(p)

	if len(eps) != 0 {
		t.Fatalf("expected 0 endpoints for localhost, got %d: %+v", len(eps), eps)
	}
}

func TestDiscoverRequiredEndpoints_MissingFile(t *testing.T) {
	eps := discoverRequiredEndpoints("/nonexistent/path/openclaw.json")

	if eps != nil {
		t.Fatalf("expected nil for missing file, got %+v", eps)
	}
}

func TestDiscoverRequiredEndpoints_EmptyJSON(t *testing.T) {
	dir := t.TempDir()
	p := writeJSON(t, dir, map[string]interface{}{})

	eps := discoverRequiredEndpoints(p)

	if len(eps) != 0 {
		t.Fatalf("expected 0 endpoints for empty JSON, got %d: %+v", len(eps), eps)
	}
}

func TestDiscoverRequiredEndpoints_Mixed(t *testing.T) {
	dir := t.TempDir()
	cfg := map[string]interface{}{
		"channels": map[string]interface{}{
			"discord": map[string]interface{}{},
		},
		"models": map[string]interface{}{
			"providers": map[string]interface{}{
				"anthropic": map[string]interface{}{
					"baseUrl": "https://api.anthropic.com/v1",
				},
			},
		},
	}
	p := writeJSON(t, dir, cfg)

	eps := discoverRequiredEndpoints(p)

	// discord has 2 endpoints + 1 provider endpoint = 3
	if len(eps) != 3 {
		t.Fatalf("expected 3 endpoints, got %d: %+v", len(eps), eps)
	}

	sources := map[string]bool{}
	for _, ep := range eps {
		sources[ep.Source] = true
	}
	if !sources["channel:discord"] {
		t.Error("missing channel:discord source")
	}
	if !sources["provider:anthropic"] {
		t.Error("missing provider:anthropic source")
	}
}

func writeJSON(t *testing.T, dir string, v interface{}) string {
	t.Helper()
	data, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	p := filepath.Join(dir, "openclaw.json")
	if err := os.WriteFile(p, data, 0644); err != nil {
		t.Fatal(err)
	}
	return p
}

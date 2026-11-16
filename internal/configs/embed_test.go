package configs

import (
	"reflect"
	"testing"
)

func TestApplyOverlayMergesRequestOverrides(t *testing.T) {
	base := &ProvidersConfig{
		Providers: []Provider{
			{
				Name:    "vllm",
				Domains: []string{"vllm.local"},
				EnvKeys: []string{"OLD_VLLM_KEY"},
				RequestOverrides: map[string]interface{}{
					"chat_template_kwargs": map[string]interface{}{
						"enable_thinking": true,
						"keep":            "yes",
					},
				},
			},
		},
	}

	overlay := ProvidersConfig{
		Providers: []Provider{
			{
				Name:    "VLLM",
				Domains: []string{"192.168.160.113"},
				EnvKeys: []string{"VLLM_API_KEY"},
				RequestOverrides: map[string]interface{}{
					"chat_template_kwargs": map[string]interface{}{
						"enable_thinking": false,
					},
					"metadata": map[string]interface{}{
						"source": "defenseclaw",
					},
				},
			},
		},
	}

	ApplyOverlay(base, overlay)

	if len(base.Providers) != 1 {
		t.Fatalf("expected one merged provider, got %d", len(base.Providers))
	}

	got := base.Providers[0]

	if !containsString(got.Domains, "vllm.local") {
		t.Fatalf("expected original domain to remain, got %#v", got.Domains)
	}
	if !containsString(got.Domains, "192.168.160.113") {
		t.Fatalf("expected overlay domain to be merged, got %#v", got.Domains)
	}
	if !containsString(got.EnvKeys, "OLD_VLLM_KEY") || !containsString(got.EnvKeys, "VLLM_API_KEY") {
		t.Fatalf("expected env keys to be merged, got %#v", got.EnvKeys)
	}

	kwargs, ok := got.RequestOverrides["chat_template_kwargs"].(map[string]interface{})
	if !ok {
		t.Fatalf("expected chat_template_kwargs override, got %#v", got.RequestOverrides)
	}

	if kwargs["enable_thinking"] != false {
		t.Fatalf("expected overlay to override enable_thinking=false, got %#v", kwargs["enable_thinking"])
	}
	if kwargs["keep"] != "yes" {
		t.Fatalf("expected nested base value to be preserved, got %#v", kwargs["keep"])
	}

	metadata, ok := got.RequestOverrides["metadata"].(map[string]interface{})
	if !ok {
		t.Fatalf("expected metadata override, got %#v", got.RequestOverrides)
	}
	if metadata["source"] != "defenseclaw" {
		t.Fatalf("expected metadata.source to be defenseclaw, got %#v", metadata["source"])
	}
}

// GAP-0361 (#1099): a same-name entry (an llm_providers.custom provider
// named like a built-in, or a provider named twice) keeps every field it
// sets. The merge kept request_path_overrides but dropped extra_headers.
func TestApplyOverlayKeepsEverySameNameField(t *testing.T) {
	profile := "team"
	base := &ProvidersConfig{Providers: []Provider{{
		Name: "openai", Domains: []string{"api.openai.com"}, EnvKeys: []string{"OPENAI_API_KEY"},
		RequestPathOverrides: map[string]string{"embedding": "/v1/embeddings"},
		ExtraHeaders:         map[string]string{"x-keep": "base"},
	}}}
	first := Provider{
		Name: "OpenAI", Domains: []string{"llm.team.internal"}, ProfileID: &profile, EnvKeys: []string{"TEAM_KEY"},
		BaseProviderType: "openai", BaseURL: "https://llm.team.internal/v1",
		AllowedRequests: []string{"chat"}, AvailableModels: []string{"team-small"},
		RequestPathOverrides: map[string]string{"chat": "/team/chat"},
		ExtraHeaders:         map[string]string{"x-team": "sec", "x-keep": "first"},
		TLS:                  &ProviderTLS{CACertPEM: "certificate"},
		Bedrock:              &ProviderBedrock{Region: "us-east-1", DeploymentAliases: map[string]string{"a": "b"}},
		Vertex:               &ProviderVertex{ProjectID: "p", Region: "r"},
		Azure:                &ProviderAzure{Endpoint: "https://a.example", APIVersion: "2026-01-01"},
	}
	second := Provider{
		Name: "openai", AllowedRequests: []string{"responses"}, AvailableModels: []string{"team-large"},
		ExtraHeaders: map[string]string{"x-team": "platform", "x-route": "eu"},
	}
	firstHeaders := map[string]string{"x-team": "sec", "x-keep": "first"}
	ApplyOverlay(base, ProvidersConfig{Providers: []Provider{first, second}})

	if len(base.Providers) != 1 {
		t.Fatalf("providers = %d, want one merged entry", len(base.Providers))
	}
	want := Provider{
		Name: "openai", Domains: []string{"api.openai.com", "llm.team.internal"}, ProfileID: &profile,
		EnvKeys: []string{"OPENAI_API_KEY", "TEAM_KEY"}, BaseProviderType: "openai", BaseURL: "https://llm.team.internal/v1",
		AllowedRequests: []string{"chat", "responses"}, AvailableModels: []string{"team-small", "team-large"},
		RequestPathOverrides: map[string]string{"embedding": "/v1/embeddings", "chat": "/team/chat"},
		ExtraHeaders:         map[string]string{"x-keep": "first", "x-team": "platform", "x-route": "eu"},
		TLS:                  first.TLS, Bedrock: first.Bedrock, Vertex: first.Vertex, Azure: first.Azure,
	}
	if got := base.Providers[0]; !reflect.DeepEqual(got, want) {
		t.Fatalf("merged provider =\n  %+v\nwant\n  %+v", got, want)
	}
	// The overlay's own maps are not written by the merge.
	if !reflect.DeepEqual(first.ExtraHeaders, firstHeaders) || len(first.RequestPathOverrides) != 1 {
		t.Fatalf("the merge changed the overlay entry: headers %v, paths %v", first.ExtraHeaders, first.RequestPathOverrides)
	}
}

func containsString(values []string, want string) bool {
	for _, value := range values {
		if value == want {
			return true
		}
	}
	return false
}

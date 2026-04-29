package configs

import "testing"

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

	applyOverlay(base, overlay)

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

func containsString(values []string, want string) bool {
	for _, value := range values {
		if value == want {
			return true
		}
	}
	return false
}

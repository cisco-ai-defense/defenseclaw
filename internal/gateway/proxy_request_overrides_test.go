package gateway

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func withCustomProvidersPath(t *testing.T, overlayPath string) {
	t.Helper()

	oldValue, hadOldValue := os.LookupEnv("DEFENSECLAW_CUSTOM_PROVIDERS_PATH")

	if err := os.Setenv("DEFENSECLAW_CUSTOM_PROVIDERS_PATH", overlayPath); err != nil {
		t.Fatalf("set DEFENSECLAW_CUSTOM_PROVIDERS_PATH: %v", err)
	}

	if err := ReloadProviderRegistry(); err != nil {
		t.Fatalf("reload provider registry with test overlay: %v", err)
	}

	t.Cleanup(func() {
		if hadOldValue {
			_ = os.Setenv("DEFENSECLAW_CUSTOM_PROVIDERS_PATH", oldValue)
		} else {
			_ = os.Unsetenv("DEFENSECLAW_CUSTOM_PROVIDERS_PATH")
		}

		if err := ReloadProviderRegistry(); err != nil {
			t.Fatalf("restore provider registry: %v", err)
		}
	})
}

func TestApplyProviderRequestOverridesForCustomVLLMProvider(t *testing.T) {
	dir := t.TempDir()
	overlayPath := filepath.Join(dir, "custom-providers.json")

	overlay := []byte(`{
	  "providers": [
	    {
	      "name": "vllm",
	      "domains": ["192.168.160.113"],
	      "env_keys": ["VLLM_API_KEY"],
	      "request_overrides": {
	        "chat_template_kwargs": {
	          "enable_thinking": false
	        },
	        "metadata": {
	          "source": "defenseclaw"
	        }
	      }
	    }
	  ],
	  "ollama_ports": []
	}`)

	if err := os.WriteFile(overlayPath, overlay, 0o600); err != nil {
		t.Fatalf("write overlay: %v", err)
	}

	withCustomProvidersPath(t, overlayPath)

	body := []byte(`{
	  "model": "Qwen/Qwen3-14B-FP8",
	  "messages": [{"role": "user", "content": "Reply with only OK."}],
	  "chat_template_kwargs": {
	    "existing": true
	  }
	}`)

	got := applyProviderRequestOverrides(body, "http://192.168.160.113:30080/v1/chat/completions")

	var parsed map[string]interface{}
	if err := json.Unmarshal(got, &parsed); err != nil {
		t.Fatalf("unmarshal patched body: %v\nbody=%s", err, string(got))
	}

	kwargs, ok := parsed["chat_template_kwargs"].(map[string]interface{})
	if !ok {
		t.Fatalf("expected chat_template_kwargs to be present, got %#v", parsed)
	}

	if kwargs["existing"] != true {
		t.Fatalf("expected existing nested value to be preserved, got %#v", kwargs["existing"])
	}
	if kwargs["enable_thinking"] != false {
		t.Fatalf("expected enable_thinking=false override, got %#v", kwargs["enable_thinking"])
	}

	metadata, ok := parsed["metadata"].(map[string]interface{})
	if !ok {
		t.Fatalf("expected metadata override, got %#v", parsed)
	}
	if metadata["source"] != "defenseclaw" {
		t.Fatalf("expected metadata.source=defenseclaw, got %#v", metadata["source"])
	}
}

func TestApplyProviderRequestOverridesIgnoresUnmatchedProvider(t *testing.T) {
	dir := t.TempDir()
	overlayPath := filepath.Join(dir, "custom-providers.json")

	overlay := []byte(`{
	  "providers": [
	    {
	      "name": "vllm",
	      "domains": ["192.168.160.113"],
	      "env_keys": ["VLLM_API_KEY"],
	      "request_overrides": {
	        "chat_template_kwargs": {
	          "enable_thinking": false
	        }
	      }
	    }
	  ],
	  "ollama_ports": []
	}`)

	if err := os.WriteFile(overlayPath, overlay, 0o600); err != nil {
		t.Fatalf("write overlay: %v", err)
	}

	withCustomProvidersPath(t, overlayPath)

	body := []byte(`{
	  "model": "gpt-4o",
	  "messages": [{"role": "user", "content": "Reply with only OK."}]
	}`)

	got := applyProviderRequestOverrides(body, "https://api.openai.com/v1/chat/completions")

	var parsed map[string]interface{}
	if err := json.Unmarshal(got, &parsed); err != nil {
		t.Fatalf("unmarshal body: %v", err)
	}

	if _, ok := parsed["chat_template_kwargs"]; ok {
		t.Fatalf("did not expect overrides for unmatched provider, got %#v", parsed["chat_template_kwargs"])
	}
}

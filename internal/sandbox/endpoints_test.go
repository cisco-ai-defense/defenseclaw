package sandbox

import "testing"

func TestKnownChannelEndpoints(t *testing.T) {
	channels := []string{"telegram", "slack", "discord"}
	for _, ch := range channels {
		eps, ok := KnownChannelEndpoints[ch]
		if !ok {
			t.Errorf("missing channel %q in KnownChannelEndpoints", ch)
			continue
		}
		if len(eps) == 0 {
			t.Errorf("channel %q has no endpoints", ch)
		}
		for _, ep := range eps {
			if ep.Host == "" {
				t.Errorf("channel %q has endpoint with empty host", ch)
			}
			if ep.Port == 0 {
				t.Errorf("channel %q has endpoint with zero port", ch)
			}
		}
	}
}

func TestKnownLLMProviderEndpoints(t *testing.T) {
	providers := []string{"openai", "anthropic", "google"}
	for _, p := range providers {
		eps, ok := KnownLLMProviderEndpoints[p]
		if !ok {
			t.Errorf("missing provider %q in KnownLLMProviderEndpoints", p)
			continue
		}
		if len(eps) == 0 {
			t.Errorf("provider %q has no endpoints", p)
		}
	}
}

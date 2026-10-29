package config

import (
	"bytes"
	"log"
	"strings"
	"testing"
)

// GAP-2234: provider "custom" with a bound instance is a documented
// setup and must not log the unknown-provider warning; without an
// instance it still warns and names the llm block.
func TestCustomProviderWithInstanceIsNotAnUnknownPrefix(t *testing.T) {
	var buf bytes.Buffer
	prevOut, prevFlags := log.Writer(), log.Flags()
	log.SetOutput(&buf)
	log.SetFlags(0)
	t.Cleanup(func() { log.SetOutput(prevOut); log.SetFlags(prevFlags) })
	for k := range warnedPrefixes {
		delete(warnedPrefixes, k)
	}

	c := &Config{LLM: LLMConfig{Provider: "custom", Model: "heavy", InstanceName: "acme-bedrock-prod"}}
	_ = c.ResolveLLM("")
	if strings.Contains(buf.String(), "unknown LLM provider prefix") {
		t.Fatalf("bound custom instance warned: %q", buf.String())
	}

	maybeWarnUnknownProvider("custom", "", "")
	got := buf.String()
	if strings.Count(got, "unknown LLM provider prefix") != 1 || !strings.Contains(got, `"custom" for llm`) {
		t.Fatalf("custom without an instance must warn once naming llm, got %q", got)
	}
}

// GAP-2379: a role override that names another provider and no instance
// does not inherit the top-level custom instance (the overlay would route
// the role to it); provider custom or no provider still inherits it.
func TestRoleWithItsOwnProviderDoesNotInheritTheCustomInstance(t *testing.T) {
	c := &Config{LLM: LLMConfig{Provider: "custom", Model: "heavy", InstanceName: "acme-bedrock-prod"}}
	c.Guardrail.Judge.LLM = LLMConfig{Provider: "anthropic", Model: "claude-sonnet-4-5"}
	if got := c.ResolveLLM("guardrail.judge").InstanceName; got != "" {
		t.Fatalf("anthropic judge inherited instance %q", got)
	}
	c.Guardrail.Judge.LLM.Provider = "custom"
	if got := c.ResolveLLM("guardrail.judge").InstanceName; got != "acme-bedrock-prod" {
		t.Fatalf("custom judge: got %q, want the inherited instance", got)
	}
	c.Guardrail.Judge.LLM.Provider = ""
	if got := c.ResolveLLM("guardrail.judge").InstanceName; got != "acme-bedrock-prod" {
		t.Fatalf("judge without a provider: got %q, want the inherited instance", got)
	}
	c.Guardrail.Judge.LLM = LLMConfig{Provider: "bedrock", Model: "m", InstanceName: "acme-other"}
	if got := c.ResolveLLM("guardrail.judge").InstanceName; got != "acme-other" {
		t.Fatalf("judge with its own instance: got %q", got)
	}
}

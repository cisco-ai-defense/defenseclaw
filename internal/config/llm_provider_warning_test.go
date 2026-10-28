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

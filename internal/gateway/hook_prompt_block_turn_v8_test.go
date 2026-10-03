// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// GAP-2485: a hook connector's blocked prompt never reaches the model, so no
// Stop ends its turn. The block ends it: Galileo gets the turn's agent and
// chat spans with the rule, severity and blocked outcome in their metadata.
func TestHookBlockedPromptEndsTheTurnWithTheBlockOnGalileo(t *testing.T) {
	galileo := &hookModelV8OTLPCapture{}
	galileoServer := httptest.NewServer(http.HandlerFunc(galileo.handler))
	t.Cleanup(galileoServer.Close)
	otlp := &hookModelV8OTLPCapture{}
	otlpServer := httptest.NewServer(http.HandlerFunc(otlp.handler))
	t.Cleanup(otlpServer.Close)
	fixture := newSidecarV8BootstrapFixture(t, 8, "")
	api := &APIServer{}
	fixture.sidecar.setAPIServer(api)
	raw := append(hookModelV8BootstrapRaw(fixture.dataDir, otlpServer.URL, []string{"traces"}), fmt.Sprintf(
		"    - name: hook-galileo\n      kind: otlp\n      preset: galileo\n      endpoint: %q\n      protocol: http/protobuf\n"+
			"      tls:\n        insecure: true\n      network_safety:\n        allow_private_networks: true\n"+
			"      batch:\n        max_export_batch_size: 16\n        scheduled_delay_ms: 10\n", galileoServer.URL)...)
	if bound, err := fixture.sidecar.BootstrapObservabilityRuntime(t.Context(), fixture.configPath, raw); err != nil || !bound {
		t.Fatalf("bootstrap bound=%t error=%v", bound, err)
	}

	meta := richHookModelV8Meta()
	meta.Source, meta.Provider, meta.Model = "claudecode", "anthropic", "claude-haiku-4-5"
	meta.UserID, meta.UserIDKind, meta.UserName = "1002", "posix_uid", "bob"
	ctx := withHookToolCallCapture(t.Context(), &hookToolCallCapture{})
	api.rememberHookLLMSpanPrompt(meta, "Reply with one word: ok. Reference dccert-prompt-marker")
	captureHookPrompt(ctx, meta)
	api.emitHookGuardrailOutcomeV8(ctx,
		agentHookRequest{ConnectorName: "claudecode", HookEventName: "UserPromptSubmit", SessionID: meta.SessionID},
		agentHookResponse{
			Action: "block", Severity: "CRITICAL", RuleIDs: []string{"R6-PROMPT-MARKER"},
			Reason: "DefenseClaw policy blocked this action (rule R6-PROMPT-MARKER)",
		}, time.Millisecond)

	found := map[string]map[string]string{}
	for deadline := time.Now().Add(3 * time.Second); len(found) < 2 && time.Now().Before(deadline); {
		for _, span := range hookModelV8CapturedSpansFromCapture(galileo) {
			for _, prefix := range []string{"invoke_agent", "chat"} {
				if strings.HasPrefix(span.Name, prefix) {
					found[prefix] = hookModelV8ProtoAttributes(span)
				}
			}
		}
		time.Sleep(10 * time.Millisecond)
	}
	for _, prefix := range []string{"invoke_agent", "chat"} {
		metadata := found[prefix]["metadata"]
		for _, want := range []string{
			`"defenseclaw.guardrail.action":"block"`, `"defenseclaw.guardrail.rule_id":"R6-PROMPT-MARKER"`,
			`"defenseclaw.guardrail.severity":"CRITICAL"`, `"defenseclaw.outcome":"blocked"`, `"defenseclaw.user.name":"bob"`,
		} {
			if !strings.Contains(metadata, want) {
				t.Errorf("galileo %s span metadata=%q, want %s", prefix, metadata, want)
			}
		}
	}
}

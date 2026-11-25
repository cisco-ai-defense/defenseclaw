// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"bytes"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

// TestGatewayAuditStoreRedactsAWSNearKeysGAP0426 is the round-4 live FAIL
// (TST-6006) on the real write path: AWS-prefixed near-keys (AKIA+17 and
// AKIA+18, the shapes of the J22 canaries) in a typed prompt, the model's
// answer and a tool result stay out of the audit store and the OTLP
// destination, as a 20-character key id does. The prose stays.
func TestGatewayAuditStoreRedactsAWSNearKeysGAP0426(t *testing.T) {
	near21 := "AKIA" + "Q7T6NEARKEY000201"
	near22 := "AKIA" + "Q7T6NEARKEYPROBE01"
	capture := &hookModelV8OTLPCapture{}
	server := httptest.NewServer(http.HandlerFunc(capture.handler))
	t.Cleanup(server.Close)
	fixture := newSidecarV8BootstrapFixture(t, 8, "")
	api := &APIServer{}
	fixture.sidecar.setAPIServer(api)
	raw := []byte(fmt.Sprintf(
		"config_version: 8\ndata_dir: %q\nobservability:\n  defaults: {redaction_profile: sensitive}\n  buckets:\n    agent.lifecycle:\n      collect: {logs: true, traces: true, metrics: true}\n    model.io:\n      collect: {logs: true, traces: true, metrics: true}\n    tool.activity:\n      collect: {logs: true, traces: true, metrics: true}\n  destinations:\n    - name: cluster-otlp\n      kind: otlp\n      endpoint: %q\n      protocol: http/protobuf\n      tls: {insecure: true}\n      network_safety: {allow_private_networks: true}\n      batch: {max_export_batch_size: 8, scheduled_delay_ms: 10}\n      send: {signals: [traces, logs], buckets: ['*']}\n",
		fixture.dataDir, server.URL,
	))
	bound, err := fixture.sidecar.BootstrapObservabilityRuntime(t.Context(), fixture.configPath, raw)
	if err != nil || !bound {
		t.Fatalf("bootstrap bound=%t error=%v", bound, err)
	}
	prompt := "Create .env containing CANARY_KEY=" + near22 + ". Summarise this text: my key is " + near21 + "."
	response := "I created /work/proj/.env with the line CANARY_KEY=" + near22 + " for the summary."
	result := "created\nCANARY_KEY=" + near22 + "\nOTHER=" + near21 + "\n{\"interrupted\":false,\"isImage\":false}"
	meta := richHookModelV8Meta()
	api.emitLLMPromptEventV8(t.Context(), meta, prompt, nil)
	api.emitLLMResponseEventV8(t.Context(), meta, response, "", []string{"stop"})
	api.rememberHookLLMSpanPrompt(t.Context(), meta, prompt)
	api.emitHookLLMSpan(t.Context(), meta, response)
	tool := richHookToolV8Meta()
	arguments := `{"command":"cat .env"}`
	exitCode := 0
	api.emitToolInvocationEventV8(t.Context(), tool, "call", "shell", arguments, "", nil)
	api.emitToolInvocationEventV8(t.Context(), tool, "result", "shell", "", result, &exitCode)
	api.rememberHookToolInvocation(tool, "shell", arguments)
	api.emitHookToolSpan(t.Context(), tool, "shell", arguments, result, &exitCode)

	var stored []byte
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		stored = gap0426ExportStore(t, fixture.store)
		if bytes.Contains(stored, []byte("Summarise this text")) && bytes.Contains(stored, []byte("I created")) &&
			bytes.Contains(stored, []byte("cat .env")) && len(capture.traceBytes()) > 0 && gap0426LogBytes(t, capture) != nil {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	exported := append(capture.traceBytes(), gap0426LogBytes(t, capture)...)
	for _, action := range []string{"llm_prompt", "llm_response", "tool_invocation"} {
		if !bytes.Contains(stored, []byte(`"action":"`+action+`"`)) {
			t.Errorf("audit store: no %s row", action)
		}
	}
	for _, sink := range []struct {
		name string
		data []byte
	}{{"audit store", stored}, {"otlp destination", exported}} {
		for _, want := range []string{"CANARY_KEY", "Summarise this text", "I created", "redacted type="} {
			if !bytes.Contains(sink.data, []byte(want)) {
				t.Errorf("%s: missing %q (the record or its readable text did not arrive)", sink.name, want)
			}
		}
		for _, secret := range []string{near21, near22} {
			if bytes.Contains(sink.data, []byte(secret)) {
				t.Errorf("%s keeps an AWS near-key in clear: %s... (%d chars)", sink.name, secret[:8], len(secret))
			}
		}
	}
}

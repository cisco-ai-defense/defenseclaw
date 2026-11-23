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

// TestProxyAuditRowsRedactFlaggedSecretsGAP0426: the proxied model path, non
// streaming and streaming, writes its llm_prompt and llm_response records
// through the same bootstrap engine; no GAP-0426 secret shape reaches the
// audit store or the destination.
func TestProxyAuditRowsRedactFlaggedSecretsGAP0426(t *testing.T) {
	answer := "Saved SERVICE_API_TOKEN=" + gap0426Hex + " and CANARY_BEARER=" + gap0426Bearer + " to .env4"
	prompt := "Create .env4 with SERVICE_API_TOKEN=" + gap0426Hex + " and CANARY_BEARER=" + gap0426Bearer +
		`, then curl -H "Authorization: Bearer ` + gap0426Header + `" https://example.com/; my password is ` +
		gap0426Password + " and my key is " + gap0426AWS
	for _, stream := range []bool{false, true} {
		t.Run(fmt.Sprintf("stream=%t", stream), func(t *testing.T) {
			capture := &hookModelV8OTLPCapture{}
			server := httptest.NewServer(http.HandlerFunc(capture.handler))
			t.Cleanup(server.Close)
			provider := &mockProvider{
				response: &ChatResponse{ID: "chatcmpl-gap0426", Model: "gpt-4", Choices: []ChatChoice{{
					Message: &ChatMessage{Role: "assistant", Content: answer}, FinishReason: strPtr("stop"),
				}}},
				streamChunks: []StreamChunk{
					{ID: "chatcmpl-gap0426", Model: "gpt-4", Choices: []ChatChoice{{Delta: &ChatMessage{Content: answer[:20]}}}},
					{ID: "chatcmpl-gap0426", Model: "gpt-4", Choices: []ChatChoice{{Delta: &ChatMessage{Content: answer[20:]}, FinishReason: strPtr("stop")}}},
				},
			}
			fixture := newSidecarV8BootstrapFixture(t, 8, "")
			proxy := newTestProxy(t, provider, newMockInspector(), "observe")
			proxy.SetDefaultAgentName("openclaw")
			fixture.sidecar.setGuardrailProxy(proxy)
			raw := []byte(fmt.Sprintf(
				"config_version: 8\ndata_dir: %q\nobservability:\n  defaults: {redaction_profile: sensitive}\n  buckets:\n    agent.lifecycle:\n      collect: {logs: true, traces: true, metrics: true}\n    model.io:\n      collect: {logs: true, traces: true, metrics: true}\n  destinations:\n    - name: cluster-otlp\n      kind: otlp\n      endpoint: %q\n      protocol: http/protobuf\n      tls: {insecure: true}\n      network_safety: {allow_private_networks: true}\n      batch: {max_export_batch_size: 8, scheduled_delay_ms: 10}\n      send: {signals: [traces, logs], buckets: ['*']}\n",
				fixture.dataDir, server.URL,
			))
			if bound, err := fixture.sidecar.BootstrapObservabilityRuntime(t.Context(), fixture.configPath, raw); err != nil || !bound {
				t.Fatalf("bootstrap bound=%t error=%v", bound, err)
			}
			recorder := postChat(t, proxy, mustJSON(t, map[string]any{
				"model": "gpt-4", "stream": stream,
				"messages": []map[string]any{{"role": "user", "content": prompt}},
			}))
			if recorder.Code != http.StatusOK {
				t.Fatalf("status=%d", recorder.Code)
			}
			var stored, exported []byte
			deadline := time.Now().Add(5 * time.Second)
			for time.Now().Before(deadline) {
				stored = gap0426ExportStore(t, fixture.store)
				exported = append(capture.traceBytes(), gap0426LogBytes(t, capture)...)
				if bytes.Contains(stored, []byte(`"action":"llm_prompt"`)) && bytes.Contains(stored, []byte(`"action":"llm_response"`)) &&
					bytes.Contains(exported, []byte("SERVICE_API_TOKEN")) {
					break
				}
				time.Sleep(20 * time.Millisecond)
			}
			for _, action := range []string{"llm_prompt", "llm_response"} {
				if !bytes.Contains(stored, []byte(`"action":"`+action+`"`)) {
					t.Errorf("audit store: no %s row", action)
				}
			}
			for _, sink := range []struct {
				name string
				data []byte
			}{{"audit store", stored}, {"otlp destination", exported}} {
				if !bytes.Contains(sink.data, []byte("SERVICE_API_TOKEN")) || !bytes.Contains(sink.data, []byte("redacted type=")) {
					t.Errorf("%s: the record or its readable key did not arrive", sink.name)
				}
				for _, secret := range gap0426Secrets()[:5] {
					if bytes.Contains(sink.data, []byte(secret)) {
						t.Errorf("%s keeps a secret in clear: %s...", sink.name, secret[:8])
					}
				}
			}
		})
	}
}

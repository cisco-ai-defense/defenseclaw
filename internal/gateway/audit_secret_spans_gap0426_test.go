// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"bytes"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/audit"
)

// GAP-0426 shapes (generated here, never the live canaries): a 40-hex value
// the hook flags HIGH (SEC-HEX-SECRET, SEC-SECRET-ASSIGN), an opaque bearer
// value in an env line and in an inline Authorization header, and the shapes
// the first fix already covered (a provider AWS key after '=', a password in
// prose, a JWT).
var (
	gap0426Hex      = "5c1e8a4f7b2d9e0361a7c4b8d2f05e9a3c6b1d47"
	gap0426Bearer   = "t6-aud-bearer-probe-4e8b1d"
	gap0426Header   = "t6-aud-header-probe-9c2f7e"
	gap0426AWS      = "AKIA" + "Z3Q7XK9M2P4W8R5T"
	gap0426Password = "Vq7-r2LmXp9w-audprobe"
	gap0426JWT      = "eyJhbGciOiJIUzI1NiJ9" + ".eyJzdWIiOiJhdWQwNDI2In0" + ".c2lnbmF0dXJlLWF1ZDA0MjY"
	// A git SHA outside a credential context: the guardrail classifier never
	// flags it (the unit test checks); secrets.high_entropy already redacts
	// a bare 40-hex in text at rel, so the store test does not assert it.
	gap0426SHA = "0123456789abcdef0123456789abcdef01234567"
)

func gap0426Secrets() []string {
	return []string{gap0426Hex, gap0426Bearer, gap0426Header, gap0426AWS, gap0426Password, gap0426JWT}
}

// TestGatewayAuditStoreRedactsFlaggedSecretsGAP0426 drives the real gateway
// write path with the chart's observability default (redaction_profile
// sensitive): the bootstrap engine, the hook model and tool producers, the
// local audit store (read back by the export `defenseclaw-gateway audit
// export` uses) and an OTLP destination. No secret shape may reach either, in
// the llm_prompt, llm_response or tool_invocation record; the env key names and the
// prose stay.
func TestGatewayAuditStoreRedactsFlaggedSecretsGAP0426(t *testing.T) {
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

	prompt := "Create a file .env4 containing SERVICE_API_TOKEN=" + gap0426Hex +
		" and CANARY_BEARER=" + gap0426Bearer + ". Then run: curl -sS -m 8 -H \"Authorization: Bearer " + gap0426Header +
		"\" https://example.com/ -o /dev/null. Summarise: my password is " + gap0426Password + " and my key is " + gap0426AWS +
		", session " + gap0426JWT + ". Ref commit " + gap0426SHA + "."
	response := "I created /work/proj/.env4 with the line SERVICE_API_TOKEN=" + gap0426Hex +
		" and CANARY_BEARER=" + gap0426Bearer + " (commit " + gap0426SHA + ")."
	result := "created\nSERVICE_API_TOKEN=" + gap0426Hex + "\nCANARY_BEARER=" + gap0426Bearer +
		"\nAWS_ACCESS_KEY_ID=" + gap0426AWS + "\n{\"interrupted\":false,\"isImage\":false}"

	// The hook model and tool records, as the Claude Code UserPromptSubmit,
	// Stop and PostToolUse produce them: the logs (the audit rows) and the
	// spans (the traces).
	meta := richHookModelV8Meta()
	api.emitLLMPromptEventV8(t.Context(), meta, prompt, nil)
	api.emitLLMResponseEventV8(t.Context(), meta, response, "", []string{"stop"})
	api.rememberHookLLMSpanPrompt(t.Context(), meta, prompt)
	api.emitHookLLMSpan(t.Context(), meta, response)
	tool := richHookToolV8Meta()
	arguments := `{"command":"curl -sS -H \"Authorization: Bearer ` + gap0426Header + `\" https://example.com/"}`
	exitCode := 0
	api.emitToolInvocationEventV8(t.Context(), tool, "call", "shell", arguments, "", nil)
	api.emitToolInvocationEventV8(t.Context(), tool, "result", "shell", "", result, &exitCode)
	api.rememberHookToolInvocation(tool, "shell", arguments)
	api.emitHookToolSpan(t.Context(), tool, "shell", arguments, result, &exitCode)

	var stored []byte
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		stored = gap0426ExportStore(t, fixture.store)
		if bytes.Contains(stored, []byte("SERVICE_API_TOKEN")) && bytes.Contains(stored, []byte("curl -sS")) &&
			bytes.Contains(stored, []byte("I created")) && len(capture.traceBytes()) > 0 && gap0426LogBytes(t, capture) != nil {
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
		for _, want := range []string{"SERVICE_API_TOKEN", "CANARY_BEARER", "I created", "curl -sS", "redacted type="} {
			if !bytes.Contains(sink.data, []byte(want)) {
				t.Errorf("%s: missing %q (the record or its readable text did not arrive)", sink.name, want)
			}
		}
		for _, secret := range gap0426Secrets() {
			if bytes.Contains(sink.data, []byte(secret)) {
				t.Errorf("%s keeps a secret in clear: %s...", sink.name, secret[:8])
			}
		}
	}
}

func gap0426ExportStore(t *testing.T, store *audit.Store) []byte {
	t.Helper()
	path := filepath.Join(t.TempDir(), "audit.jsonl")
	if err := store.ExportJSONL(path, 500, audit.ExportJSONLOptions{}); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return data
}

func gap0426LogBytes(t *testing.T, capture *hookModelV8OTLPCapture) []byte {
	t.Helper()
	wire, _ := capturedModelLogWire(t, capture)
	return wire
}

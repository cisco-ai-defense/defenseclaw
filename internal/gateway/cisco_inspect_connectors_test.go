// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/config"
)

const goldenHookPayloadDir = "../../scripts/live-connector-e2e/golden"

// aidWire is what AID receives.
type aidWire struct {
	Messages []struct {
		Role      string `json:"role"`
		Content   string `json:"content"`
		ToolCalls []struct {
			ID       *string `json:"id"`
			Type     string  `json:"type"`
			Function struct {
				Name      string `json:"name"`
				Arguments string `json:"arguments"`
			} `json:"function"`
		} `json:"tool_calls"`
	} `json:"messages"`
}

func loadGoldenHookPayload(t *testing.T, connectorName, event string) map[string]interface{} {
	t.Helper()
	path := filepath.Join(goldenHookPayloadDir, connectorName, event+".json")
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read golden: %v", err)
	}
	var payload map[string]interface{}
	if err := json.Unmarshal(raw, &payload); err != nil {
		t.Fatalf("golden %s is not an object: %v", path, err)
	}
	return payload
}

// captureAIDPayloadForConnector runs one hook event through the connector's own
// hook route and returns what reached AID.
func captureAIDPayloadForConnector(
	t *testing.T,
	connectorName string,
	payload map[string]interface{},
	headers map[string]string,
) []byte {
	t.Helper()
	installCorrelationHMACForTest()

	var gotBody []byte
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotBody, _ = io.ReadAll(r.Body)
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"is_safe":true,"action":"Allow","rules":[]}`)
	}))
	t.Cleanup(srv.Close)

	store, logger := testStoreAndV8Logger(t)
	cfg := &config.Config{}
	cfg.Guardrail.Mode = "action"
	cfg.Guardrail.Connector = connectorName
	api := NewAPIServer("127.0.0.1:0", NewSidecarHealth(), nil, store, logger, cfg)

	client := newCiscoInspectTestClient(t, srv.URL, "TEST_CISCO_CONNECTOR_PAYLOAD")
	client.client = srv.Client()
	api.SetCiscoInspector(client)

	raw, err := json.Marshal(payload)
	if err != nil {
		t.Fatal(err)
	}
	request := httptest.NewRequest(http.MethodPost, "/api/v1/"+connectorName+"/hook", bytes.NewReader(raw))
	for key, value := range headers {
		request.Header.Set(key, value)
	}
	response := httptest.NewRecorder()
	http.HandlerFunc(api.handleAgentHook(connectorName)).ServeHTTP(response, request)
	if response.Code != http.StatusOK {
		t.Fatalf("hook status=%d body=%s", response.Code, response.Body.String())
	}
	return gotBody
}

func decodeAIDWire(t *testing.T, body []byte) aidWire {
	t.Helper()
	if len(body) == 0 {
		t.Fatal("AID was not called")
	}
	var got aidWire
	if err := json.Unmarshal(body, &got); err != nil {
		t.Fatalf("unmarshal: %v (body=%s)", err, body)
	}
	return got
}

// Each connector's committed golden hook payload, through its own hook route,
// as AID receives it. The wanted values are the vendor's own: tool names and
// argument keys differ between connectors and a cloud rule has to match what is
// listed here.
func TestCiscoInspectClient_ConnectorToolCallPayloads(t *testing.T) {
	const command = "rm -rf /"

	for _, test := range []struct {
		connector string
		tool      string
		args      map[string]interface{}
		headers   map[string]string
		// wantID is the id the agent reported. Empty means the golden carries
		// none, and no id is sent.
		wantID string
	}{
		{
			connector: "claudecode",
			tool:      "Bash",
			args:      map[string]interface{}{"command": command},
		},
		{
			connector: "codex",
			tool:      "shell",
			args:      map[string]interface{}{"command": command},
			headers: map[string]string{
				"X-DefenseClaw-Hook-Event":    "PreToolUse",
				"X-DefenseClaw-Hook-Contract": defaultTestCodexHookContract,
			},
		},
		{
			connector: "cursor",
			tool:      "run_terminal_cmd",
			args:      map[string]interface{}{"command": command},
		},
		{
			connector: "windsurf",
			tool:      "run_command",
			args:      map[string]interface{}{"command": command},
		},
		{
			connector: "opencode",
			tool:      "bash",
			args:      map[string]interface{}{"command": command},
			wantID:    "dc-e2e-call-block",
		},
		{
			connector: "amp",
			tool:      "shell",
			args:      map[string]interface{}{"command": command},
			wantID:    "dc-e2e-amp-tool-block",
		},
		{
			connector: "antigravity",
			tool:      "run_command",
			args: map[string]interface{}{
				"CommandLine": command,
				"Cwd":         `C:\dc-e2e-workspace`,
			},
			headers: map[string]string{"X-DefenseClaw-Antigravity-Event": "PreToolUse"},
		},
		{
			connector: "hermes",
			tool:      "execute_command",
			args:      map[string]interface{}{"command": command},
		},
		{
			connector: "geminicli",
			tool:      "RunShellCommand",
			args:      map[string]interface{}{"command": command},
		},
		{
			connector: "openhands",
			tool:      "terminal",
			args:      map[string]interface{}{"command": command},
		},
		{
			connector: "devin",
			tool:      "exec",
			args:      map[string]interface{}{"command": command},
		},
		{
			connector: "copilot",
			tool:      "shell",
			args:      map[string]interface{}{"command": command},
			headers:   map[string]string{"X-DefenseClaw-Copilot-Event": "preToolUse"},
		},
	} {
		t.Run(test.connector, func(t *testing.T) {
			payload := loadGoldenHookPayload(t, test.connector, "pre_tool_block")
			got := decodeAIDWire(t, captureAIDPayloadForConnector(t, test.connector, payload, test.headers))

			if len(got.Messages) != 2 {
				t.Fatalf("messages = %d, want the text form and the tool call", len(got.Messages))
			}
			text, structured := got.Messages[0], got.Messages[1]
			if text.Role != "user" {
				t.Errorf("text role = %q, want user", text.Role)
			}
			if !strings.HasPrefix(text.Content, "Tool call: "+test.tool+"\n") ||
				!strings.Contains(text.Content, command) {
				t.Errorf("text content = %q", text.Content)
			}
			if structured.Role != "assistant" {
				t.Errorf("tool-call role = %q, want assistant", structured.Role)
			}
			if len(structured.ToolCalls) != 1 {
				t.Fatalf("tool_calls = %d, want 1", len(structured.ToolCalls))
			}
			call := structured.ToolCalls[0]
			if call.Type != "function" {
				t.Errorf("type = %q, want function", call.Type)
			}
			if call.Function.Name != test.tool {
				t.Errorf("name = %q, want the vendor name %q", call.Function.Name, test.tool)
			}
			var args map[string]interface{}
			if err := json.Unmarshal([]byte(call.Function.Arguments), &args); err != nil {
				t.Fatalf("arguments is not a JSON object: %v (%q)", err, call.Function.Arguments)
			}
			if !reflect.DeepEqual(args, test.args) {
				t.Errorf("arguments = %v, want %v", args, test.args)
			}
			switch {
			case test.wantID == "":
				if call.ID != nil {
					t.Errorf("id = %q, want the field omitted when the agent reports none", *call.ID)
				}
			case call.ID == nil || *call.ID != test.wantID:
				t.Errorf("id = %v, want the agent's id %q", call.ID, test.wantID)
			}
		})
	}
}

// A payload with no tool-argument object leaves args as the whole hook envelope,
// which cannot stand as tool-call fields, so only the text form is sent.
func TestCiscoInspectClient_HookEnvelopeArgsStayText(t *testing.T) {
	body := captureAIDPayloadForConnector(t, "windsurf", map[string]interface{}{
		"hook_event_name": "pre_run_command",
		"session_id":      "dc-envelope",
		"execution_id":    "e1",
		"command":         "rm -rf /",
		"cwd":             "/repo",
	}, nil)
	got := decodeAIDWire(t, body)
	if len(got.Messages) != 1 || got.Messages[0].Role != "user" {
		t.Fatalf("want the text form alone; body = %s", body)
	}
	if len(got.Messages[0].ToolCalls) != 0 {
		t.Errorf("tool_calls must be absent: %s", body)
	}
	if !strings.Contains(got.Messages[0].Content, "rm -rf /") {
		t.Errorf("content = %q", got.Messages[0].Content)
	}
}

// Arguments that are not a JSON object cannot become tool-call fields either.
// The public inspect route accepts any JSON here.
func TestCiscoInspectClient_NonObjectArgsStayText(t *testing.T) {
	var gotBody []byte
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotBody, _ = io.ReadAll(r.Body)
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"is_safe":true,"action":"Allow","rules":[]}`)
	}))
	t.Cleanup(srv.Close)

	api := testAPIServerWithConfig(t, "action")
	client := newCiscoInspectTestClient(t, srv.URL, "TEST_CISCO_NON_OBJECT_ARGS")
	client.client = srv.Client()
	api.SetCiscoInspector(client)

	for _, args := range []string{`"rm -rf /"`, `42`, `["rm -rf /"]`} {
		gotBody = nil
		req := &ToolInspectRequest{
			Tool:      "shell",
			Args:      json.RawMessage(args),
			Direction: "tool_call",
		}
		if v := api.hookAIDInspectTool(t.Context(), req, req.Tool, args); v == nil {
			t.Fatalf("args %s: expected a verdict", args)
		}
		if strings.Contains(string(gotBody), `"tool_calls"`) {
			t.Errorf("args %s: tool_calls must be absent; body = %s", args, gotBody)
		}
	}
}

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
	"sync"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/gateway/connector"
	"github.com/defenseclaw/defenseclaw/internal/hookpaths"
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

// connectorToolCallGoldens lists the connectors whose committed golden PreToolUse
// reaches AID as a tool call, with the contract its hook route resolves.
var connectorToolCallGoldens = []struct {
	connector string
	contract  string
	headers   map[string]string
	// extra is merged into the golden payload.
	extra map[string]interface{}
	// native rewrites the golden into the body the agent sends, for a
	// connector whose decoder does not read the golden's generic shape.
	native func(map[string]interface{}) map[string]interface{}
	// extraArgs are the arguments the vendor sends beside the command.
	extraArgs map[string]interface{}
	// wantID is the id the agent reported. Empty means the payload carries
	// none, so the id is DefenseClaw's "dc-" one: the chat schema rejects a
	// tool call without an id, and a minted correlation id is not the agent's.
	wantID string
}{
	{
		connector: "claudecode",
		contract:  "claudecode-hooks-v1",
		extra:     map[string]interface{}{"tool_use_id": "toolu_01U3wpX"},
		wantID:    "toolu_01U3wpX",
	},
	{
		connector: "codex",
		contract:  defaultTestCodexHookContract,
		headers: map[string]string{
			"X-DefenseClaw-Hook-Event":    "PreToolUse",
			"X-DefenseClaw-Hook-Contract": defaultTestCodexHookContract,
		},
		extra:  map[string]interface{}{"tool_use_id": "call_codex_42"},
		wantID: "call_codex_42",
	},
	{connector: "cursor", contract: "cursor-hooks-v1"},
	{connector: "amp", contract: "amp-plugin-v1", wantID: "dc-e2e-amp-tool-block"},
	{connector: "hermes", contract: "hermes-hooks-v2"},
	{connector: "devin", contract: "devin-hooks-v1"},
	{connector: "opencode", contract: "opencode-hooks-v2", wantID: "dc-e2e-call-block"},
	{
		connector: "antigravity",
		contract:  "antigravity-hooks-v2",
		headers:   map[string]string{"X-DefenseClaw-Antigravity-Event": "PreToolUse"},
		extraArgs: map[string]interface{}{"Cwd": `C:\dc-e2e-workspace`},
	},
	{
		connector: "copilot",
		contract:  "copilot-hooks-v2",
		headers:   map[string]string{"X-DefenseClaw-Copilot-Event": "preToolUse"},
		// The Copilot CLI sends toolName and toolArgs as a JSON string; the
		// golden's tool_name/tool_input is refused as an unread tool call
		// before AID is asked.
		native: func(golden map[string]interface{}) map[string]interface{} {
			args, _ := json.Marshal(golden["tool_input"])
			return map[string]interface{}{
				"sessionId": golden["session_id"],
				"cwd":       "/tmp",
				"toolName":  golden["tool_name"],
				"toolArgs":  string(args),
			}
		},
	},
}

// connectorTextOnlyGoldens lists the connectors whose golden PreToolUse reaches
// AID as the text form alone, and why. Every committed golden reaches AID as a
// tool call today; a connector added here needs its reason.
var connectorTextOnlyGoldens = map[string]string{}

// goldenToolName is the vendor's tool name in a golden hook payload: tool_name,
// or antigravity's toolCall.name.
func goldenToolName(payload map[string]interface{}) string {
	if name, _ := payload["tool_name"].(string); name != "" {
		return name
	}
	call, _ := payload["toolCall"].(map[string]interface{})
	name, _ := call["name"].(string)
	return name
}

// Each connector's committed golden hook payload, through its own hook route,
// as AID receives it. The tool name and the command key are not written here:
// they come from the registry's AIDToolCallShapes for the resolved contract, so
// the registry, the goldens and the wire have to agree, and a vendor renaming a
// tool or its command argument fails here.
func TestCiscoInspectClient_ConnectorToolCallPayloads(t *testing.T) {
	const command = "rm -rf /"

	for _, test := range connectorToolCallGoldens {
		t.Run(test.connector, func(t *testing.T) {
			contract, ok := knownHookContractByID(test.connector, test.contract)
			if !ok {
				t.Fatalf("no contract %s for %s", test.contract, test.connector)
			}
			payload := loadGoldenHookPayload(t, test.connector, "pre_tool_block")
			goldenTool := goldenToolName(payload)
			shape, ok := contract.AIDToolCallShapeFor(goldenTool)
			if !ok {
				t.Fatalf("%s declares no tool-call shape for the golden's tool %q", test.contract, goldenTool)
			}
			if shape.Surface == connector.ToolSurfaceShell && shape.CommandArg == "" {
				t.Fatalf("%s shape %q is a shell tool with no command key", test.contract, goldenTool)
			}
			for key, value := range test.extra {
				payload[key] = value
			}
			if test.native != nil {
				payload = test.native(payload)
			}
			got := decodeAIDWire(t, captureAIDPayloadForConnector(t, test.connector, payload, test.headers))

			if len(got.Messages) != 2 {
				t.Fatalf("messages = %d, want the tool call and the text form", len(got.Messages))
			}
			// The text form stays last, so AID keeps the request path.
			structured, text := got.Messages[0], got.Messages[1]
			if text.Role != "user" {
				t.Errorf("text role = %q, want user", text.Role)
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
			if call.Function.Name != shape.Tool {
				t.Errorf("name = %q, want the registry's %q for %s", call.Function.Name, shape.Tool, test.contract)
			}
			if goldenTool != call.Function.Name {
				t.Errorf("name = %q, want the golden's tool name %q", call.Function.Name, goldenTool)
			}
			var args map[string]interface{}
			if err := json.Unmarshal([]byte(call.Function.Arguments), &args); err != nil {
				t.Fatalf("arguments is not a JSON object: %v (%q)", err, call.Function.Arguments)
			}
			want := map[string]interface{}{shape.CommandArg: command}
			for key, value := range test.extraArgs {
				want[key] = value
			}
			if !reflect.DeepEqual(args, want) {
				t.Errorf("arguments = %v, want %v (command_arg %q from the registry)", args, want, shape.CommandArg)
			}
			if want := "Tool call: " + shape.Tool + "\n" + call.Function.Arguments; text.Content != want {
				t.Errorf("text content = %q, want the same invocation as text %q", text.Content, want)
			}
			switch {
			case call.ID == nil || *call.ID == "":
				t.Errorf("id = %v, want a non-empty id on every tool call", call.ID)
			case test.wantID != "" && *call.ID != test.wantID:
				t.Errorf("id = %q, want the agent's id %q", *call.ID, test.wantID)
			case test.wantID == "" && !strings.HasPrefix(*call.ID, "dc-"):
				t.Errorf("id = %q, want a \"dc-\" id when the agent reported none", *call.ID)
			}
		})
	}
	for connectorName, reason := range connectorTextOnlyGoldens {
		t.Run(connectorName+"/text-only", func(t *testing.T) {
			payload := loadGoldenHookPayload(t, connectorName, "pre_tool_block")
			got := decodeAIDWire(t, captureAIDPayloadForConnector(t, connectorName, payload, nil))
			if len(got.Messages) != 1 || len(got.Messages[0].ToolCalls) != 0 {
				t.Fatalf("messages = %+v, want the text form alone (%s)", got.Messages, reason)
			}
			if !strings.Contains(got.Messages[0].Content, command) {
				t.Errorf("text content = %q, want the command", got.Messages[0].Content)
			}
		})
	}
}

// Each call of a Copilot CLI parallel toolCalls envelope (GAP-1016) reaches AID
// as its own tool call, under its own name, with a "dc-" id derived from that
// call, since the CLI hook reports no tool id.
func TestCiscoInspectClient_CopilotParallelCallsEachSendAToolCall(t *testing.T) {
	installCorrelationHMACForTest()
	var (
		mu     sync.Mutex
		bodies [][]byte
	)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		mu.Lock()
		bodies = append(bodies, body)
		mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"is_safe":true,"action":"Allow","rules":[]}`)
	}))
	t.Cleanup(srv.Close)

	store, logger := testStoreAndV8Logger(t)
	cfg := &config.Config{}
	cfg.Guardrail.Mode = "action"
	cfg.Guardrail.Connector = "copilot"
	api := NewAPIServer("127.0.0.1:0", NewSidecarHealth(), nil, store, logger, cfg)
	client := newCiscoInspectTestClient(t, srv.URL, "TEST_CISCO_COPILOT_PARALLEL")
	client.client = srv.Client()
	api.SetCiscoInspector(client)

	input := copilotParallelOnHost(t, copilotParallelCorpusInput(t, "windows-native-parallel-read-tools"), t.TempDir())
	calls := input["toolCalls"].([]any)
	raw, err := json.Marshal(input)
	if err != nil {
		t.Fatal(err)
	}
	request := httptest.NewRequest(http.MethodPost, "/api/v1/copilot/hook", bytes.NewReader(raw))
	request.Header.Set("X-DefenseClaw-Copilot-Event", "preToolUse")
	if header := hookpaths.ResolveConnector("copilot", "", "preToolUse", raw); header != "" {
		request.Header.Set(hookpaths.Header, header)
	}
	response := httptest.NewRecorder()
	api.handleAgentHook("copilot").ServeHTTP(response, request)
	if response.Code != http.StatusOK {
		t.Fatalf("hook status=%d body=%s", response.Code, response.Body.String())
	}

	if len(bodies) != len(calls) {
		t.Fatalf("AID requests = %d, want one per call (%d)", len(bodies), len(calls))
	}
	ids := map[string]bool{}
	for i, body := range bodies {
		got := decodeAIDWire(t, body)
		if len(got.Messages) != 2 || len(got.Messages[0].ToolCalls) != 1 || got.Messages[1].Role != "user" {
			t.Fatalf("call %d: want the tool call and the text form; body = %s", i, body)
		}
		call := got.Messages[0].ToolCalls[0]
		if want := calls[i].(map[string]any)["name"]; call.Function.Name != want {
			t.Errorf("call %d: name = %q, want %q", i, call.Function.Name, want)
		}
		if call.ID == nil || !strings.HasPrefix(*call.ID, "dc-") || ids[*call.ID] {
			t.Errorf("call %d: id = %v, want its own \"dc-\" id", i, call.ID)
		} else {
			ids[*call.ID] = true
		}
	}
}

// Every committed PreToolUse golden is accounted for: carried as a tool call
// with a registry shape, or listed as text only with a reason. A new golden
// cannot be left out of the wire test unnoticed.
func TestCiscoInspectClient_EveryToolGoldenIsChecked(t *testing.T) {
	covered := map[string]bool{}
	for _, test := range connectorToolCallGoldens {
		covered[test.connector] = true
	}
	for connectorName := range connectorTextOnlyGoldens {
		if covered[connectorName] {
			t.Errorf("%s is listed both as a tool call and as text only", connectorName)
		}
		covered[connectorName] = true
	}
	entries, err := os.ReadDir(goldenHookPayloadDir)
	if err != nil {
		t.Fatalf("read goldens: %v", err)
	}
	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		if _, err := os.Stat(filepath.Join(goldenHookPayloadDir, entry.Name(), "pre_tool_block.json")); err != nil {
			continue
		}
		if !covered[entry.Name()] {
			t.Errorf("golden %s/pre_tool_block.json is not in the AID wire test", entry.Name())
		}
	}
}

func knownHookContractByID(connectorName, contractID string) (connector.HookContract, bool) {
	for _, contract := range connector.KnownHookContracts(connectorName) {
		if contract.ContractID == contractID {
			return contract, true
		}
	}
	return connector.HookContract{}, false
}

// A payload with no tool-argument object leaves args as the whole hook envelope,
// which cannot stand as tool-call fields, so only the text form is sent.
func TestCiscoInspectClient_HookEnvelopeArgsStayText(t *testing.T) {
	body := captureAIDPayloadForConnector(t, "devin", map[string]interface{}{
		"hook_event_name": "PreToolUse",
		"tool_name":       "exec",
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

	for _, args := range []string{`"rm -rf /"`, `42`, `["rm -rf /"]`, `null`, ` null `} {
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

// A hook whose tool_input is null projects "null", which decodes without error
// but is not an object: AID's rule engine fails the tool-call rules on it, so
// only the text form is sent.
func TestCiscoInspectClient_NullToolInputStaysText(t *testing.T) {
	payload := loadGoldenHookPayload(t, "cursor", "pre_tool_block")
	payload["tool_input"] = nil
	body := captureAIDPayloadForConnector(t, "cursor", payload, nil)
	got := decodeAIDWire(t, body)
	if len(got.Messages) != 1 || got.Messages[0].Role != "user" || len(got.Messages[0].ToolCalls) != 0 {
		t.Fatalf("want the text form alone; body = %s", body)
	}
}

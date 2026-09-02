// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package idfabric

import (
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

func TestEventKind(t *testing.T) {
	tests := []struct {
		name  string
		event string
		want  EventType
		ok    bool
	}{
		{name: "claude code pascal case", event: "SessionStart", want: EventTypeSessionStart, ok: true},
		{name: "codex snake case", event: "session_start", want: EventTypeSessionStart, ok: true},
		{name: "cursor camel case", event: "beforeShellExecution", ok: false},
		{name: "pre tool use pascal", event: "PreToolUse", want: EventTypePreToolUse, ok: true},
		{name: "pre tool use snake", event: "pre_tool_use", want: EventTypePreToolUse, ok: true},
		{name: "post tool use is out of scope", event: "PostToolUse", ok: false},
		{name: "empty", event: "", ok: false},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, ok := eventKind(tc.event)
			if ok != tc.ok {
				t.Fatalf("eventKind(%q) ok = %v, want %v", tc.event, ok, tc.ok)
			}
			if got != tc.want {
				t.Errorf("eventKind(%q) = %q, want %q", tc.event, got, tc.want)
			}
		})
	}
}

func TestMCPServerNameFromToolName(t *testing.T) {
	tests := []struct {
		name   string
		fields hookPayloadFields
		want   string
	}{
		{
			name:   "namespaced mcp tool",
			fields: hookPayloadFields{toolName: "mcp__github__create_issue"},
			want:   "github",
		},
		{
			name:   "builtin tool has no server",
			fields: hookPayloadFields{toolName: "Bash"},
			want:   "",
		},
		{
			name:   "explicit field wins",
			fields: hookPayloadFields{toolName: "mcp__github__x", mcpServer: "declared"},
			want:   "declared",
		},
		{
			name:   "malformed namespace",
			fields: hookPayloadFields{toolName: "mcp__onlyserver"},
			want:   "",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := tc.fields.mcpServerName(); got != tc.want {
				t.Errorf("mcpServerName() = %q, want %q", got, tc.want)
			}
		})
	}
}

func TestOSIdentityUsesPlatformJoinKey(t *testing.T) {
	got := OSIdentity()
	if runtime.GOOS == "windows" {
		if got.UID != "" {
			t.Errorf("UID = %q, want empty on Windows", got.UID)
		}
		if !strings.HasPrefix(got.SID, "S-1-") {
			t.Errorf("SID = %q, want an S-1- prefixed SID", got.SID)
		}
		return
	}
	if got.SID != "" {
		t.Errorf("SID = %q, want empty off Windows", got.SID)
	}
	if got.UID == "" {
		t.Error("UID is empty, want the effective UID")
	}
}

func TestCaptureHookEventSessionStartWritesEventAndInventory(t *testing.T) {
	home := t.TempDir()
	setHome(t, home)
	spoolDir := filepath.Join(home, "spool")
	t.Setenv(SpoolDirEnv, spoolDir)
	t.Setenv(EnableEnv, "1")
	t.Setenv("CODEX_HOME", filepath.Join(home, ".codex"))

	writeJSON(t, filepath.Join(home, ".codex", "auth.json"), map[string]any{
		"tokens": map[string]any{
			"id_token": unverifiedTestJWT(t, map[string]any{"email": "dev@example.com"}),
		},
	})

	written, err := CaptureHookEvent(HookContext{
		Connector:       "codex",
		Event:           "session_start",
		Payload:         []byte(`{"session_id":"sess-1","model":"gpt-5","cwd":"` + filepath.ToSlash(home) + `"}`),
		Home:            home,
		ProducerVersion: "v0.0.0-test",
		ReceivedAt:      time.Now().UTC(),
	})
	if err != nil {
		t.Fatalf("CaptureHookEvent: %v", err)
	}
	if len(written) != 2 {
		t.Fatalf("wrote %d records, want 2 (event + inventory): %v", len(written), written)
	}

	var sawEvent, sawInventory bool
	for _, path := range written {
		base := filepath.Base(path)
		data, err := os.ReadFile(path)
		if err != nil {
			t.Fatalf("ReadFile: %v", err)
		}
		var record map[string]any
		if err := json.Unmarshal(data, &record); err != nil {
			t.Fatalf("record %s is not valid JSON: %v", base, err)
		}

		switch record["schema_model"] {
		case string(SchemaModelAgentEvent):
			sawEvent = true
			if !strings.Contains(base, "session_start") {
				t.Errorf("event filename %q does not name its hook event", base)
			}
			session, ok := record["session_start"].(map[string]any)
			if !ok {
				t.Fatalf("record %s has no session_start block", base)
			}
			if session["event_type"] != string(EventTypeSessionStart) {
				t.Errorf("event_type = %v", session["event_type"])
			}
			if session["mcp_discovery_status"] != string(MCPDiscoveryComplete) {
				t.Errorf("mcp_discovery_status = %v, want %q", session["mcp_discovery_status"], MCPDiscoveryComplete)
			}
			if _, present := session["mcp_servers"]; !present {
				t.Error("mcp_servers is absent, want a present array")
			}
			assertUserBlock(t, session["user"])
		case string(SchemaModelAgent):
			sawInventory = true
			if !strings.Contains(base, "inventory") {
				t.Errorf("inventory filename %q does not name its source", base)
			}
			if record["runtime_status"] != string(RuntimeStatusRunning) {
				t.Errorf("runtime_status = %v, want %q", record["runtime_status"], RuntimeStatusRunning)
			}
			assertUserBlock(t, record["user"])
		default:
			t.Errorf("record %s has unexpected schema_model %v", base, record["schema_model"])
		}

		// The workspace path is used to locate MCP config but is never part of
		// the projection.
		if strings.Contains(string(data), `"cwd"`) {
			t.Errorf("record %s leaked the working directory", base)
		}
	}
	if !sawEvent || !sawInventory {
		t.Errorf("sawEvent = %v, sawInventory = %v; want both", sawEvent, sawInventory)
	}
}

// assertUserBlock checks that the OS join key came from the process token and
// that attribution was read from the connector's own account file.
func assertUserBlock(t *testing.T, raw any) {
	t.Helper()
	user, ok := raw.(map[string]any)
	if !ok {
		t.Fatalf("user block missing or malformed: %v", raw)
	}
	if user["authenticated_user_email"] != "dev@example.com" {
		t.Errorf("authenticated_user_email = %v", user["authenticated_user_email"])
	}
	if runtime.GOOS == "windows" {
		if sid, _ := user["sid"].(string); !strings.HasPrefix(sid, "S-1-") {
			t.Errorf("sid = %v, want an S-1- prefixed SID", user["sid"])
		}
		if _, present := user["uid"]; present {
			t.Error("uid is present on Windows, want it omitted")
		}
		return
	}
	if uid, _ := user["uid"].(string); uid == "" {
		t.Errorf("uid = %v, want the effective UID", user["uid"])
	}
	if _, present := user["sid"]; present {
		t.Error("sid is present off Windows, want it omitted")
	}
}

// TestCaptureHookEventStaleReceivedAtStillDiscovers guards the discovery
// budget against being measured from the event timestamp. A hook whose
// ReceivedAt lags behind the clock must still read its config tree.
func TestCaptureHookEventStaleReceivedAtStillDiscovers(t *testing.T) {
	home := t.TempDir()
	setHome(t, home)
	t.Setenv(SpoolDirEnv, filepath.Join(home, "spool"))
	t.Setenv(EnableEnv, "1")
	writeJSON(t, filepath.Join(home, ".cursor", "mcp.json"), map[string]any{
		"mcpServers": map[string]any{
			"grafana": map[string]any{"command": "docker", "args": []string{"run", "grafana/mcp-grafana:1.4.0"}},
		},
	})

	written, err := CaptureHookEvent(HookContext{
		Connector: "cursor",
		Event:     "sessionStart",
		Payload:   []byte(`{"session_id":"stale"}`),
		Home:      home,
		// An hour in the past, as clock skew or a slow start would produce.
		ReceivedAt: time.Now().Add(-time.Hour),
	})
	if err != nil {
		t.Fatalf("CaptureHookEvent: %v", err)
	}

	var event struct {
		SessionStart struct {
			Status  string      `json:"mcp_discovery_status"`
			Servers []MCPServer `json:"mcp_servers"`
		} `json:"session_start"`
	}
	for _, path := range written {
		data, err := os.ReadFile(path)
		if err != nil {
			t.Fatalf("ReadFile: %v", err)
		}
		if err := json.Unmarshal(data, &event); err != nil {
			t.Fatalf("Unmarshal: %v", err)
		}
		if event.SessionStart.Status == "" {
			continue
		}
		if event.SessionStart.Status != string(MCPDiscoveryComplete) {
			t.Errorf("mcp_discovery_status = %q, want %q", event.SessionStart.Status, MCPDiscoveryComplete)
		}
		if len(event.SessionStart.Servers) != 1 {
			t.Errorf("discovered %d servers, want 1", len(event.SessionStart.Servers))
		}
	}
}

// TestParseHookPayloadToleratesFieldTypeChanges pins per-field decoding. An
// agent that changes one field's shape must cost at most that field: a
// whole-payload decode failure would drop hook_event_name and silently stop
// telemetry for the connector.
func TestParseHookPayloadToleratesFieldTypeChanges(t *testing.T) {
	tests := []struct {
		name      string
		payload   string
		wantModel string
	}{
		{
			name:      "model as string",
			payload:   `{"hook_event_name":"SessionStart","session_id":"s-1","cwd":"/w","model":"claude-sonnet-4-6"}`,
			wantModel: "claude-sonnet-4-6",
		},
		{
			name:      "model as object",
			payload:   `{"hook_event_name":"SessionStart","session_id":"s-1","cwd":"/w","model":{"id":"claude-sonnet-4-6","display_name":"Sonnet"}}`,
			wantModel: "claude-sonnet-4-6",
		},
		{
			name:      "model object without id falls back to display name",
			payload:   `{"hook_event_name":"SessionStart","session_id":"s-1","cwd":"/w","model":{"display_name":"Sonnet"}}`,
			wantModel: "Sonnet",
		},
		{
			name:    "model of an unusable type costs only the model",
			payload: `{"hook_event_name":"SessionStart","session_id":"s-1","cwd":"/w","model":["a","b"]}`,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			fields := parseHookPayload([]byte(tc.payload))
			if fields.hookEventName != "SessionStart" {
				t.Errorf("hookEventName = %q, want %q", fields.hookEventName, "SessionStart")
			}
			if fields.sessionID != "s-1" {
				t.Errorf("sessionID = %q, want %q", fields.sessionID, "s-1")
			}
			if fields.cwd != "/w" {
				t.Errorf("cwd = %q, want %q", fields.cwd, "/w")
			}
			if fields.model != tc.wantModel {
				t.Errorf("model = %q, want %q", fields.model, tc.wantModel)
			}
		})
	}
}

// TestCaptureHookEventObjectModelStillRecordsEvent covers the end-to-end
// consequence: the record must still be produced and still carry its session.
func TestCaptureHookEventObjectModelStillRecordsEvent(t *testing.T) {
	home := t.TempDir()
	setHome(t, home)
	t.Setenv(SpoolDirEnv, filepath.Join(home, "spool"))
	t.Setenv(EnableEnv, "1")

	// Event is empty so the record type must come from the payload, which is
	// how Claude Code invokes the hook.
	written, err := CaptureHookEvent(HookContext{
		Connector: "claudecode",
		Payload:   []byte(`{"hook_event_name":"SessionStart","session_id":"cc-object-model","model":{"id":"claude-sonnet-4-6"}}`),
		Home:      home,
	})
	if err != nil {
		t.Fatalf("CaptureHookEvent: %v", err)
	}
	if len(written) == 0 {
		t.Fatal("no records written; an object-valued model dropped the event")
	}

	var found bool
	for _, path := range written {
		data, err := os.ReadFile(path)
		if err != nil {
			t.Fatalf("ReadFile: %v", err)
		}
		var event struct {
			SessionStart struct {
				SessionID string `json:"session_id"`
				Model     string `json:"model"`
			} `json:"session_start"`
		}
		if err := json.Unmarshal(data, &event); err != nil {
			t.Fatalf("Unmarshal: %v", err)
		}
		if event.SessionStart.SessionID == "" {
			continue
		}
		found = true
		if event.SessionStart.SessionID != "cc-object-model" {
			t.Errorf("session_id = %q, want %q", event.SessionStart.SessionID, "cc-object-model")
		}
		if event.SessionStart.Model != "claude-sonnet-4-6" {
			t.Errorf("model = %q, want %q", event.SessionStart.Model, "claude-sonnet-4-6")
		}
	}
	if !found {
		t.Error("no session_start record carried a session id")
	}
}

func TestCollectDeviceOmitsIDWhenNoDeviceKeyExists(t *testing.T) {
	home := t.TempDir()
	setHome(t, home)

	device := collectDevice(home)
	if device.ID != "" {
		t.Fatalf("ID = %q, want empty when no device key exists", device.ID)
	}
	encoded, err := json.Marshal(device)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	var decoded map[string]any
	if err := json.Unmarshal(encoded, &decoded); err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}
	if _, present := decoded["id"]; present {
		// An empty id would read as an established identity that happens to be
		// blank, rather than as identity not yet established.
		t.Errorf("id is present in %s, want it omitted", encoded)
	}
}

func TestCaptureHookEventPreToolUse(t *testing.T) {
	home := t.TempDir()
	setHome(t, home)
	t.Setenv(SpoolDirEnv, filepath.Join(home, "spool"))
	t.Setenv(EnableEnv, "1")

	written, err := CaptureHookEvent(HookContext{
		Connector:       "claudecode",
		Payload:         []byte(`{"hook_event_name":"PreToolUse","session_id":"s2","tool_name":"mcp__github__create_issue","tool_input":{"title":"secret title"}}`),
		Home:            home,
		ProducerVersion: "v0.0.0-test",
	})
	if err != nil {
		t.Fatalf("CaptureHookEvent: %v", err)
	}
	if len(written) != 1 {
		t.Fatalf("wrote %d records, want 1: %v", len(written), written)
	}

	data, err := os.ReadFile(written[0])
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}
	if strings.Contains(string(data), "secret title") {
		t.Error("record leaked tool input")
	}

	var record struct {
		PreToolUse *struct {
			EventType     string `json:"event_type"`
			ToolName      string `json:"tool_name"`
			MCPServerName string `json:"mcp_server_name"`
			TimeSource    string `json:"event_time_source"`
		} `json:"pre_tool_use"`
	}
	if err := json.Unmarshal(data, &record); err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}
	if record.PreToolUse == nil {
		t.Fatal("pre_tool_use block is absent")
	}
	if record.PreToolUse.EventType != string(EventTypePreToolUse) {
		t.Errorf("event_type = %q", record.PreToolUse.EventType)
	}
	if record.PreToolUse.ToolName != "mcp__github__create_issue" {
		t.Errorf("tool_name = %q", record.PreToolUse.ToolName)
	}
	if record.PreToolUse.MCPServerName != "github" {
		t.Errorf("mcp_server_name = %q, want github", record.PreToolUse.MCPServerName)
	}
	if record.PreToolUse.TimeSource != string(TimeSourceHookReceipt) {
		t.Errorf("event_time_source = %q, want %q", record.PreToolUse.TimeSource, TimeSourceHookReceipt)
	}
}

func TestCaptureHookEventSkipsOutOfScopeInput(t *testing.T) {
	home := t.TempDir()
	setHome(t, home)
	t.Setenv(SpoolDirEnv, filepath.Join(home, "spool"))
	t.Setenv(EnableEnv, "1")

	tests := []struct {
		name      string
		connector string
		event     string
	}{
		{name: "unsupported connector", connector: "amp", event: "session_start"},
		{name: "unsupported event", connector: "codex", event: "PostToolUse"},
		{name: "empty connector", connector: "", event: "session_start"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			written, err := CaptureHookEvent(HookContext{
				Connector: tc.connector,
				Event:     tc.event,
				Payload:   []byte(`{}`),
				Home:      home,
			})
			if err != nil {
				t.Fatalf("CaptureHookEvent: %v", err)
			}
			if len(written) != 0 {
				t.Errorf("wrote %v, want no records", written)
			}
		})
	}
}

func TestEnabled(t *testing.T) {
	t.Run("disabled by default", func(t *testing.T) {
		t.Setenv(EnableEnv, "")
		t.Setenv("DEFENSECLAW_DEPLOYMENT_MODE", "")
		if Enabled("", false) {
			t.Error("Enabled = true, want false outside managed enterprise")
		}
	})

	t.Run("enabled for a managed enterprise hook", func(t *testing.T) {
		t.Setenv(EnableEnv, "")
		t.Setenv("DEFENSECLAW_DEPLOYMENT_MODE", "")
		if !Enabled("", true) {
			t.Error("Enabled = false, want true for a managed enterprise hook")
		}
	})

	t.Run("enabled by deployment mode", func(t *testing.T) {
		t.Setenv(EnableEnv, "")
		t.Setenv("DEFENSECLAW_DEPLOYMENT_MODE", "")
		if !Enabled("managed_enterprise", false) {
			t.Error("Enabled = false, want true for managed_enterprise")
		}
	})

	t.Run("enabled by the test override", func(t *testing.T) {
		t.Setenv("DEFENSECLAW_DEPLOYMENT_MODE", "")
		t.Setenv(EnableEnv, "1")
		if !Enabled("unmanaged_byod", false) {
			t.Error("Enabled = false, want true with the override set")
		}
	})
}

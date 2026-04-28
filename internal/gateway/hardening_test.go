package gateway

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// ---------------------------------------------------------------------------
// injectSystemMessage
// ---------------------------------------------------------------------------

func TestInjectSystemMessage(t *testing.T) {
	t.Run("prepends_system_message", func(t *testing.T) {
		raw := json.RawMessage(`{"model":"gpt-4","messages":[{"role":"user","content":"hi"}]}`)
		patched, err := injectSystemMessage(raw, "security alert")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		var m map[string]json.RawMessage
		if err := json.Unmarshal(patched, &m); err != nil {
			t.Fatalf("unmarshal patched: %v", err)
		}
		var msgs []map[string]string
		if err := json.Unmarshal(m["messages"], &msgs); err != nil {
			t.Fatalf("unmarshal messages: %v", err)
		}
		if len(msgs) != 2 {
			t.Fatalf("expected 2 messages, got %d", len(msgs))
		}
		if msgs[0]["role"] != "system" {
			t.Errorf("first message role = %q, want system", msgs[0]["role"])
		}
		if msgs[0]["content"] != "security alert" {
			t.Errorf("first message content = %q, want %q", msgs[0]["content"], "security alert")
		}
	})

	t.Run("invalid_json_returns_error", func(t *testing.T) {
		_, err := injectSystemMessage(json.RawMessage(`{not json}`), "msg")
		if err == nil {
			t.Error("expected error for invalid JSON")
		}
	})

	t.Run("missing_messages_returns_error", func(t *testing.T) {
		_, err := injectSystemMessage(json.RawMessage(`{"model":"gpt-4"}`), "msg")
		if err == nil {
			t.Error("expected error when messages field missing")
		}
	})
}

// ---------------------------------------------------------------------------
// mergeToolCallChunks
// ---------------------------------------------------------------------------

func TestMergeToolCallChunks(t *testing.T) {
	t.Run("nil_existing_returns_chunk", func(t *testing.T) {
		chunk := json.RawMessage(`[{"id":"1"}]`)
		result := mergeToolCallChunks(nil, chunk)
		if string(result) != string(chunk) {
			t.Errorf("got %s, want %s", result, chunk)
		}
	})

	t.Run("nil_chunk_returns_existing", func(t *testing.T) {
		existing := json.RawMessage(`[{"id":"1"}]`)
		result := mergeToolCallChunks(existing, nil)
		if string(result) != string(existing) {
			t.Errorf("got %s, want %s", result, existing)
		}
	})

	t.Run("merges_two_arrays", func(t *testing.T) {
		existing := json.RawMessage(`[{"id":"1"}]`)
		chunk := json.RawMessage(`[{"id":"2"}]`)
		result := mergeToolCallChunks(existing, chunk)

		var arr []map[string]string
		if err := json.Unmarshal(result, &arr); err != nil {
			t.Fatalf("unmarshal result: %v", err)
		}
		if len(arr) != 2 {
			t.Fatalf("expected 2 elements, got %d", len(arr))
		}
		if arr[0]["id"] != "1" || arr[1]["id"] != "2" {
			t.Errorf("unexpected merge result: %v", arr)
		}
	})

	t.Run("empty_arrays_merge_safely", func(t *testing.T) {
		existing := json.RawMessage(`[]`)
		chunk := json.RawMessage(`[]`)
		result := mergeToolCallChunks(existing, chunk)

		var arr []json.RawMessage
		if err := json.Unmarshal(result, &arr); err != nil {
			t.Fatalf("unmarshal: %v", err)
		}
		if len(arr) != 0 {
			t.Errorf("expected empty array, got %d elements", len(arr))
		}
	})

	t.Run("invalid_existing_returns_chunk", func(t *testing.T) {
		existing := json.RawMessage(`not json`)
		chunk := json.RawMessage(`[{"id":"1"}]`)
		result := mergeToolCallChunks(existing, chunk)
		if string(result) != string(chunk) {
			t.Errorf("got %s, want %s", result, chunk)
		}
	})

	t.Run("invalid_chunk_returns_existing", func(t *testing.T) {
		existing := json.RawMessage(`[{"id":"1"}]`)
		chunk := json.RawMessage(`not json`)
		result := mergeToolCallChunks(existing, chunk)
		if string(result) != string(existing) {
			t.Errorf("got %s, want %s", result, existing)
		}
	})
}

// ---------------------------------------------------------------------------
// inspectToolCalls — parse failure returns alert (not nil)
// ---------------------------------------------------------------------------

func TestInspectToolCalls_ParseError(t *testing.T) {
	prov := &mockProvider{}
	insp := newMockInspector()
	proxy := newTestProxy(t, prov, insp, "action")

	malformed := json.RawMessage(`{not a valid tool calls array}`)
	verdict := proxy.inspectToolCalls(context.Background(), malformed)
	if verdict == nil {
		t.Fatal("expected non-nil verdict on parse error")
		return
	}
	if verdict.Action != "block" {
		t.Errorf("action = %q, want block (fail closed)", verdict.Action)
	}
	if verdict.Severity != "HIGH" {
		t.Errorf("severity = %q, want HIGH", verdict.Severity)
	}
}

func TestInspectToolCalls_Empty(t *testing.T) {
	prov := &mockProvider{}
	insp := newMockInspector()
	proxy := newTestProxy(t, prov, insp, "action")

	if v := proxy.inspectToolCalls(context.Background(), nil); v != nil {
		t.Errorf("expected nil for empty input, got %+v", v)
	}
	if v := proxy.inspectToolCalls(context.Background(), json.RawMessage(``)); v != nil {
		t.Errorf("expected nil for empty bytes, got %+v", v)
	}
}

// ---------------------------------------------------------------------------
// Streaming block enforcement: mid-stream block stops forwarding
// ---------------------------------------------------------------------------

func TestStreamingMidStreamBlockStopsForwarding(t *testing.T) {
	longContent := strings.Repeat("a", 600)
	prov := &mockProvider{
		streamChunks: []StreamChunk{
			{
				ID: "chatcmpl-s1", Object: "chat.completion.chunk", Model: "gpt-4",
				Choices: []ChatChoice{{Index: 0, Delta: &ChatMessage{Role: "assistant"}}},
			},
			{
				ID: "chatcmpl-s1", Object: "chat.completion.chunk", Model: "gpt-4",
				Choices: []ChatChoice{{Index: 0, Delta: &ChatMessage{Content: longContent}}},
			},
			{
				ID: "chatcmpl-s1", Object: "chat.completion.chunk", Model: "gpt-4",
				Choices: []ChatChoice{{Index: 0, Delta: &ChatMessage{Content: " should-not-be-forwarded"}}},
			},
		},
	}

	blockInsp := &conditionalInspector{blockAfterChars: 500}
	proxy := newTestProxy(t, prov, blockInsp, "action")

	reqBody := mustJSON(t, map[string]interface{}{
		"model":    "gpt-4",
		"messages": []map[string]interface{}{{"role": "user", "content": "test"}},
		"stream":   true,
	})

	rec := postChat(t, proxy, reqBody)
	body := rec.Body.String()

	if !strings.Contains(body, "[DONE]") {
		t.Error("stream should always end with [DONE]")
	}
	if strings.Contains(body, "should-not-be-forwarded") {
		t.Error("content after block should NOT be forwarded")
	}
	if !strings.Contains(body, "blocked") {
		t.Error("blocked message should appear in stream")
	}
}

// ---------------------------------------------------------------------------
// Streaming tool-call block enforcement
// ---------------------------------------------------------------------------

func TestStreamingToolCallBlockEnforcement(t *testing.T) {
	toolCalls := json.RawMessage(`[{"id":"call_1","type":"function","function":{"name":"write_file","arguments":"{\"path\":\"/etc/passwd\",\"content\":\"hack\"}"}}]`)
	prov := &mockProvider{
		streamChunks: []StreamChunk{
			{
				ID: "chatcmpl-tc", Object: "chat.completion.chunk", Model: "gpt-4",
				Choices: []ChatChoice{{Index: 0, Delta: &ChatMessage{Role: "assistant"}}},
			},
			{
				ID: "chatcmpl-tc", Object: "chat.completion.chunk", Model: "gpt-4",
				Choices: []ChatChoice{{Index: 0, Delta: &ChatMessage{ToolCalls: toolCalls}}},
			},
			{
				ID: "chatcmpl-tc", Object: "chat.completion.chunk", Model: "gpt-4",
				Choices: []ChatChoice{{Index: 0, Delta: &ChatMessage{}, FinishReason: strPtr("tool_calls")}},
			},
		},
	}

	insp := newMockInspector()
	proxy := newTestProxy(t, prov, insp, "action")

	reqBody := mustJSON(t, map[string]interface{}{
		"model":    "gpt-4",
		"messages": []map[string]interface{}{{"role": "user", "content": "write to /etc/passwd"}},
		"stream":   true,
	})

	rec := postChat(t, proxy, reqBody)
	body := rec.Body.String()

	if !strings.Contains(body, "[DONE]") {
		t.Error("stream should end with [DONE]")
	}
	if strings.Contains(body, `"write_file"`) {
		t.Error("blocked tool-call name should not appear in forwarded chunks")
	}
	if strings.Contains(body, `\"path\"`) {
		t.Error("blocked tool-call arguments JSON should not appear in forwarded chunks")
	}
	if !strings.Contains(body, "blocked") {
		t.Error("response should contain a block notice")
	}
}

// ---------------------------------------------------------------------------
// inspectToolCalls — malformed JSON fails closed
// ---------------------------------------------------------------------------

func TestInspectToolCallsMalformedJSONBlocks(t *testing.T) {
	prov := &mockProvider{}
	insp := newMockInspector()
	proxy := newTestProxy(t, prov, insp, "action")

	verdict := proxy.inspectToolCalls(context.Background(), json.RawMessage(`{not valid json`))
	if verdict == nil {
		t.Fatal("expected non-nil verdict for malformed JSON")
		return
	}
	if verdict.Action != "block" {
		t.Errorf("Action = %q, want block (fail closed on parse error)", verdict.Action)
	}
	if verdict.Severity != "HIGH" {
		t.Errorf("Severity = %q, want HIGH", verdict.Severity)
	}
}

func TestInspectToolCallsNilReturnsNil(t *testing.T) {
	prov := &mockProvider{}
	insp := newMockInspector()
	proxy := newTestProxy(t, prov, insp, "action")

	if v := proxy.inspectToolCalls(context.Background(), nil); v != nil {
		t.Errorf("expected nil verdict for nil input, got %+v", v)
	}
	if v := proxy.inspectToolCalls(context.Background(), json.RawMessage(``)); v != nil {
		t.Errorf("expected nil verdict for empty input, got %+v", v)
	}
}

// ---------------------------------------------------------------------------
// Notification inject body divergence
// ---------------------------------------------------------------------------

func TestNotificationInjectBodyDivergence(t *testing.T) {
	t.Run("inject_failure_does_not_add_to_messages", func(t *testing.T) {
		prov := &mockProvider{}
		insp := newMockInspector()
		proxy := newTestProxy(t, prov, insp, "action")
		proxy.notify = NewNotificationQueue()
		proxy.notify.Push(SecurityNotification{
			SkillName: "evil-skill",
			Severity:  "HIGH",
			Findings:  2,
			Actions:   []string{"blocked"},
			Reason:    "test enforcement",
		})

		reqBody := mustJSON(t, map[string]interface{}{
			"model":    "gpt-4",
			"messages": []map[string]interface{}{{"role": "user", "content": "hi"}},
		})

		rec := postChat(t, proxy, reqBody)
		if rec.Code != http.StatusOK {
			t.Fatalf("status = %d", rec.Code)
		}

		forwarded := prov.getLastReq()
		if forwarded == nil {
			t.Fatal("request should have been forwarded")
			return
		}

		// When RawBody is present and inject succeeds, Messages and RawBody
		// should both contain the notification. Verify consistency.
		hasNotifyInMessages := false
		for _, m := range forwarded.Messages {
			if m.Role == "system" && strings.Contains(m.Content, "DEFENSECLAW") {
				hasNotifyInMessages = true
				break
			}
		}
		if hasNotifyInMessages && len(forwarded.RawBody) > 0 {
			if !strings.Contains(string(forwarded.RawBody), "DEFENSECLAW") {
				t.Error("Messages has notification but RawBody does not — divergence detected")
			}
		}
	})

	t.Run("fallback_to_messages_on_bad_rawbody", func(t *testing.T) {
		prov := &mockProvider{}
		insp := newMockInspector()
		proxy := newTestProxy(t, prov, insp, "observe")
		proxy.notify = NewNotificationQueue()
		proxy.notify.Push(SecurityNotification{
			SkillName: "bad-skill",
			Severity:  "CRITICAL",
			Findings:  1,
			Actions:   []string{"blocked"},
			Reason:    "fallback test",
		})

		reqBody := mustJSON(t, map[string]interface{}{
			"model":    "gpt-4",
			"messages": []map[string]interface{}{{"role": "user", "content": "test"}},
		})

		rec := postChat(t, proxy, reqBody)
		if rec.Code != http.StatusOK {
			t.Fatalf("status = %d", rec.Code)
		}

		forwarded := prov.getLastReq()
		if forwarded == nil {
			t.Fatal("request should have been forwarded")
			return
		}

		hasNotifyInMessages := false
		for _, m := range forwarded.Messages {
			if m.Role == "system" && strings.Contains(m.Content, "DEFENSECLAW") {
				hasNotifyInMessages = true
				break
			}
		}
		if !hasNotifyInMessages {
			t.Error("notification should appear in Messages as fallback when RawBody inject fails")
		}
	})
}

// ---------------------------------------------------------------------------
// NotificationQueue
// ---------------------------------------------------------------------------

func TestNotificationQueue(t *testing.T) {
	t.Run("push_and_active", func(t *testing.T) {
		q := NewNotificationQueue()
		q.Push(SecurityNotification{SkillName: "s1", Severity: "HIGH"})
		q.Push(SecurityNotification{SkillName: "s2", Severity: "MEDIUM"})

		active := q.ActiveNotifications()
		if len(active) != 2 {
			t.Fatalf("expected 2 active, got %d", len(active))
		}
	})

	t.Run("expired_notifications_pruned", func(t *testing.T) {
		q := NewNotificationQueue()
		q.mu.Lock()
		q.items = append(q.items, SecurityNotification{
			SkillName: "old",
			ExpiresAt: time.Now().Add(-1 * time.Minute),
		})
		q.mu.Unlock()

		q.Push(SecurityNotification{SkillName: "new", Severity: "HIGH"})

		active := q.ActiveNotifications()
		if len(active) != 1 {
			t.Fatalf("expected 1 active after pruning, got %d", len(active))
		}
		if active[0].SkillName != "new" {
			t.Errorf("expected 'new', got %q", active[0].SkillName)
		}
	})

	t.Run("cap_enforced", func(t *testing.T) {
		q := NewNotificationQueue()
		for i := 0; i < maxNotificationQueueSize+20; i++ {
			q.Push(SecurityNotification{SkillName: "s", Severity: "LOW"})
		}
		q.mu.Lock()
		count := len(q.items)
		q.mu.Unlock()
		if count > maxNotificationQueueSize {
			t.Errorf("queue size %d exceeds cap %d", count, maxNotificationQueueSize)
		}
	})

	t.Run("format_system_message", func(t *testing.T) {
		q := NewNotificationQueue()
		msg := q.FormatSystemMessage()
		if msg != "" {
			t.Error("expected empty message for empty queue")
		}

		q.Push(SecurityNotification{
			SkillName: "malware",
			Severity:  "CRITICAL",
			Findings:  5,
			Actions:   []string{"quarantined", "disabled"},
			Reason:    "dangerous code detected",
		})
		msg = q.FormatSystemMessage()
		if !strings.Contains(msg, "DEFENSECLAW") {
			t.Error("message should contain DEFENSECLAW header")
		}
		if !strings.Contains(msg, "malware") {
			t.Error("message should contain skill name")
		}
	})
}

// ---------------------------------------------------------------------------
// Session map pruning
// ---------------------------------------------------------------------------

func TestActiveSessionsPruning(t *testing.T) {
	store, logger := testStoreAndLogger(t)
	router := NewEventRouter(nil, store, logger, true, nil)

	router.activeSessionsMu.Lock()
	router.activeSessions["old"] = time.Now().Add(-2 * time.Hour)
	router.activeSessions["recent"] = time.Now()
	router.activeSessionsMu.Unlock()

	keys := router.ActiveSessionKeys()
	if len(keys) != 1 {
		t.Fatalf("expected 1 active key, got %d", len(keys))
	}
	if keys[0] != "recent" {
		t.Errorf("expected 'recent', got %q", keys[0])
	}
}

func TestTrackSessionPrunes(t *testing.T) {
	store, logger := testStoreAndLogger(t)
	router := NewEventRouter(nil, store, logger, true, nil)

	router.activeSessionsMu.Lock()
	for i := 0; i < maxActiveSessions+10; i++ {
		key := strings.Repeat("x", 10) + string(rune('A'+i%26))
		router.activeSessions[key] = time.Now().Add(-2 * time.Hour)
	}
	router.activeSessionsMu.Unlock()

	router.trackSession("new-session")

	router.activeSessionsMu.RLock()
	count := len(router.activeSessions)
	router.activeSessionsMu.RUnlock()

	if count > maxActiveSessions+1 {
		t.Errorf("session map not pruned: got %d entries", count)
	}
}

// ---------------------------------------------------------------------------
// modelMaxTokens
// ---------------------------------------------------------------------------

func TestModelMaxTokens(t *testing.T) {
	tests := []struct {
		model string
		want  int
	}{
		{"gpt-4o-mini-2024-07-18", 16384},
		{"gpt-4o", 16384},
		{"gpt-4-turbo-preview", 4096},
		{"gpt-4-0613", 8192},
		{"o3-mini", 100000},
		{"o3", 100000},
		{"o4-mini", 100000},
		{"claude-3-opus", 8192},
		{"unknown-model-xyz", defaultMaxTokensFallback},
	}
	for _, tt := range tests {
		t.Run(tt.model, func(t *testing.T) {
			if got := modelMaxTokens(tt.model); got != tt.want {
				t.Errorf("modelMaxTokens(%q) = %d, want %d", tt.model, got, tt.want)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// patchRawBody max_tokens capping
// ---------------------------------------------------------------------------

func TestPatchRawBodyMaxTokensCapping(t *testing.T) {
	t.Run("caps_max_tokens_above_limit", func(t *testing.T) {
		raw := json.RawMessage(`{"model":"gpt-4","max_tokens":999999,"messages":[]}`)
		patched, err := patchRawBody(raw, "gpt-4", false)
		if err != nil {
			t.Fatalf("patchRawBody: %v", err)
		}

		var m map[string]json.RawMessage
		json.Unmarshal(patched, &m)
		var maxTok int
		json.Unmarshal(m["max_tokens"], &maxTok)
		if maxTok != 8192 {
			t.Errorf("max_tokens = %d, want 8192 (gpt-4 limit)", maxTok)
		}
	})

	t.Run("preserves_max_tokens_within_limit", func(t *testing.T) {
		raw := json.RawMessage(`{"model":"gpt-4","max_tokens":1000,"messages":[]}`)
		patched, err := patchRawBody(raw, "gpt-4", false)
		if err != nil {
			t.Fatalf("patchRawBody: %v", err)
		}

		var m map[string]json.RawMessage
		json.Unmarshal(patched, &m)
		var maxTok int
		json.Unmarshal(m["max_tokens"], &maxTok)
		if maxTok != 1000 {
			t.Errorf("max_tokens = %d, want 1000 (within limit)", maxTok)
		}
	})

	t.Run("unknown_model_uses_fallback", func(t *testing.T) {
		raw := json.RawMessage(`{"model":"unknown","max_tokens":999999,"messages":[]}`)
		patched, err := patchRawBody(raw, "unknown-model", false)
		if err != nil {
			t.Fatalf("patchRawBody: %v", err)
		}

		var m map[string]json.RawMessage
		json.Unmarshal(patched, &m)
		var maxTok int
		json.Unmarshal(m["max_tokens"], &maxTok)
		if maxTok != defaultMaxTokensFallback {
			t.Errorf("max_tokens = %d, want %d (fallback default)", maxTok, defaultMaxTokensFallback)
		}
	})

	t.Run("non_int_max_tokens_preserved", func(t *testing.T) {
		raw := json.RawMessage(`{"model":"gpt-4","max_tokens":"not-a-number","messages":[]}`)
		patched, err := patchRawBody(raw, "gpt-4", false)
		if err != nil {
			t.Fatalf("patchRawBody: %v", err)
		}

		var m map[string]json.RawMessage
		json.Unmarshal(patched, &m)
		var s string
		_ = json.Unmarshal(m["max_tokens"], &s)
	})
}

// ---------------------------------------------------------------------------
// Streaming block with notification queue injection
// ---------------------------------------------------------------------------

func TestProxyNotificationInjectSuccess(t *testing.T) {
	prov := &mockProvider{}
	insp := newMockInspector()
	proxy := newTestProxy(t, prov, insp, "action")
	proxy.notify = NewNotificationQueue()
	proxy.notify.Push(SecurityNotification{
		SkillName: "bad-skill",
		Severity:  "HIGH",
		Findings:  1,
		Actions:   []string{"disabled"},
		Reason:    "security issue",
	})

	reqBody := mustJSON(t, map[string]interface{}{
		"model":    "gpt-4",
		"messages": []map[string]interface{}{{"role": "user", "content": "hello"}},
	})

	req := httptest.NewRequest(http.MethodPost, "/v1/chat/completions", bytes.NewReader(reqBody))
	req.RemoteAddr = "127.0.0.1:12345"
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	proxy.handleChatCompletion(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d", rec.Code)
	}

	forwarded := prov.getLastReq()
	if forwarded == nil {
		t.Fatal("request should have been forwarded")
		return
	}

	foundNotify := false
	for _, m := range forwarded.Messages {
		if m.Role == "system" && strings.Contains(m.Content, "DEFENSECLAW") {
			foundNotify = true
			break
		}
	}
	if !foundNotify {
		t.Error("notification system message should be in forwarded request")
	}
}

func TestToolCallAccumulator(t *testing.T) {
	t.Run("single_complete_call", func(t *testing.T) {
		var acc toolCallAccumulator
		acc.Merge(json.RawMessage(`[{"index":0,"id":"call_1","type":"function","function":{"name":"write_file","arguments":"{\"path\":\"/tmp/a\"}"}}]`))

		got := acc.JSON()
		var calls []accToolCall
		if err := json.Unmarshal(got, &calls); err != nil {
			t.Fatalf("unmarshal: %v", err)
		}
		if len(calls) != 1 {
			t.Fatalf("expected 1 call, got %d", len(calls))
		}
		if calls[0].Function.Name != "write_file" {
			t.Errorf("name = %q, want write_file", calls[0].Function.Name)
		}
		if calls[0].Function.Arguments != `{"path":"/tmp/a"}` {
			t.Errorf("args = %q", calls[0].Function.Arguments)
		}
	})

	t.Run("reassembles_split_arguments", func(t *testing.T) {
		var acc toolCallAccumulator
		acc.Merge(json.RawMessage(`[{"index":0,"id":"call_1","type":"function","function":{"name":"exec","arguments":""}}]`))
		acc.Merge(json.RawMessage(`[{"index":0,"function":{"arguments":"{\"cmd\":"}}]`))
		acc.Merge(json.RawMessage(`[{"index":0,"function":{"arguments":"\"cat /etc"}}]`))
		acc.Merge(json.RawMessage(`[{"index":0,"function":{"arguments":"/passwd\"}"}}]`))

		got := acc.JSON()
		var calls []accToolCall
		if err := json.Unmarshal(got, &calls); err != nil {
			t.Fatalf("unmarshal: %v", err)
		}
		if len(calls) != 1 {
			t.Fatalf("expected 1 call, got %d", len(calls))
		}
		if calls[0].ID != "call_1" {
			t.Errorf("id = %q", calls[0].ID)
		}
		if calls[0].Function.Name != "exec" {
			t.Errorf("name = %q", calls[0].Function.Name)
		}
		want := `{"cmd":"cat /etc/passwd"}`
		if calls[0].Function.Arguments != want {
			t.Errorf("args = %q, want %q", calls[0].Function.Arguments, want)
		}
	})

	t.Run("multiple_tool_calls", func(t *testing.T) {
		var acc toolCallAccumulator
		acc.Merge(json.RawMessage(`[{"index":0,"id":"c1","type":"function","function":{"name":"read","arguments":""}},{"index":1,"id":"c2","type":"function","function":{"name":"write","arguments":""}}]`))
		acc.Merge(json.RawMessage(`[{"index":0,"function":{"arguments":"{\"a\":1}"}},{"index":1,"function":{"arguments":"{\"b\":2}"}}]`))

		got := acc.JSON()
		var calls []accToolCall
		if err := json.Unmarshal(got, &calls); err != nil {
			t.Fatalf("unmarshal: %v", err)
		}
		if len(calls) != 2 {
			t.Fatalf("expected 2 calls, got %d", len(calls))
		}
		if calls[0].Function.Arguments != `{"a":1}` {
			t.Errorf("call 0 args = %q", calls[0].Function.Arguments)
		}
		if calls[1].Function.Arguments != `{"b":2}` {
			t.Errorf("call 1 args = %q", calls[1].Function.Arguments)
		}
	})

	t.Run("empty_returns_nil", func(t *testing.T) {
		var acc toolCallAccumulator
		if got := acc.JSON(); got != nil {
			t.Errorf("expected nil, got %s", got)
		}
	})

	t.Run("invalid_json_ignored", func(t *testing.T) {
		var acc toolCallAccumulator
		acc.Merge(json.RawMessage(`not-json`))
		if got := acc.JSON(); got != nil {
			t.Errorf("expected nil after invalid merge, got %s", got)
		}
	})
}

func TestStreamingToolCallFinishChunkOrdering(t *testing.T) {
	// The finish_reason:"tool_calls" chunk must arrive AFTER tool-call
	// argument deltas, not before.  Verify that the proxy buffers both
	// and flushes them together in the correct order.
	fr := "tool_calls"
	prov := &mockProvider{
		streamChunks: []StreamChunk{
			{
				ID: "s1", Object: "chat.completion.chunk", Model: "gpt-4",
				Choices: []ChatChoice{{Index: 0, Delta: &ChatMessage{Role: "assistant"}}},
			},
			{
				ID: "s1", Object: "chat.completion.chunk", Model: "gpt-4",
				Choices: []ChatChoice{{Index: 0, Delta: &ChatMessage{
					ToolCalls: json.RawMessage(`[{"index":0,"id":"c1","type":"function","function":{"name":"run","arguments":""}}]`),
				}}},
			},
			{
				ID: "s1", Object: "chat.completion.chunk", Model: "gpt-4",
				Choices: []ChatChoice{{Index: 0, Delta: &ChatMessage{
					ToolCalls: json.RawMessage(`[{"index":0,"function":{"arguments":"{\"x\":1}"}}]`),
				}}},
			},
			{
				ID: "s1", Object: "chat.completion.chunk", Model: "gpt-4",
				Choices: []ChatChoice{{Index: 0, Delta: &ChatMessage{}, FinishReason: &fr}},
			},
		},
	}
	insp := newMockInspector()
	proxy := newTestProxy(t, prov, insp, "action")

	reqBody := mustJSON(t, map[string]interface{}{
		"model":    "gpt-4",
		"messages": []map[string]interface{}{{"role": "user", "content": "hi"}},
		"stream":   true,
	})

	rec := postChat(t, proxy, reqBody)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d; body: %s", rec.Code, rec.Body.String())
	}

	chunks := parseSSEChunks(t, rec.Body)

	// Find positions of first tool_calls delta and the finish chunk.
	firstTCIdx := -1
	finishIdx := -1
	for i, raw := range chunks {
		var c StreamChunk
		if json.Unmarshal(raw, &c) != nil || len(c.Choices) == 0 {
			continue
		}
		if c.Choices[0].Delta != nil && c.Choices[0].Delta.ToolCalls != nil && firstTCIdx == -1 {
			firstTCIdx = i
		}
		if c.Choices[0].FinishReason != nil && *c.Choices[0].FinishReason == "tool_calls" {
			finishIdx = i
		}
	}

	if firstTCIdx == -1 {
		t.Fatal("no tool_calls delta chunk found in response")
	}
	if finishIdx == -1 {
		t.Fatal("no finish_reason:tool_calls chunk found in response")
	}
	if finishIdx <= firstTCIdx {
		t.Errorf("finish chunk (idx=%d) arrived before tool-call deltas (idx=%d)", finishIdx, firstTCIdx)
	}
}

// ---------------------------------------------------------------------------
// Buffered tool-call chunks capped at maxBufferedTCBytes
// ---------------------------------------------------------------------------

func TestBufferedToolCallChunksCapped(t *testing.T) {
	bigArgs := strings.Repeat("A", 512*1024) // 512 KiB per chunk
	var chunks []StreamChunk
	for i := 0; i < 30; i++ { // 30 * 512K = ~15 MiB > 10 MiB cap
		tc := json.RawMessage(`[{"index":0,"id":"c1","type":"function","function":{"name":"big","arguments":"` + bigArgs + `"}}]`)
		chunks = append(chunks, StreamChunk{
			ID: "chatcmpl-big", Object: "chat.completion.chunk", Model: "gpt-4",
			Choices: []ChatChoice{{Index: 0, Delta: &ChatMessage{ToolCalls: tc}}},
		})
	}
	fin := "tool_calls"
	chunks = append(chunks, StreamChunk{
		ID: "chatcmpl-big", Object: "chat.completion.chunk", Model: "gpt-4",
		Choices: []ChatChoice{{Index: 0, Delta: &ChatMessage{}, FinishReason: &fin}},
	})

	prov := &mockProvider{streamChunks: chunks}
	insp := newMockInspector()
	proxy := newTestProxy(t, prov, insp, "action")

	reqBody := mustJSON(t, map[string]interface{}{
		"model":    "gpt-4",
		"messages": []map[string]interface{}{{"role": "user", "content": "big payload"}},
		"stream":   true,
	})

	rec := postChat(t, proxy, reqBody)
	body := rec.Body.String()

	if !strings.Contains(body, "blocked") {
		t.Error("expected block message when buffered tool-call data exceeds cap")
	}
	if !strings.Contains(body, "[DONE]") {
		t.Error("stream should end with [DONE]")
	}
}

// ---------------------------------------------------------------------------
// Stream block ends OTel LLM span
// ---------------------------------------------------------------------------

func TestStreamBlockEndsLLMSpan(t *testing.T) {
	prov := &mockProvider{
		streamChunks: []StreamChunk{
			{
				ID: "chatcmpl-1", Object: "chat.completion.chunk", Model: "gpt-4",
				Choices: []ChatChoice{{Index: 0, Delta: &ChatMessage{
					Role: "assistant", Content: "dangerous content",
				}}},
			},
		},
	}

	insp := &mockInspectorBlockAll{}
	proxy := newTestProxy(t, prov, insp, "action")

	reqBody := mustJSON(t, map[string]interface{}{
		"model":    "gpt-4",
		"messages": []map[string]interface{}{{"role": "user", "content": "test"}},
		"stream":   true,
	})

	rec := postChat(t, proxy, reqBody)
	body := rec.Body.String()

	if !strings.Contains(body, "blocked") {
		t.Error("expected stream to be blocked")
	}
}

type mockInspectorBlockAll struct{}

func (m *mockInspectorBlockAll) Inspect(_ context.Context, _, _ string, _ []ChatMessage, _, _ string) *ScanVerdict {
	return &ScanVerdict{Action: "block", Severity: "HIGH", Reason: "test block"}
}

func (m *mockInspectorBlockAll) InspectMidStream(ctx context.Context, direction, content string, messages []ChatMessage, model, mode string) *ScanVerdict {
	return m.Inspect(ctx, direction, content, messages, model, mode)
}

func (m *mockInspectorBlockAll) SetScannerMode(_ string) {}

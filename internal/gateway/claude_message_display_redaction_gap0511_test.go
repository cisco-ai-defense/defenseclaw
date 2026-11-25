// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"database/sql"
	"fmt"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/observability"
)

const (
	gap0511AWS = "AKIA" + "Z3Q7XK9M2P4W8R5T"
	gap0511GH  = "ghp_" + "Xq7mR2vL9pT4wK8nJ3cF6hB1yD5sG0aZe4Nu"
)

// bindClaudeDisplayRedactionRuntimeGAP0511 binds the real v8 runtime whose
// local event history (the audit database) stores the model.io bucket under
// the sensitive redaction profile, the chart default since GAP-0426.
func bindClaudeDisplayRedactionRuntimeGAP0511(t *testing.T) (*APIServer, string) {
	t.Helper()
	fixture := newSidecarV8BootstrapFixture(t, 8, "")
	api := &APIServer{}
	fixture.sidecar.setAPIServer(api)
	raw := fmt.Sprintf("config_version: 8\ndata_dir: %q\nobservability:\n  buckets:\n"+
		"    model.io:\n      collect: {logs: true}\n      redaction_profile: sensitive\n", fixture.dataDir)
	bound, err := fixture.sidecar.BootstrapObservabilityRuntime(t.Context(), fixture.configPath, []byte(raw))
	if err != nil || !bound || api.observabilityV8RuntimeEmitter() == nil {
		t.Fatalf("bootstrap v8 runtime bound=%t error=%v", bound, err)
	}
	return api, filepath.Join(fixture.dataDir, config.DefaultAuditDBName)
}

func displayClaudeChunksGAP0511(t *testing.T, api *APIServer, session string, chunks []string, final bool) {
	t.Helper()
	message := "msg-" + session
	for index, chunk := range chunks {
		api.emitClaudeCodeHookLLMEvent(t.Context(), claudeCodeHookRequest{
			HookEventName: "MessageDisplay", SessionID: session, TurnID: session + "-turn",
			MessageID: message, Model: "claude-sonnet-4", Delta: chunk,
			DisplayIndex: index, DisplayFinal: final && index == len(chunks)-1,
		}, nil, []byte(`{"message_id":"`+message+`"}`))
	}
}

func storedModelResponsesGAP0511(t *testing.T, dbPath string) []string {
	t.Helper()
	database, err := sql.Open("sqlite", dbPath)
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()
	rows, err := database.Query(`SELECT COALESCE(projected_record_json,'') FROM audit_events WHERE event_name = ? ORDER BY rowid`,
		observability.TelemetryEventModelResponse)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	var result []string
	for rows.Next() {
		var projected string
		if err := rows.Scan(&projected); err != nil {
			t.Fatal(err)
		}
		result = append(result, projected)
	}
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}
	return result
}

// GAP-0511: Claude Code streams a displayed message in MessageDisplay chunks.
// A provider token split across two or three chunks must not reach a stored
// llm_response (model.response) row, whole or as any 8-byte piece, and a
// token inside one chunk is still redacted. At the base every chunk was its
// own row, so each piece of a split token escaped the detectors.
func TestClaudeMessageDisplayRedactsASecretSplitAcrossChunksGAP0511(t *testing.T) {
	api, dbPath := bindClaudeDisplayRedactionRuntimeGAP0511(t)
	cases := []struct {
		session, marker string
		chunks          []string
		tokens          []string
		stopFlush       bool
	}{
		{
			session: "gap0511-aws-two", marker: "plain words alpha",
			chunks: []string{"Deploy key AKIAZ3Q7XK", "9M2P4W8R5T is live, plain words alpha."},
			tokens: []string{gap0511AWS},
		},
		{
			session: "gap0511-gh-two", marker: "plain words bravo",
			chunks: []string{"token ghp_Xq7mR2vL9pT4wK8nJ3c", "F6hB1yD5sG0aZe4Nu done, plain words bravo."},
			tokens: []string{gap0511GH},
		},
		{
			// A whitespace-only chunk separates the token from the word
			// before it; dropping it would glue them into one longer token.
			session: "gap0511-gh-three", marker: "plain words charlie",
			chunks: []string{"Use", " ", "ghp_Xq7mR2vL9", "pT4wK8nJ3cF6h", "B1yD5sG0aZe4Nu now, plain words charlie."},
			tokens: []string{gap0511GH},
		},
		{
			session: "gap0511-aws-three", marker: "plain words delta",
			chunks: []string{"key AKIAZ3Q", "7XK9M2P", "4W8R5T end, plain words delta."},
			tokens: []string{gap0511AWS},
		},
		{
			session: "gap0511-inline", marker: "plain words echo",
			chunks: []string{"one chunk " + gap0511AWS + " and " + gap0511GH + " here, plain words echo."},
			tokens: []string{gap0511AWS, gap0511GH},
		},
		{
			// No final chunk: the session's next hook event ends the message.
			session: "gap0511-stop", marker: "plain words foxtrot",
			chunks:    []string{"pending ghp_Xq7mR2vL9pT4", "wK8nJ3cF6hB1yD5sG0aZe4Nu, plain words foxtrot."},
			tokens:    []string{gap0511GH},
			stopFlush: true,
		},
	}
	for _, c := range cases {
		displayClaudeChunksGAP0511(t, api, c.session, c.chunks, !c.stopFlush)
		if c.stopFlush {
			api.emitClaudeCodeHookLLMEvent(t.Context(), claudeCodeHookRequest{
				HookEventName: "Stop", SessionID: c.session, TurnID: c.session + "-turn", Model: "claude-sonnet-4",
			}, nil, []byte(`{"hook_event_name":"Stop"}`))
		}
	}

	var stored []string
	for deadline := time.Now().Add(5 * time.Second); ; time.Sleep(20 * time.Millisecond) {
		stored = storedModelResponsesGAP0511(t, dbPath)
		joined := strings.Join(stored, "\n")
		missing := ""
		for _, c := range cases {
			if !strings.Contains(joined, c.marker) {
				missing = c.marker
				break
			}
		}
		if missing == "" {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("no stored model.response row carries %q (the message was not stored); rows=%d", missing, len(stored))
		}
	}
	for _, c := range cases {
		for _, token := range c.tokens {
			for _, row := range stored {
				if strings.Contains(row, token) {
					t.Fatalf("%s: a stored model.response row holds the whole token: %s", c.session, row)
				}
				for start := 0; start+8 <= len(token); start++ {
					for end := start + 8; end <= len(token); end++ {
						if piece := token[start:end]; strings.Contains(row, piece) {
							t.Fatalf("%s: a stored model.response row holds the token piece %q: %s", c.session, piece, row)
						}
					}
				}
			}
		}
	}
}

// GAP-0511: the structured message format splits text into parts of at most
// 4096 bytes and redaction scans each part on its own, so a part ends after
// whitespace and a token across the 4096-byte mark stays in one part.
func TestHookModelV8TextPartsKeepATokenWholeGAP0511(t *testing.T) {
	content := strings.Repeat("word ", 818) + gap0511GH + " tail"
	if start := strings.Index(content, gap0511GH); start >= 4096 || start+len(gap0511GH) <= 4096 {
		t.Fatalf("test setup: the token must span byte 4096, it is at %d", start)
	}
	var joined strings.Builder
	whole := false
	for index, part := range hookModelV8TextParts(content) {
		text, ok := part.(observability.TelemetryStructuredArmGenAIMessagePartText)
		if !ok {
			t.Fatalf("part %d type=%T", index, part)
		}
		if len(text.Value.Content) > 4096 {
			t.Fatalf("part %d bytes=%d", index, len(text.Value.Content))
		}
		whole = whole || strings.Contains(text.Value.Content, gap0511GH)
		joined.WriteString(text.Value.Content)
	}
	if joined.String() != content {
		t.Fatalf("split content bytes=%d want=%d", joined.Len(), len(content))
	}
	if !whole {
		t.Fatal("the token was split across two parts")
	}
}

// GAP-0511: a message longer than a row keeps is written in parts cut after
// whitespace, so a token across the size limit is in one row, and the parts
// join to the message.
func TestClaudeDisplayBufferCutsLongMessagesAfterWhitespaceGAP0511(t *testing.T) {
	api := &APIServer{}
	meta := llmEventMeta{Source: "claudecode", SessionID: "gap0511-long", ResponseID: "msg-long", ResponseIDReported: true}
	key := claudeDisplayKey{sessionID: meta.SessionID, responseID: meta.ResponseID}
	first := strings.Repeat("abcd ", 6550) + gap0511GH[:13]
	second := gap0511GH[13:] + strings.Repeat(" tail", 10)
	if len(first) > claudeDisplayMaxBytes || len(first)+len(second) <= claudeDisplayMaxBytes {
		t.Fatalf("test setup: the second chunk must cross the %d-byte limit", claudeDisplayMaxBytes)
	}
	if flushes := api.claudeDisplays.add(t.Context(), api, key, meta, 0, first, false); len(flushes) != 0 {
		t.Fatalf("a message under the limit was written early: %d rows", len(flushes))
	}
	flushes := api.claudeDisplays.add(t.Context(), api, key, meta, 1, second, true)
	if len(flushes) != 2 || flushes[0].final || !flushes[1].final {
		t.Fatalf("rows=%d, want a streaming part then the final part", len(flushes))
	}
	if strings.Contains(flushes[0].content, "ghp_") || !strings.Contains(flushes[1].content, gap0511GH) {
		t.Fatal("the token was split across two rows")
	}
	if flushes[0].content+flushes[1].content != first+second {
		t.Fatal("the rows do not join to the message")
	}
	if len(api.claudeDisplays.messages) != 0 {
		t.Fatalf("the final chunk left %d messages held", len(api.claudeDisplays.messages))
	}
}

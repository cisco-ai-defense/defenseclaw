// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	collectortracepb "go.opentelemetry.io/proto/otlp/collector/trace/v1"
	"google.golang.org/protobuf/encoding/protojson"
)

const claudeCorrelationDocsRevision = "docs-sha256-30703875ce62463eda4f0efe92dd7f9d57207424f990f39fc72c77c06fb96190"

func TestClaudeSourceBackedToolUseIDJoinsHookAndNativeOTLP(t *testing.T) {
	installCorrelationHMACForTest()
	fixture := newCodexNativeOTLPFixture(t)
	api := &APIServer{store: fixture.store}
	api.bindOTLPObservabilityRuntime(fixture.runtime)

	hookPayload, hookRaw := loadClaudeHookCorrelationSourceFixture(t)
	profile := api.hookProfileForConnector("claudecode")
	hook := normalizeAgentHookRequestWithProfile("claudecode", hookPayload, profile)
	_, hook, err := api.correlateHookOccurrence(t.Context(), profile, hook, hookRaw)
	if err != nil {
		t.Fatal(err)
	}
	if hook.ToolInvocationID != "claude-tool-source-backed-1" {
		t.Fatalf("hook tool ID=%q", hook.ToolInvocationID)
	}

	accounting, err := api.importDecodedOTLPRequestV8(
		t.Context(), loadClaudeNativeCorrelationSourceFixture(t), otelSignalTraces,
		"claudecode", time.Now().UTC(),
	)
	if err != nil || !accounting.valid() || accounting.importedAndDerived != 1 {
		t.Fatalf("Claude native import accounting=%+v err=%v", accounting, err)
	}

	database := openCorrelationDB(t, fixture.path)
	var events, groups, sameAs, claims int
	if err := database.QueryRow(`SELECT COUNT(*), COUNT(DISTINCT logical_group_id)
		FROM correlation_events WHERE logical_group_id=?`, hook.LogicalEventID).Scan(&events, &groups); err != nil {
		t.Fatal(err)
	}
	if err := database.QueryRow(`SELECT COUNT(*) FROM correlation_relationships
		WHERE relationship_type='same_as' AND status='active'`).Scan(&sameAs); err != nil {
		t.Fatal(err)
	}
	if err := database.QueryRow(`SELECT COUNT(*) FROM correlation_identity_claims
		WHERE identifier_kind='tool_invocation' AND event_name='tool_end'`).Scan(&claims); err != nil {
		t.Fatal(err)
	}
	if events != 2 || groups != 1 || sameAs == 0 || claims != 2 {
		t.Fatalf("Claude hook/native join events=%d groups=%d same_as=%d claims=%d",
			events, groups, sameAs, claims)
	}
}

func loadClaudeHookCorrelationSourceFixture(t *testing.T) (map[string]any, []byte) {
	t.Helper()
	path := filepath.Join("testdata", "correlation", "claudecode", claudeCorrelationDocsRevision,
		"post-tool-use.hook.source.json")
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var payload map[string]any
	if err := json.Unmarshal(raw, &payload); err != nil {
		t.Fatalf("decode %s: %v", path, err)
	}
	return payload, raw
}

func loadClaudeNativeCorrelationSourceFixture(t *testing.T) *collectortracepb.ExportTraceServiceRequest {
	t.Helper()
	path := filepath.Join("testdata", "correlation", "claudecode", claudeCorrelationDocsRevision,
		"tool.span.source.json")
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	request := &collectortracepb.ExportTraceServiceRequest{}
	if err := protojson.Unmarshal(raw, request); err != nil {
		t.Fatalf("decode %s: %v", path, err)
	}
	return request
}

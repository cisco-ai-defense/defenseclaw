// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/actionfacts"
)

const syntheticToolResourceConnectorID = "0198f0c2-7b31-7a42-8c51-123456789abc"

func TestAuthenticatedToolResourcePopulatesOpaqueActionFactsIdentity(t *testing.T) {
	req := agentHookRequest{
		ConnectorName: "codex", ConnectorInstanceID: syntheticToolResourceConnectorID,
		ToolName: "mcp__sqlite__read_query",
		Payload:  map[string]interface{}{"mcp_server_name": "sqlite"},
	}
	ctx := withAuthenticatedHookConnector(context.Background(), "codex")
	ctx = withAuthenticatedToolResource(ctx, req, []byte(`{
		"tool_name":"synthetic","metadata":{"exact":true}
	}`))
	tool, identity := trustedToolActionFromContext(
		ctx, "codex", req.ToolName, req.ToolName,
	)
	if tool != "read_query" || !strings.HasPrefix(identity, "mcp-resource:v1:") ||
		len(identity) != len("mcp-resource:v1:")+64 {
		t.Fatalf("trusted action tool=%q identity=%q", tool, identity)
	}
	facts := actionfacts.Analyze(actionfacts.Input{
		Tool:                 tool,
		Args:                 json.RawMessage(`{"query":"SELECT password FROM credentials LIMIT 1"}`),
		ToolResourceIdentity: identity,
	})
	reads := actionfacts.ExactSensitiveSQLRowsetReads(facts)
	if len(reads) != 1 || reads[0].DatabaseIdentityDigest == "" {
		t.Fatalf("sensitive SQL reads=%+v", reads)
	}
	encoded, err := json.Marshal(actionfacts.Input{
		Tool: tool, ToolResourceIdentity: identity,
	})
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(encoded), identity) || strings.Contains(identity, "sqlite") {
		t.Fatalf("resource identity crossed privacy boundary: input=%s identity=%q", encoded, identity)
	}
}

func TestAuthenticatedToolResourceRejectsDuplicateOrOversizedRawEnvelope(t *testing.T) {
	req := agentHookRequest{
		ConnectorName: "codex", ConnectorInstanceID: syntheticToolResourceConnectorID,
		ToolName: "mcp__sqlite__read_query",
		Payload:  map[string]interface{}{"mcp_server_name": "sqlite"},
	}
	base := withAuthenticatedHookConnector(context.Background(), "codex")
	for name, raw := range map[string][]byte{
		"duplicate nested key": []byte(`{"tool_input":{"query":"one","query":"two"}}`),
		"trailing value":       []byte(`{} {}`),
		"oversized":            []byte(`{"padding":"` + strings.Repeat("a", toolValueLineageMaxInputBytes) + `"}`),
	} {
		t.Run(name, func(t *testing.T) {
			ctx := withAuthenticatedToolResource(base, req, raw)
			if _, ok := ctx.Value(trustedToolResourceContextKey{}).(trustedToolResourceProjection); ok {
				t.Fatal("ambiguous raw envelope established resource authority")
			}
		})
	}
}

func TestAuthenticatedToolResourceAuthorityAndSeparation(t *testing.T) {
	base := agentHookRequest{
		ConnectorName: "codex", ConnectorInstanceID: syntheticToolResourceConnectorID,
		ToolName: "mcp__sqlite__read_query",
		Payload:  map[string]interface{}{"mcp_server_name": "sqlite"},
	}
	authenticated := withAuthenticatedHookConnector(context.Background(), "codex")
	projection, ok := authenticatedToolResource(authenticated, base)
	if !ok {
		t.Fatal("matching scoped connector did not establish resource authority")
	}

	separations := []agentHookRequest{
		{ConnectorName: "codex", ConnectorInstanceID: "0198f0c2-7b31-7a42-8c51-abcdef012345", ToolName: base.ToolName, Payload: base.Payload},
		{ConnectorName: "codex", ConnectorInstanceID: base.ConnectorInstanceID, ToolName: "mcp__other__read_query", Payload: map[string]interface{}{"mcp_server_name": "other"}},
	}
	for _, candidate := range separations {
		other, accepted := authenticatedToolResource(authenticated, candidate)
		if !accepted || other.resourceIdentity == projection.resourceIdentity {
			t.Fatalf("resource identity did not separate candidate=%+v", candidate)
		}
	}

	for name, test := range map[string]struct {
		ctx context.Context
		req agentHookRequest
	}{
		"no scoped authentication":   {context.Background(), base},
		"wrong scoped connector":     {withAuthenticatedHookConnector(context.Background(), "claudecode"), base},
		"missing connector instance": {authenticated, func() agentHookRequest { value := base; value.ConnectorInstanceID = ""; return value }()},
		"non-v7 connector instance": {authenticated, func() agentHookRequest {
			value := base
			value.ConnectorInstanceID = "0198f0c2-7b31-4a42-8c51-123456789abc"
			return value
		}()},
		"degraded correlation": {authenticated, func() agentHookRequest { value := base; value.SuppressCorrelationEmit = true; return value }()},
		"server disagreement": {authenticated, func() agentHookRequest {
			value := base
			value.Payload = map[string]interface{}{"mcp_server_name": "other"}
			return value
		}()},
		"argument cannot name server": {authenticated, agentHookRequest{ConnectorName: "codex", ConnectorInstanceID: base.ConnectorInstanceID, ToolName: "read_query", Payload: map[string]interface{}{"tool_input": map[string]interface{}{"mcp_server_name": "sqlite"}}}},
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			if _, accepted := authenticatedToolResource(test.ctx, test.req); accepted {
				t.Fatal("untrusted resource metadata was accepted")
			}
		})
	}
}

func TestExactMCPToolResourceRejectsAmbiguousOrDynamicMetadata(t *testing.T) {
	tests := []struct{ tool, server string }{
		{"mcp__sqlite__read_query__extra", "sqlite"},
		{"mcp:sqlite:read_query:extra", "sqlite"},
		{"mcp____read_query", ""},
		{"mcp__sqlite__", "sqlite"},
		{"mcp__${SERVER}__read_query", ""},
		{"read_query", "{{server}}"},
		{"read/query", "sqlite"},
		{"read_query", strings.Repeat("a", trustedToolResourceComponentMax+1)},
		{strings.Repeat("a", trustedToolResourceComponentMax*3+1), "sqlite"},
		{"mcp__sqlite\n__read_query", ""},
	}
	for _, test := range tests {
		if server, tool, ok := exactMCPToolResource(test.tool, test.server); ok {
			t.Fatalf("accepted tool=%q server=%q as %q/%q", test.tool, test.server, server, tool)
		}
	}
}

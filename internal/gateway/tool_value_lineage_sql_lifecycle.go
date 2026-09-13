// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"context"
	"encoding/json"
	"strings"

	"github.com/defenseclaw/defenseclaw/internal/actionfacts"
	"github.com/defenseclaw/defenseclaw/internal/audit"
)

// toolValueLineageSQLSuccessfulProjection is intentionally request-scoped and
// inert. Stage 2b populates it only after an exact pending invocation resolves
// successfully; no matcher, finding, audit event, or telemetry sink consumes
// it yet.
type toolValueLineageSQLSuccessfulProjection struct {
	databaseIdentityDigest string
	valueDigests           []toolValueLineageDigest
}

func pendingSQLValueSource(
	capture *toolChainHookCapture,
) audit.ToolChainPendingSQLValueSource {
	if capture == nil || !capture.recorded {
		return audit.ToolChainPendingSQLValueSource{}
	}
	reads := actionfacts.ExactSensitiveSQLRowsetReads(capture.facts)
	if len(reads) != 1 || !reads[0].Exact {
		return audit.ToolChainPendingSQLValueSource{}
	}
	return audit.ToolChainPendingSQLValueSource{
		TableClass:             reads[0].TableClass,
		DatabaseIdentityDigest: reads[0].DatabaseIdentityDigest,
	}
}

func projectBoundSuccessfulSQLResult(
	ctx context.Context,
	req agentHookRequest,
	source audit.ToolChainPendingSQLValueSource,
) (toolValueLineageSQLSuccessfulProjection, bool) {
	if source == (audit.ToolChainPendingSQLValueSource{}) ||
		!activeToolValueLineageProcessKey.available {
		return toolValueLineageSQLSuccessfulProjection{}, false
	}
	actionTool, resourceIdentity := trustedToolActionFromContext(
		ctx, req.ConnectorName, req.ToolName, req.ToolName,
	)
	if resourceIdentity == "" {
		return toolValueLineageSQLSuccessfulProjection{}, false
	}
	toolInput, ok := req.Payload["tool_input"].(map[string]interface{})
	if !ok || len(toolInput) == 0 {
		return toolValueLineageSQLSuccessfulProjection{}, false
	}
	args, err := json.Marshal(toolInput)
	if err != nil {
		return toolValueLineageSQLSuccessfulProjection{}, false
	}
	facts := actionfacts.Analyze(actionfacts.Input{
		Tool: actionTool, Args: args, CWD: req.CWD,
		ActiveHome:           trustedSameHostHome(),
		ToolResourceIdentity: resourceIdentity,
	})
	reads := actionfacts.ExactSensitiveSQLRowsetReads(facts)
	if len(reads) != 1 || !reads[0].Exact ||
		reads[0].TableClass != source.TableClass ||
		reads[0].DatabaseIdentityDigest != source.DatabaseIdentityDigest {
		return toolValueLineageSQLSuccessfulProjection{}, false
	}
	result, ok := exactSuccessfulSQLResultBytes(req)
	if !ok {
		return toolValueLineageSQLSuccessfulProjection{}, false
	}
	digests, ok := toolValueLineageSQLRowsetDigests(
		activeToolValueLineageProcessKey.material, source.TableClass, result,
	)
	if !ok {
		return toolValueLineageSQLSuccessfulProjection{}, false
	}
	return toolValueLineageSQLSuccessfulProjection{
		databaseIdentityDigest: source.DatabaseIdentityDigest,
		valueDigests:           append([]toolValueLineageDigest(nil), digests...),
	}, true
}

func exactSuccessfulSQLResultBytes(req agentHookRequest) ([]byte, bool) {
	switch canonicalConnectorRulePackKey(req.ConnectorName) {
	case "codex":
		if req.HookEventName != "PostToolUse" ||
			!strings.HasPrefix(req.ToolName, "mcp__") {
			return nil, false
		}
		response, ok := req.Payload["tool_response"].(map[string]interface{})
		if !ok || len(response) < 1 || len(response) > 2 {
			return nil, false
		}
		for key := range response {
			if key != "content" && key != "isError" {
				return nil, false
			}
		}
		if isError, exists := response["isError"]; exists {
			flag, valid := isError.(bool)
			if !valid || flag {
				return nil, false
			}
		}
		content, ok := response["content"].([]interface{})
		if !ok || len(content) != 1 {
			return nil, false
		}
		block, ok := content[0].(map[string]interface{})
		if !ok || len(block) != 2 || block["type"] != "text" {
			return nil, false
		}
		text, ok := block["text"].(string)
		if !ok {
			return nil, false
		}
		return []byte(text), true
	case "claudecode":
		if req.HookEventName != "PostToolUse" || req.Payload["tool_calls"] != nil ||
			strings.TrimSpace(payloadString(req.Payload, "error")) != "" ||
			strings.TrimSpace(payloadString(req.Payload, "error_details")) != "" {
			return nil, false
		}
		response, ok := req.Payload["tool_response"].(string)
		if !ok {
			return nil, false
		}
		return []byte(response), true
	default:
		return nil, false
	}
}

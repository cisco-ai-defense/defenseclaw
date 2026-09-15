// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"strings"

	"github.com/defenseclaw/defenseclaw/internal/actionfacts"
	"github.com/defenseclaw/defenseclaw/internal/audit"
	"github.com/defenseclaw/defenseclaw/internal/guardrail"
)

// toolValueLineageSQLSuccessfulProjection is intentionally request-scoped.
// Only its bounded digests cross into the successful pending-resolution path;
// raw SQL results and values never enter matcher, audit, log, or telemetry
// state.
type toolValueLineageSQLSuccessfulProjection struct {
	databaseIdentityDigest string
	resourceIdentityDigest string
	valueDigests           []toolValueLineageDigest
}

const toolValueLineageMCPResourceJoinDomain = "defenseclaw/tool-value-lineage/mcp-resource-join/v1"

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
	candidateSource, projection, ok := projectSuccessfulSQLResultCandidate(ctx, req)
	if !ok || source == (audit.ToolChainPendingSQLValueSource{}) ||
		candidateSource != source {
		return toolValueLineageSQLSuccessfulProjection{}, false
	}
	return projection, true
}

// projectSuccessfulSQLResultCandidate produces only value-free descriptors and
// keyed digests. ResolvePending must rebind candidateSource to the invocation's
// stored descriptor before any part of projection can enter durable state.
func projectSuccessfulSQLResultCandidate(
	ctx context.Context,
	req agentHookRequest,
) (
	audit.ToolChainPendingSQLValueSource,
	toolValueLineageSQLSuccessfulProjection,
	bool,
) {
	if !activeToolValueLineageProcessKey.available {
		return audit.ToolChainPendingSQLValueSource{},
			toolValueLineageSQLSuccessfulProjection{}, false
	}
	actionTool, resourceIdentity := trustedToolActionFromContext(
		ctx, req.ConnectorName, req.ToolName, req.ToolName,
	)
	if resourceIdentity == "" {
		return audit.ToolChainPendingSQLValueSource{},
			toolValueLineageSQLSuccessfulProjection{}, false
	}
	toolInput, ok := req.Payload["tool_input"].(map[string]interface{})
	if !ok || len(toolInput) == 0 {
		return audit.ToolChainPendingSQLValueSource{},
			toolValueLineageSQLSuccessfulProjection{}, false
	}
	args, err := json.Marshal(toolInput)
	if err != nil {
		return audit.ToolChainPendingSQLValueSource{},
			toolValueLineageSQLSuccessfulProjection{}, false
	}
	facts := actionfacts.Analyze(actionfacts.Input{
		Tool: actionTool, Args: args, CWD: req.CWD,
		ActiveHome:           trustedSameHostHome(),
		ToolResourceIdentity: resourceIdentity,
	})
	reads := actionfacts.ExactSensitiveSQLRowsetReads(facts)
	if len(reads) != 1 || !reads[0].Exact {
		return audit.ToolChainPendingSQLValueSource{},
			toolValueLineageSQLSuccessfulProjection{}, false
	}
	source := audit.ToolChainPendingSQLValueSource{
		TableClass:             reads[0].TableClass,
		DatabaseIdentityDigest: reads[0].DatabaseIdentityDigest,
	}
	result, ok := exactSuccessfulSQLResultBytes(req)
	if !ok {
		return audit.ToolChainPendingSQLValueSource{},
			toolValueLineageSQLSuccessfulProjection{}, false
	}
	digests, ok := toolValueLineageSQLRowsetDigests(
		activeToolValueLineageProcessKey.material, source.TableClass, result,
	)
	if !ok {
		return audit.ToolChainPendingSQLValueSource{},
			toolValueLineageSQLSuccessfulProjection{}, false
	}
	resourceDigest := toolValueLineageMCPResourceDigest(resourceIdentity)
	if resourceDigest == "" {
		return audit.ToolChainPendingSQLValueSource{},
			toolValueLineageSQLSuccessfulProjection{}, false
	}
	return source, toolValueLineageSQLSuccessfulProjection{
		databaseIdentityDigest: source.DatabaseIdentityDigest,
		resourceIdentityDigest: resourceDigest,
		valueDigests:           append([]toolValueLineageDigest(nil), digests...),
	}, true
}

func projectSQLValuePersistenceSink(
	ctx context.Context,
	req agentHookRequest,
	projection *guardrail.ToolChainProjection,
) {
	if projection == nil || !activeToolValueLineageProcessKey.available {
		return
	}
	actionTool, resourceIdentity := trustedToolActionFromContext(
		ctx, req.ConnectorName, req.ToolName, req.ToolName,
	)
	if resourceIdentity == "" {
		return
	}
	toolInput, ok := req.Payload["tool_input"].(map[string]interface{})
	if !ok || len(toolInput) == 0 {
		return
	}
	args, err := json.Marshal(toolInput)
	if err != nil {
		return
	}
	input := actionfacts.Input{
		Tool: actionTool, Args: args, CWD: req.CWD,
		ActiveHome:           trustedSameHostHome(),
		ToolResourceIdentity: resourceIdentity,
	}
	digests, ok := toolValueLineageStructuredPersistenceDigests(
		activeToolValueLineageProcessKey.material,
		input,
	)
	values := toolValueLineageGuardrailDigests(digests)
	resourceDigest := toolValueLineageMCPResourceDigest(resourceIdentity)
	if !ok || values == (guardrail.ToolChainValueJoinDigests{}) ||
		resourceDigest == "" {
		return
	}
	addToolChainStep(
		projection,
		guardrail.ToolChainSensitiveSQLValueCrossResourcePersist,
		2,
		true,
		false,
	)
	index, ok := guardrail.ToolChainIndexByID(
		guardrail.ToolChainSensitiveSQLValueCrossResourcePersist,
	)
	if !ok {
		return
	}
	projection.EnforcementJoinDigests[index] = resourceDigest
	projection.ValueJoinDigests[index] = values
}

func toolValueLineageMCPResourceDigest(identity string) string {
	if identity == "" {
		return ""
	}
	hash := sha256.New()
	for _, value := range []string{toolValueLineageMCPResourceJoinDomain, identity} {
		var size [4]byte
		binary.BigEndian.PutUint32(size[:], uint32(len(value)))
		_, _ = hash.Write(size[:])
		_, _ = hash.Write([]byte(value))
	}
	return hex.EncodeToString(hash.Sum(nil))
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

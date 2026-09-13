// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"strings"
)

const (
	trustedToolResourceIdentityDomain = "defenseclaw/trusted-tool-resource/v1"
	trustedToolResourceComponentMax   = 128
)

type trustedToolResourceContextKey struct{}

// trustedToolResourceProjection is populated only at the authenticated hook
// boundary after correlation has assigned the connector instance. It is
// request-scoped and contains no arguments, SQL, result content, or secret.
type trustedToolResourceProjection struct {
	connector        string
	nativeTool       string
	actionTool       string
	resourceIdentity string
}

func withAuthenticatedToolResource(
	ctx context.Context,
	req agentHookRequest,
	rawBody []byte,
) context.Context {
	if ctx == nil {
		ctx = context.Background()
	}
	decoded, exact := toolValueLineageDecodeJSON(rawBody)
	if !exact {
		return ctx
	}
	if _, object := decoded.(map[string]interface{}); !object {
		return ctx
	}
	projection, ok := authenticatedToolResource(ctx, req)
	if !ok {
		return ctx
	}
	return context.WithValue(ctx, trustedToolResourceContextKey{}, projection)
}

func authenticatedToolResource(
	ctx context.Context,
	req agentHookRequest,
) (trustedToolResourceProjection, bool) {
	connectorName := canonicalConnectorRulePackKey(req.ConnectorName)
	if connectorName == "" || authenticatedHookConnector(ctx) != connectorName ||
		req.SuppressCorrelationEmit || !exactConnectorInstanceID(req.ConnectorInstanceID) {
		return trustedToolResourceProjection{}, false
	}
	explicitServer := strings.TrimSpace(payloadString(req.Payload, "mcp_server_name"))
	server, actionTool, ok := exactMCPToolResource(req.ToolName, explicitServer)
	if !ok {
		return trustedToolResourceProjection{}, false
	}
	identity := opaqueTrustedToolResourceIdentity(
		connectorName, req.ConnectorInstanceID, server,
	)
	if identity == "" {
		return trustedToolResourceProjection{}, false
	}
	return trustedToolResourceProjection{
		connector: connectorName, nativeTool: req.ToolName, actionTool: actionTool,
		resourceIdentity: identity,
	}, true
}

func trustedToolActionFromContext(
	ctx context.Context,
	connectorName string,
	nativeTool string,
	fallbackTool string,
) (string, string) {
	if ctx == nil {
		return fallbackTool, ""
	}
	projection, ok := ctx.Value(trustedToolResourceContextKey{}).(trustedToolResourceProjection)
	if !ok || projection.connector != canonicalConnectorRulePackKey(connectorName) ||
		projection.nativeTool != nativeTool || projection.actionTool == "" ||
		projection.resourceIdentity == "" {
		return fallbackTool, ""
	}
	return projection.actionTool, projection.resourceIdentity
}

func exactMCPToolResource(nativeTool, explicitServer string) (string, string, bool) {
	nativeTool = strings.TrimSpace(nativeTool)
	explicitServer = strings.TrimSpace(explicitServer)
	if nativeTool == "" || len(nativeTool) > trustedToolResourceComponentMax*3 {
		return "", "", false
	}

	prefixedServer, actionTool, prefixed := exactPrefixedMCPTool(nativeTool)
	if !prefixed {
		if strings.HasPrefix(nativeTool, "mcp__") ||
			strings.HasPrefix(nativeTool, "mcp:") {
			return "", "", false
		}
		if explicitServer == "" || !exactToolResourceComponent(nativeTool) {
			return "", "", false
		}
		actionTool = nativeTool
	}
	if explicitServer != "" {
		if !exactToolResourceComponent(explicitServer) ||
			(prefixedServer != "" && explicitServer != prefixedServer) {
			return "", "", false
		}
		prefixedServer = explicitServer
	}
	if !exactToolResourceComponent(prefixedServer) ||
		!exactToolResourceComponent(actionTool) {
		return "", "", false
	}
	return prefixedServer, actionTool, true
}

func exactPrefixedMCPTool(nativeTool string) (string, string, bool) {
	if strings.HasPrefix(nativeTool, "mcp__") {
		parts := strings.Split(nativeTool, "__")
		if len(parts) != 3 || parts[0] != "mcp" {
			return "", "", false
		}
		return parts[1], parts[2], true
	}
	if strings.HasPrefix(nativeTool, "mcp:") {
		parts := strings.Split(nativeTool, ":")
		if len(parts) != 3 || parts[0] != "mcp" {
			return "", "", false
		}
		return parts[1], parts[2], true
	}
	return "", "", false
}

func exactToolResourceComponent(value string) bool {
	if value == "" || len(value) > trustedToolResourceComponentMax ||
		strings.TrimSpace(value) != value {
		return false
	}
	for index := 0; index < len(value); index++ {
		character := value[index]
		if character >= 'a' && character <= 'z' ||
			character >= 'A' && character <= 'Z' ||
			character >= '0' && character <= '9' ||
			character == '_' || character == '-' || character == '.' {
			continue
		}
		return false
	}
	return true
}

func exactConnectorInstanceID(value string) bool {
	if len(value) != 36 || value[14] != '7' ||
		!strings.ContainsRune("89ab", rune(value[19])) {
		return false
	}
	for index := 0; index < len(value); index++ {
		if index == 8 || index == 13 || index == 18 || index == 23 {
			if value[index] != '-' {
				return false
			}
			continue
		}
		character := value[index]
		if !(character >= '0' && character <= '9' ||
			character >= 'a' && character <= 'f') {
			return false
		}
	}
	return true
}

func opaqueTrustedToolResourceIdentity(connectorName, connectorID, server string) string {
	if connectorName == "" || !exactConnectorInstanceID(connectorID) ||
		!exactToolResourceComponent(server) {
		return ""
	}
	hash := sha256.New()
	for _, value := range []string{
		trustedToolResourceIdentityDomain, connectorName, connectorID, server,
	} {
		var size [4]byte
		binary.BigEndian.PutUint32(size[:], uint32(len(value)))
		_, _ = hash.Write(size[:])
		_, _ = hash.Write([]byte(value))
	}
	return "mcp-resource:v1:" + hex.EncodeToString(hash.Sum(nil))
}

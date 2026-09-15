// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"strings"
)

const (
	trustedToolResourceIdentityDomain = "defenseclaw/trusted-tool-resource/v1"
	trustedToolResourceComponentMax   = 128
	// The authenticated hook envelope adds exactly one object around the
	// reviewed value-lineage input grammars. Keep that additional depth local
	// to envelope validation so the value parsers retain their tighter bound.
	trustedToolResourceEnvelopeMaxJSONDepth = toolValueLineageMaxJSONDepth + 1
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
	if !exactTrustedToolResourceEnvelopeJSON(rawBody) {
		return ctx
	}
	projection, ok := authenticatedToolResource(ctx, req)
	if !ok {
		return ctx
	}
	return context.WithValue(ctx, trustedToolResourceContextKey{}, projection)
}

// exactTrustedToolResourceEnvelopeJSON validates the original authenticated
// bytes before attaching trusted metadata. It intentionally retains no values:
// the already-decoded request remains the only consumer. Case-insensitive
// duplicate keys, malformed input, excessive nesting/cardinality, and trailing
// values all fail closed.
func exactTrustedToolResourceEnvelopeJSON(raw []byte) bool {
	if !toolValueLineageInputValid(raw) {
		return false
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	elements := 0
	rootObject, err := consumeTrustedToolResourceJSONValue(decoder, 0, &elements)
	if err != nil || !rootObject {
		return false
	}
	_, err = decoder.Token()
	return errors.Is(err, io.EOF)
}

func consumeTrustedToolResourceJSONValue(
	decoder *json.Decoder,
	depth int,
	elements *int,
) (bool, error) {
	if depth > trustedToolResourceEnvelopeMaxJSONDepth {
		return false, errors.New("trusted tool resource JSON depth exceeded")
	}
	*elements = *elements + 1
	if *elements > toolValueLineageMaxJSONElements {
		return false, errors.New("trusted tool resource JSON element limit exceeded")
	}
	token, err := decoder.Token()
	if err != nil {
		return false, err
	}
	delimiter, composite := token.(json.Delim)
	if !composite {
		switch token.(type) {
		case string, json.Number, bool, nil:
			return false, nil
		default:
			return false, errors.New("trusted tool resource unsupported JSON scalar")
		}
	}

	switch delimiter {
	case '{':
		seen := make(map[string]struct{})
		for decoder.More() {
			keyToken, err := decoder.Token()
			if err != nil {
				return false, err
			}
			key, ok := keyToken.(string)
			if !ok || key == "" || strings.ContainsRune(key, 0) {
				return false, errors.New("trusted tool resource invalid JSON key")
			}
			folded := strings.ToLower(key)
			if _, duplicate := seen[folded]; duplicate {
				return false, errors.New("trusted tool resource duplicate JSON key")
			}
			seen[folded] = struct{}{}
			if _, err := consumeTrustedToolResourceJSONValue(decoder, depth+1, elements); err != nil {
				return false, err
			}
		}
		closing, err := decoder.Token()
		if err != nil || closing != json.Delim('}') {
			return false, errors.New("trusted tool resource invalid JSON object")
		}
		return true, nil
	case '[':
		for decoder.More() {
			if _, err := consumeTrustedToolResourceJSONValue(decoder, depth+1, elements); err != nil {
				return false, err
			}
		}
		closing, err := decoder.Token()
		if err != nil || closing != json.Delim(']') {
			return false, errors.New("trusted tool resource invalid JSON array")
		}
		return false, nil
	default:
		return false, errors.New("trusted tool resource invalid JSON delimiter")
	}
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

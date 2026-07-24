// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// SPDX-License-Identifier: Apache-2.0

package push

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"unicode/utf8"

	"github.com/defenseclaw/defenseclaw/internal/observability"
	"github.com/defenseclaw/defenseclaw/internal/observability/delivery"
)

const (
	maxHECWrapperBytes  = 64 * 1024
	maxHECResponseBytes = 64 * 1024
	// There are fewer than 32 compatibility aliases. At 256 source bytes
	// each, even JSON's six-byte HTML escapes plus bounded static metadata
	// remain below maxHECWrapperBytes.
	maxAliasValueBytes = 256
)

type SplunkHECConfig struct {
	Destination         string
	Endpoint            string
	Token               string
	Index               string
	Source              string
	SourceType          string
	SourceTypeOverrides map[string]string
	TLS                 TLSOptions
	Network             NetworkOptions
	Observer            WarningObserver
}

type SplunkHEC struct {
	endpoint            string
	token               string
	index               string
	source              string
	sourceType          string
	sourceTypeOverrides map[string]string
	client              *http.Client
	activation          ActivationState
}

var _ delivery.Adapter = (*SplunkHEC)(nil)

func NewSplunkHEC(ctx context.Context, config SplunkHECConfig) (*SplunkHEC, error) {
	if !validSecret(config.Token) ||
		!validBoundedWireValue(config.Index) ||
		!validBoundedWireValue(config.Source) ||
		!validBoundedWireValue(config.SourceType) {
		return nil, ErrInvalidConfig
	}
	overrides := make(map[string]string, len(config.SourceTypeOverrides))
	if len(config.SourceTypeOverrides) > 1024 {
		return nil, ErrInvalidConfig
	}
	for action, sourceType := range config.SourceTypeOverrides {
		if !observability.IsStableToken(action) ||
			!validBoundedWireValue(sourceType) || sourceType == "" {
			return nil, ErrInvalidConfig
		}
		overrides[action] = sourceType
	}
	prepared, err := prepareTransport(ctx, baseConfig{
		destination: config.Destination,
		endpoint:    config.Endpoint,
		tls:         config.TLS,
		network:     config.Network,
		observer:    config.Observer,
		credentials: true,
	})
	if err != nil {
		return nil, err
	}
	return &SplunkHEC{
		endpoint: prepared.endpoint.String(), token: config.Token,
		index: config.Index, source: config.Source, sourceType: config.SourceType,
		sourceTypeOverrides: overrides, client: prepared.client,
		activation: prepared.activation,
	}, nil
}

func (adapter *SplunkHEC) ActivationState() ActivationState {
	if adapter == nil {
		return ActivationDegraded
	}
	return adapter.activation
}

// CloseIdleConnections releases generation-local pooled connections.
func (adapter *SplunkHEC) CloseIdleConnections() {
	if adapter != nil && adapter.client != nil {
		adapter.client.CloseIdleConnections()
	}
}

// EncodedSize reserves the normative, conservative 64-KiB per-record wrapper
// allowance. The immutable projected bytes themselves are never escaped or
// duplicated by the estimator.
func (*SplunkHEC) EncodedSize(projectedSizes []int) (int, bool) {
	total := 0
	for _, size := range projectedSizes {
		if size < 0 || total > int(^uint(0)>>1)-size-maxHECWrapperBytes {
			return 0, false
		}
		total += size + maxHECWrapperBytes
	}
	return total, true
}

func (adapter *SplunkHEC) Deliver(ctx context.Context, batch delivery.Batch) delivery.DeliveryResult {
	if adapter == nil || ctx == nil || batch.Len() == 0 {
		return delivery.DeliveryResult{Outcome: delivery.OutcomePermanentPayload}
	}
	var body bytes.Buffer
	if batch.EncodedSize() > 0 {
		body.Grow(batch.EncodedSize())
	}
	for _, item := range batch.Items() {
		projected := item.Bytes()
		aliases, action, ok := projectedAliases(projected)
		if !ok {
			return delivery.DeliveryResult{Outcome: delivery.OutcomePermanentPayload}
		}
		sourceType := adapter.sourceType
		if override, found := adapter.sourceTypeOverrides[action]; found {
			sourceType = override
		}
		envelope := hecEnvelope{
			Index: adapter.index, Source: adapter.source, SourceType: sourceType,
			Event: hecEvent{Record: json.RawMessage(projected), Aliases: aliases},
		}
		encoded, err := encodeHECEnvelope(envelope)
		if err != nil || len(encoded)+1 > len(projected)+maxHECWrapperBytes ||
			body.Len() > batch.EncodedSize()-len(encoded)-1 {
			return delivery.DeliveryResult{Outcome: delivery.OutcomePermanentPayload}
		}
		_, _ = body.Write(encoded)
		_ = body.WriteByte('\n')
	}
	if body.Len() > batch.EncodedSize() {
		return delivery.DeliveryResult{Outcome: delivery.OutcomePermanentPayload}
	}
	writeTracker := &requestWriteTracker{}
	req, err := http.NewRequestWithContext(writeTracker.traceContext(ctx), http.MethodPost, adapter.endpoint, bytes.NewReader(body.Bytes()))
	if err != nil {
		return delivery.DeliveryResult{Outcome: delivery.OutcomePermanentPayload}
	}
	req.Header.Set("Authorization", "Splunk "+adapter.token)
	req.Header.Set("Content-Type", "application/json")
	resp, err := adapter.client.Do(req)
	if err != nil {
		if resp != nil && resp.Body != nil {
			_ = resp.Body.Close()
		}
		return delivery.DeliveryResult{Outcome: classifyTransportError(err, writeTracker.mayHaveReachedPeer())}
	}
	defer resp.Body.Close()
	if outcome := classifyHTTPStatus(resp.StatusCode); outcome != delivery.OutcomeDelivered {
		_, _ = io.CopyN(io.Discard, resp.Body, 4096)
		return delivery.DeliveryResult{Outcome: outcome}
	}
	return delivery.DeliveryResult{Outcome: classifyHECAcknowledgement(resp.Body)}
}

type hecEnvelope struct {
	Index      string   `json:"index,omitempty"`
	Source     string   `json:"source,omitempty"`
	SourceType string   `json:"sourcetype,omitempty"`
	Event      hecEvent `json:"event"`
}

type hecEvent struct {
	Record  json.RawMessage    `json:"record"`
	Aliases compatibilityAlias `json:"-"` // flattened by encodeHECEnvelope
}

// encodeHECEnvelope deliberately writes Record without asking encoding/json to
// marshal json.RawMessage. encoding/json may HTML-escape bytes returned by a
// Marshaler, which would make the embedded projection semantically equivalent
// but no longer byte-identical. Static wrapper fields and aliases still use the
// standard encoder.
func encodeHECEnvelope(envelope hecEnvelope) ([]byte, error) {
	if !json.Valid(envelope.Event.Record) {
		return nil, ErrInvalidConfig
	}
	aliases, err := json.Marshal(envelope.Event.Aliases)
	if err != nil {
		return nil, ErrInvalidConfig
	}
	var encoded bytes.Buffer
	encoded.WriteByte('{')
	fields := 0
	for _, field := range []struct {
		name  string
		value string
	}{
		{"index", envelope.Index},
		{"source", envelope.Source},
		{"sourcetype", envelope.SourceType},
	} {
		if field.value == "" {
			continue
		}
		if fields > 0 {
			encoded.WriteByte(',')
		}
		value, marshalErr := json.Marshal(field.value)
		if marshalErr != nil {
			return nil, ErrInvalidConfig
		}
		encoded.WriteString(`"` + field.name + `":`)
		encoded.Write(value)
		fields++
	}
	if fields > 0 {
		encoded.WriteByte(',')
	}
	encoded.WriteString(`"event":{"record":`)
	encoded.Write(envelope.Event.Record)
	if len(aliases) > 2 {
		encoded.WriteByte(',')
		encoded.Write(aliases[1 : len(aliases)-1])
	}
	encoded.WriteString("}}")
	return encoded.Bytes(), nil
}

type compatibilityAlias struct {
	ID                  string `json:"id,omitempty"`
	RecordID            string `json:"record_id,omitempty"`
	Timestamp           string `json:"timestamp,omitempty"`
	Bucket              string `json:"bucket,omitempty"`
	EventName           string `json:"event_name,omitempty"`
	Severity            string `json:"severity,omitempty"`
	Source              string `json:"source,omitempty"`
	Connector           string `json:"connector,omitempty"`
	Action              string `json:"action,omitempty"`
	Outcome             string `json:"outcome,omitempty"`
	SemanticEventID     string `json:"semantic_event_id,omitempty"`
	LogicalEventID      string `json:"logical_event_id,omitempty"`
	ConnectorInstanceID string `json:"connector_instance_id,omitempty"`
	RunID               string `json:"run_id,omitempty"`
	RequestID           string `json:"request_id,omitempty"`
	SessionID           string `json:"session_id,omitempty"`
	TurnID              string `json:"turn_id,omitempty"`
	TraceID             string `json:"trace_id,omitempty"`
	AgentID             string `json:"agent_id,omitempty"`
	AgentInstanceID     string `json:"agent_instance_id,omitempty"`
	SidecarInstanceID   string `json:"sidecar_instance_id,omitempty"`
	PolicyID            string `json:"policy_id,omitempty"`
	ModelRequestID      string `json:"model_request_id,omitempty"`
	ModelResponseID     string `json:"model_response_id,omitempty"`
	ToolInvocationID    string `json:"tool_invocation_id,omitempty"`
	ConnectorID         string `json:"connector_id,omitempty"`
	Actor               string `json:"actor,omitempty"`
	Target              string `json:"target,omitempty"`
	Details             string `json:"details,omitempty"`
	ToolName            string `json:"tool_name,omitempty"`
	ToolID              string `json:"tool_id,omitempty"`
	DestinationApp      string `json:"destination_app,omitempty"`
	AgentName           string `json:"agent_name,omitempty"`
}

func projectedAliases(projected []byte) (compatibilityAlias, string, bool) {
	if !utf8.Valid(projected) {
		return compatibilityAlias{}, "", false
	}
	decoder := json.NewDecoder(bytes.NewReader(projected))
	decoder.UseNumber()
	var wire map[string]any
	if err := decoder.Decode(&wire); err != nil || wire == nil || containsOpaqueHEC(wire) {
		return compatibilityAlias{}, "", false
	}
	if decoder.Decode(&struct{}{}) != io.EOF {
		return compatibilityAlias{}, "", false
	}
	alias := compatibilityAlias{
		RecordID: stringAt(wire, "record_id"), Timestamp: stringAt(wire, "timestamp"),
		Bucket: stringAt(wire, "bucket"), EventName: stringAt(wire, "event_name"),
		Severity: stringAt(wire, "severity"), Source: stringAt(wire, "source"),
		Connector: stringAt(wire, "connector"), Action: stringAt(wire, "action"),
		Outcome: stringAt(wire, "outcome"),
	}
	alias.ID = alias.RecordID
	if correlation, ok := wire["correlation"].(map[string]any); ok {
		alias.SemanticEventID = stringAt(correlation, "semantic_event_id")
		alias.LogicalEventID = stringAt(correlation, "logical_event_id")
		alias.ConnectorInstanceID = stringAt(correlation, "connector_instance_id")
		alias.RunID = stringAt(correlation, "run_id")
		alias.RequestID = stringAt(correlation, "request_id")
		alias.SessionID = stringAt(correlation, "session_id")
		alias.TurnID = stringAt(correlation, "turn_id")
		alias.TraceID = stringAt(correlation, "trace_id")
		alias.AgentID = stringAt(correlation, "agent_id")
		alias.AgentInstanceID = stringAt(correlation, "agent_instance_id")
		alias.SidecarInstanceID = stringAt(correlation, "sidecar_instance_id")
		alias.PolicyID = stringAt(correlation, "policy_id")
		alias.ModelRequestID = stringAt(correlation, "model_request_id")
		alias.ModelResponseID = stringAt(correlation, "model_response_id")
		alias.ToolInvocationID = stringAt(correlation, "tool_invocation_id")
		alias.ConnectorID = stringAt(correlation, "connector_id")
	}
	if body, ok := wire["body"].(map[string]any); ok {
		alias.Actor = stringAt(body, "actor")
		alias.Target = stringAt(body, "target")
		alias.Details = firstStringAt(body, "details", "message", "description")
		alias.ToolName = stringAt(body, "tool_name")
		alias.ToolID = stringAt(body, "tool_id")
		alias.DestinationApp = stringAt(body, "destination_app")
		alias.AgentName = stringAt(body, "agent_name")
	}
	if alias.Actor == "" {
		if provenance, ok := wire["provenance"].(map[string]any); ok {
			alias.Actor = stringAt(provenance, "producer")
		}
	}
	return alias, alias.Action, true
}

func containsOpaqueHEC(value any) bool {
	switch typed := value.(type) {
	case map[string]any:
		for key, child := range typed {
			if key == "_splunk_hec_events" || containsOpaqueHEC(child) {
				return true
			}
		}
	case []any:
		for _, child := range typed {
			if containsOpaqueHEC(child) {
				return true
			}
		}
	}
	return false
}

func stringAt(object map[string]any, key string) string {
	value, ok := object[key].(string)
	if !ok || value == "" || len(value) > maxAliasValueBytes || !validBoundedWireValue(value) {
		return ""
	}
	return value
}

func firstStringAt(object map[string]any, keys ...string) string {
	for _, key := range keys {
		if value := stringAt(object, key); value != "" {
			return value
		}
	}
	return ""
}

func classifyHECAcknowledgement(body io.Reader) delivery.DeliveryOutcome {
	limited := io.LimitReader(body, maxHECResponseBytes+1)
	encoded, err := io.ReadAll(limited)
	if err != nil || len(encoded) == 0 || len(encoded) > maxHECResponseBytes {
		return delivery.OutcomeAmbiguous
	}
	decoder := json.NewDecoder(bytes.NewReader(encoded))
	var acknowledgement struct {
		Code *int   `json:"code"`
		Text string `json:"text,omitempty"`
	}
	if decoder.Decode(&acknowledgement) != nil || decoder.Decode(&struct{}{}) != io.EOF || acknowledgement.Code == nil {
		return delivery.OutcomeAmbiguous
	}
	switch *acknowledgement.Code {
	case 0:
		return delivery.OutcomeDelivered
	case 1, 2, 3, 4:
		return delivery.OutcomeAuthentication
	case 8, 9:
		return delivery.OutcomeTransient
	default:
		return delivery.OutcomePermanentPayload
	}
}

// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
// SPDX-License-Identifier: Apache-2.0

package telemetry

import (
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"

	"google.golang.org/protobuf/encoding/protojson"

	collogspb "go.opentelemetry.io/proto/otlp/collector/logs/v1"
	logspb "go.opentelemetry.io/proto/otlp/logs/v1"
)

// CiscoAIDefenseTelemetryPath is the AI Defense event-ingest path appended to
// the configured cisco_ai_defense.endpoint host to receive DefenseClaw's OTEL
// log events. It reuses the inspection host (the installer renders the
// per-environment endpoint into cisco_ai_defense.endpoint), so no dedicated
// telemetry endpoint config is required. Note the "/api" prefix, matching the
// inspection route (/api/v1/inspect/defense_claw): the bare /v1/... path is a
// different (unauthorized) route and is rejected with HTTP 403.
const CiscoAIDefenseTelemetryPath = "/api/v1/defenseclaw/events/ingest"

// ciscoAIDefenseIngestURL derives the telemetry ingest URL from the configured
// inspection endpoint, mirroring how CiscoDefenseClawInspectClient builds its
// inspect URL (TrimRight("/") + path).
func ciscoAIDefenseIngestURL(endpoint string) string {
	return strings.TrimRight(strings.TrimSpace(endpoint), "/") + CiscoAIDefenseTelemetryPath
}

// marshalLogsPayload converts OTLP ResourceLogs into the AI Defense ingest
// request body: the OTLP-JSON ExportLogsServiceRequest ({"resourceLogs":[...]})
// wrapped in the required {"payload": {...}} envelope.
//
// The OTLP/JSON spec requires trace_id / span_id as lowercase hex and 64-bit
// timestamps as decimal strings. protojson satisfies the string-timestamp rule
// (proto3 JSON maps 64-bit ints to strings) and, with UseEnumNumbers, emits the
// numeric severity_number the sample shows. It does, however, base64-encode the
// bytes-typed trace_id / span_id fields, so those are re-encoded to hex below.
func marshalLogsPayload(rls []*logspb.ResourceLogs) ([]byte, error) {
	inner, err := marshalLogsInner(rls)
	if err != nil {
		return nil, err
	}
	var buf bytes.Buffer
	buf.Grow(len(inner) + len(`{"payload":}`))
	buf.WriteString(`{"payload":`)
	buf.Write(inner)
	buf.WriteByte('}')
	return buf.Bytes(), nil
}

// marshalLogsInner produces the bare OTLP/JSON ExportLogsServiceRequest
// ({"resourceLogs":[...]}) with hex trace/span IDs — i.e. marshalLogsPayload
// without the AI Defense {"payload": ...} envelope.
func marshalLogsInner(rls []*logspb.ResourceLogs) ([]byte, error) {
	req := &collogspb.ExportLogsServiceRequest{ResourceLogs: rls}
	inner, err := protojson.MarshalOptions{UseEnumNumbers: true}.Marshal(req)
	if err != nil {
		return nil, fmt.Errorf("cisco ai defense telemetry: marshal logs: %w", err)
	}
	inner, err = hexEncodeTraceSpanIDs(inner)
	if err != nil {
		return nil, fmt.Errorf("cisco ai defense telemetry: encode ids: %w", err)
	}
	return inner, nil
}

// hexEncodeTraceSpanIDs rewrites the base64 OTLP-JSON trace_id / span_id fields
// emitted by protojson into the lowercase-hex form the OTLP/JSON spec (and the
// AI Defense ingest API) expects. Only the reserved "traceId" / "spanId" object
// keys are touched; bytes-valued log attributes / bodies stay base64, which is
// correct for those fields.
func hexEncodeTraceSpanIDs(data []byte) ([]byte, error) {
	var root any
	if err := json.Unmarshal(data, &root); err != nil {
		return nil, err
	}
	convertTraceSpanIDs(root)
	return json.Marshal(root)
}

func convertTraceSpanIDs(node any) {
	switch v := node.(type) {
	case map[string]any:
		for key, val := range v {
			if key == "traceId" || key == "spanId" {
				if s, ok := val.(string); ok {
					if decoded, err := base64.StdEncoding.DecodeString(s); err == nil {
						v[key] = hex.EncodeToString(decoded)
					}
				}
				continue
			}
			convertTraceSpanIDs(val)
		}
	case []any:
		for _, item := range v {
			convertTraceSpanIDs(item)
		}
	}
}

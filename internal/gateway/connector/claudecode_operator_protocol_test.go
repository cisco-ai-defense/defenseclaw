// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package connector

import "testing"

// An operator's traces-only collector keeps the generic
// OTEL_EXPORTER_OTLP_PROTOCOL it relies on; a protocol host Setup wrote
// itself is still the product's (GAP-1871).
func TestClaudeCodeOperatorSignalRouteKeepsTheGenericProtocol(t *testing.T) {
	existing := map[string]interface{}{
		"OTEL_TRACES_EXPORTER":               "otlp",
		"OTEL_EXPORTER_OTLP_PROTOCOL":        "http/protobuf",
		"OTEL_EXPORTER_OTLP_TRACES_ENDPOINT": "https://collector.example.test/v1/traces",
	}
	if keep := claudeCodeOperatorOtelSettings(existing, map[string]string{}, nil); !keep["OTEL_EXPORTER_OTLP_PROTOCOL"] ||
		!keep["OTEL_EXPORTER_OTLP_TRACES_ENDPOINT"] || !keep["OTEL_TRACES_EXPORTER"] {
		t.Fatalf("operator traces route lost its settings: %v", keep)
	}
	previous := map[string]string{"OTEL_EXPORTER_OTLP_PROTOCOL": "http/protobuf"}
	if keep := claudeCodeOperatorOtelSettings(existing, previous, nil); keep["OTEL_EXPORTER_OTLP_PROTOCOL"] {
		t.Fatalf("a protocol host Setup wrote was kept as the operator's: %v", keep)
	}
	delete(existing, "OTEL_EXPORTER_OTLP_TRACES_ENDPOINT")
	if keep := claudeCodeOperatorOtelSettings(existing, map[string]string{}, nil); len(keep) != 0 {
		t.Fatalf("no operator route, yet settings kept: %v", keep)
	}
}

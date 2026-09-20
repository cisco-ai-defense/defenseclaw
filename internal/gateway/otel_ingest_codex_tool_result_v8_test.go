// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/gatewaylog"
	"github.com/defenseclaw/defenseclaw/internal/observability"
	collectorlogspb "go.opentelemetry.io/proto/otlp/collector/logs/v1"
	"google.golang.org/protobuf/encoding/protojson"
)

const codexToolResultSourceRevision = "f90e7deea6a715bbd153044af6f475eefa749177"

func TestOTLPInboundCodexToolResultSourceFixtureClassifiesAndImports(t *testing.T) {
	request := loadCodexToolResultSourceFixture(t)
	var leaf otlpDecodedLeaf
	stats, err := walkDecodedOTLPLeaves(request, otelSignalLogs, func(candidate otlpDecodedLeaf) error {
		if leaf.logRecord != nil {
			t.Fatal("source fixture contains more than one log record")
		}
		leaf = candidate
		return nil
	})
	if err != nil || stats.Records != 1 || leaf.logRecord == nil {
		t.Fatalf("walk source fixture stats=%+v leaf=%+v err=%v", stats, leaf, err)
	}

	classifier := mustOTLPInboundClassifierV8(t)
	classification, err := classifier.classify(leaf, "codex")
	if err != nil || classification.identityState != otlpInboundIdentityMatched ||
		classification.match.ID() != "otlp.codex.tool_result.v1.log.tool.invocation.completed" ||
		classification.match.MappingStrategy() != observability.InboundMappingConnectorToolLog {
		t.Fatalf("Codex tool-result classification=%+v err=%v", classification, err)
	}
	wrongSource, err := classifier.classify(leaf, "claudecode")
	if err != nil || wrongSource.identityState != otlpInboundIdentityUnsupported {
		t.Fatalf("wrong-source classification=%+v err=%v", wrongSource, err)
	}

	previousInstance := gatewaylog.SidecarInstanceID()
	gatewaylog.SetSidecarInstanceID("otlp-inbound-codex-tool-result-source-fixture")
	t.Cleanup(func() { gatewaylog.SetSidecarInstanceID(previousInstance) })
	fixture := newOTLPV8MetricFixture(t)
	api := &APIServer{}
	api.bindOTLPObservabilityRuntime(fixture.runtime)
	accounting, err := api.importDecodedOTLPRequestV8(
		context.Background(), request, otelSignalLogs, "codex", time.Now().UTC(),
	)
	if err != nil || !accounting.valid() || accounting.imported != 1 {
		t.Fatalf("Codex tool-result accounting=%+v err=%v", accounting, err)
	}

	record := inboundStoredProjectedRecord(t, fixture.path, "codex", "tool.invocation.completed")
	if record["outcome"] != "completed" {
		t.Fatalf("outcome=%#v", record["outcome"])
	}
	correlation, ok := record["correlation"].(map[string]any)
	if !ok || correlation["session_id"] != "conversation-native-tool-1" {
		t.Fatalf("correlation=%#v", record["correlation"])
	}
	body, ok := record["body"].(map[string]any)
	if !ok {
		t.Fatalf("body=%#v", record["body"])
	}
	if body["gen_ai.operation.name"] != "execute_tool" ||
		body["gen_ai.tool.name"] != "shell" ||
		body["gen_ai.tool.call.id"] != "codex-call-source-backed-1" {
		t.Fatalf("tool identity fields=%#v", body)
	}
	arguments, argumentsOK := body["gen_ai.tool.call.arguments"].(map[string]any)
	result, resultOK := body["gen_ai.tool.call.result"].(map[string]any)
	if !argumentsOK || arguments["command"] != "true" ||
		!resultOK || result["content"] != "ok" {
		t.Fatalf("tool payload arguments=%#v result=%#v", arguments, result)
	}
}

func loadCodexToolResultSourceFixture(t *testing.T) *collectorlogspb.ExportLogsServiceRequest {
	t.Helper()
	path := filepath.Join(
		"testdata", "correlation", "codex", codexToolResultSourceRevision, "tool-result.logs.json",
	)
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	request := &collectorlogspb.ExportLogsServiceRequest{}
	if err := protojson.Unmarshal(raw, request); err != nil {
		t.Fatalf("decode %s: %v", path, err)
	}
	return request
}

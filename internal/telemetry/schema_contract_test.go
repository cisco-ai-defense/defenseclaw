// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     https://www.apache.org/licenses/LICENSE-2.0
//
// SPDX-License-Identifier: Apache-2.0

package telemetry

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"testing"
	"time"

	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/sdk/resource"
	"go.opentelemetry.io/otel/sdk/trace/tracetest"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/gatewaylog"
	"github.com/defenseclaw/defenseclaw/internal/redaction"
)

type runtimeSpanSchema struct {
	RequiredAttributes []string `json:"x-required-attribute-keys"`
	OptionalAttributes []string `json:"x-optional-attribute-keys"`
	Properties         struct {
		Name struct {
			Pattern string `json:"pattern"`
		} `json:"name"`
		Kind struct {
			Const int `json:"const"`
		} `json:"kind"`
	} `json:"properties"`
	Defs struct {
		AttributeDefinitions struct {
			Properties map[string]json.RawMessage `json:"properties"`
		} `json:"attributeDefinitions"`
	} `json:"$defs"`
}

func loadRuntimeSpanSchema(t *testing.T, name string) runtimeSpanSchema {
	t.Helper()
	_, currentFile, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller failed")
	}
	path := filepath.Join(filepath.Dir(currentFile), "..", "..", "schemas", "otel", name)
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	var schema runtimeSpanSchema
	if err := json.Unmarshal(raw, &schema); err != nil {
		t.Fatalf("decode %s: %v", path, err)
	}
	return schema
}

func assertSpanMatchesRuntimeSchema(
	t *testing.T,
	span tracetest.SpanStub,
	schemaName string,
) {
	t.Helper()
	schema := loadRuntimeSpanSchema(t, schemaName)
	matched, err := regexp.MatchString(schema.Properties.Name.Pattern, span.Name)
	if err != nil || !matched {
		t.Fatalf("%s name=%q does not match %q (err=%v)", schemaName, span.Name, schema.Properties.Name.Pattern, err)
	}
	if int(span.SpanKind) != schema.Properties.Kind.Const {
		t.Fatalf("%s kind=%d want %d", schemaName, span.SpanKind, schema.Properties.Kind.Const)
	}

	emitted := make(map[string]struct{}, len(span.Attributes))
	for _, item := range span.Attributes {
		key := string(item.Key)
		emitted[key] = struct{}{}
		if _, declared := schema.Defs.AttributeDefinitions.Properties[key]; !declared {
			t.Errorf("%s emitted undeclared attribute %q", schemaName, key)
		}
	}
	for _, key := range schema.RequiredAttributes {
		if _, ok := emitted[key]; !ok {
			t.Errorf("%s missing required emitted attribute %q", schemaName, key)
		}
	}
	optional := make(map[string]struct{}, len(schema.OptionalAttributes))
	for _, key := range schema.OptionalAttributes {
		optional[key] = struct{}{}
		if _, declared := schema.Defs.AttributeDefinitions.Properties[key]; !declared {
			t.Errorf("%s lists undeclared optional attribute %q", schemaName, key)
		}
	}
	for key := range schema.Defs.AttributeDefinitions.Properties {
		if _, ok := emitted[key]; !ok {
			if _, allowed := optional[key]; allowed {
				continue
			}
			t.Errorf("%s declares stale/unexercised attribute %q", schemaName, key)
		}
	}
}

func oneRecordedSpan(t *testing.T, exporter *tracetest.InMemoryExporter) tracetest.SpanStub {
	t.Helper()
	spans := exporter.GetSpans()
	if len(spans) != 1 {
		t.Fatalf("got %d spans, want 1", len(spans))
	}
	return spans[0]
}

func attachAllSchemaSpanContext(p *Provider) {
	p.res = resource.NewSchemaless(
		attribute.String("tenant.id", "tenant-schema"),
		attribute.String("workspace.id", "workspace-schema"),
		attribute.String("deployment.environment", "test"),
		attribute.String("deployment.mode", "unmanaged_byod"),
		attribute.String("discovery.source", "registry"),
		attribute.String("defenseclaw.device.id", "device-schema"),
	)
}

func TestRuntimeLLMSpanSchemaMatchesEmitter(t *testing.T) {
	redaction.SetDisableAll(true)
	t.Cleanup(func() { redaction.SetDisableAll(false) })
	gatewaylog.SetProcessRunID("run-schema")
	t.Cleanup(func() { gatewaylog.SetProcessRunID("") })

	p, exporter := newTracingProvider(t)
	attachAllSchemaSpanContext(p)
	_, span := p.StartLLMSpan(context.Background(), "openai", "gpt-4o-mini", "openai", 128, 0.2)
	p.SetGenAIInput(span, "schema input")
	p.SetGenAIOutput(span, "schema output")
	for _, item := range []attribute.KeyValue{
		attribute.String("defenseclaw.llm.request.body", "request"),
		attribute.String("defenseclaw.llm.response.body", "response"),
		attribute.String("defenseclaw.llm.response.content", "content"),
		attribute.String("defenseclaw.llm.response.raw_content", "raw-content"),
		attribute.Bool(telemetryCanaryAttribute, true),
	} {
		span.SetAttributes(item)
	}
	p.EndLLMSpan(
		context.Background(), span, "gpt-4o-mini", 8, 4, []string{"stop"}, 1,
		"local", "pass", "openai", time.Now(), "codex", "ide", "agent-1", "session-1",
	)
	assertSpanMatchesRuntimeSchema(t, oneRecordedSpan(t, exporter), "runtime-llm-span.schema.json")
}

func TestRuntimeAgentSpanSchemaMatchesEmitter(t *testing.T) {
	gatewaylog.SetProcessRunID("run-schema")
	t.Cleanup(func() { gatewaylog.SetProcessRunID("") })
	p, exporter := newTracingProvider(t)
	attachAllSchemaSpanContext(p)
	p.SetAgentInstanceID("instance-1")
	_, span := p.StartAgentSpan(
		context.Background(), "session-1", "codex", "ide", "agent-1", "openai", "codex",
	)
	p.SetGenAIInput(span, "schema agent input")
	p.SetGenAIOutput(span, "schema agent output")
	span.SetAttributes(
		attribute.Bool(telemetryCanaryAttribute, true),
	)
	p.EndAgentSpan(span, "")
	assertSpanMatchesRuntimeSchema(t, oneRecordedSpan(t, exporter), "runtime-agent-span.schema.json")
}

func TestRuntimeToolSpanSchemaMatchesEmitter(t *testing.T) {
	redaction.SetDisableAll(true)
	t.Cleanup(func() { redaction.SetDisableAll(false) })
	p, exporter := newTracingProvider(t)
	attachAllSchemaSpanContext(p)
	p.SetAgentInstanceID("instance-1")
	_, span := p.StartToolSpan(
		context.Background(), "shell", "requested", json.RawMessage(`{"command":"pwd"}`),
		true, "dangerous-pattern", "builtin", "skill-1",
		ToolSpanContext{
			ToolID: "tool-1", SessionID: "session-1", RunID: "run-1",
			DestinationApp: "builtin", PolicyID: "policy-1",
			AgentName: "codex", AgentType: "ide", AgentID: "agent-1",
		},
	)
	p.SetGenAIToolResult(span, "schema tool result")
	p.EndToolSpan(span, 0, 12, time.Now(), "shell", "builtin")
	assertSpanMatchesRuntimeSchema(t, oneRecordedSpan(t, exporter), "runtime-tool-span.schema.json")
}

func TestRuntimeApprovalSpanSchemaMatchesEmitter(t *testing.T) {
	redaction.SetDisableAll(true)
	t.Cleanup(func() { redaction.SetDisableAll(false) })
	p, exporter := newTracingProvider(t)
	attachAllSchemaSpanContext(p)
	p.SetAgentInstanceID("instance-1")
	_, span := p.StartApprovalSpan(
		context.Background(), "approval-1", "/usr/bin/pwd", []string{"pwd"}, "/tmp",
		ToolSpanContext{
			ToolID: "tool-1", SessionID: "session-1", RunID: "run-1",
			DestinationApp: "builtin", PolicyID: "policy-1",
			AgentName: "codex", AgentType: "ide", AgentID: "agent-1",
		},
	)
	p.EndApprovalSpan(span, "approved", "operator approved", false, false)
	assertSpanMatchesRuntimeSchema(t, oneRecordedSpan(t, exporter), "runtime-approval-span.schema.json")
}

func TestGalileoExportProfileMatchesRuntimeFilter(t *testing.T) {
	_, currentFile, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller failed")
	}
	path := filepath.Join(filepath.Dir(currentFile), "..", "..", "schemas", "otel", "galileo-export-profile.schema.json")
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var profile struct {
		Properties struct {
			Operations struct {
				Const []struct {
					Name              string   `json:"name"`
					RequireAttributes []string `json:"required_attributes"`
				} `json:"const"`
			} `json:"operations"`
		} `json:"properties"`
	}
	if err := json.Unmarshal(raw, &profile); err != nil {
		t.Fatal(err)
	}
	filter := config.OTelSpanFilterConfig{}
	for _, operation := range profile.Properties.Operations.Const {
		filter.Operations = append(filter.Operations, config.OTelSpanFilterOperationConfig{
			Name: operation.Name, RequireAttributes: operation.RequireAttributes,
		})
	}
	if !filter.Enabled() || len(filter.Operations) == 0 {
		t.Fatalf("Galileo profile does not produce an enabled runtime filter: %+v", filter)
	}
	requiredOperations := map[string]bool{
		"chat": true, "invoke_agent": true, "execute_tool": true,
	}
	for _, operation := range filter.Operations {
		if operation.Name == "" || len(operation.RequireAttributes) == 0 {
			t.Fatalf("Galileo profile contains an incomplete operation: %+v", operation)
		}
		delete(requiredOperations, operation.Name)
	}
	if len(requiredOperations) != 0 {
		t.Fatalf("Galileo profile is missing required operations: %v", requiredOperations)
	}
}

// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// SPDX-License-Identifier: Apache-2.0

package otlp

import (
	"context"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/observability"
	resourcepb "go.opentelemetry.io/proto/otlp/resource/v1"
)

func TestLogAdapterSnapshotsGenerationResourceAndIsolatesSiblings(t *testing.T) {
	config := Config{
		Destination: "resource-snapshot", Protocol: ProtocolHTTPProtobuf,
		Endpoint: "https://8.8.8.8:4318", Selected: []observability.Signal{observability.SignalLogs},
		Timeout: time.Second,
	}
	values := map[string]string{
		"service.name":                   "defenseclaw",
		"service.instance.id":            "generation-one",
		"deployment.environment.name":    "production",
		"deployment.environment":         "production",
		"defenseclaw.custom.team.name":   "security-platform",
		"defenseclaw.custom.region.name": "east",
	}
	snapshot := LogResourceSnapshot{
		SchemaURL: "https://opentelemetry.io/schemas/1.42.0", Values: values,
		DroppedAttributesCount: 7,
	}
	firstFactory := prepareTestFactory(t, config, Dependencies{})
	secondFactory := prepareTestFactory(t, config, Dependencies{})
	first, err := firstFactory.NewLogAdapter(context.Background(), snapshot)
	if err != nil {
		t.Fatal(err)
	}
	second, err := secondFactory.NewLogAdapter(context.Background(), snapshot)
	if err != nil {
		t.Fatal(err)
	}

	// Neither the source map nor an independently prepared sibling may alias
	// another generation's protobuf resource.
	values["service.instance.id"] = "mutated-source"
	delete(values, "defenseclaw.custom.team.name")
	if got := protoLogResourceValue(first.builder.resource, "service.instance.id"); got != "generation-one" {
		t.Fatalf("first adapter observed source mutation: %q", got)
	}
	if got := protoLogResourceValue(second.builder.resource, "defenseclaw.custom.team.name"); got != "security-platform" {
		t.Fatalf("second adapter observed source mutation: %q", got)
	}
	first.builder.resource.Attributes[0].Value.Value = nil
	first.builder.resource.DroppedAttributesCount = 99
	if got := protoLogResourceValue(second.builder.resource, "service.name"); got != "defenseclaw" ||
		second.builder.resource.DroppedAttributesCount != 7 || second.builder.resourceURL != snapshot.SchemaURL {
		t.Fatalf("sibling resource was not isolated: service=%q dropped=%d schema=%q", got, second.builder.resource.DroppedAttributesCount, second.builder.resourceURL)
	}
}

func TestLogAdapterRejectsIncompleteGenerationResource(t *testing.T) {
	for name, snapshot := range map[string]LogResourceSnapshot{
		"missing schema": {Values: map[string]string{"service.name": "defenseclaw"}},
		"missing values": {SchemaURL: "https://opentelemetry.io/schemas/1.42.0"},
		"blank key": {
			SchemaURL: "https://opentelemetry.io/schemas/1.42.0", Values: map[string]string{" ": "value"},
		},
		"blank value": {
			SchemaURL: "https://opentelemetry.io/schemas/1.42.0", Values: map[string]string{"service.name": ""},
		},
	} {
		t.Run(name, func(t *testing.T) {
			factory := prepareTestFactory(t, Config{
				Destination: "invalid-resource", Protocol: ProtocolHTTPProtobuf,
				Endpoint: "https://8.8.8.8:4318", Selected: []observability.Signal{observability.SignalLogs},
				Timeout: time.Second,
			}, Dependencies{})
			if adapter, err := factory.NewLogAdapter(context.Background(), snapshot); err == nil || adapter != nil {
				t.Fatalf("adapter=%T error=%v", adapter, err)
			}
		})
	}
}

func protoLogResourceValue(resource *resourcepb.Resource, key string) string {
	for _, attribute := range resource.GetAttributes() {
		if attribute != nil && attribute.Key == key && attribute.Value != nil {
			return attribute.Value.GetStringValue()
		}
	}
	return ""
}

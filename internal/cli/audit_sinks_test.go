// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/config"
)

// These tests pin the config → sinks.Manager translation layer. They are
// cheap to run because they never talk to a real collector: OTLP sinks
// use loopback + insecure, Splunk/HTTPJSONL sinks do not open connections
// until the first Forward() call.

func TestBuildAuditSinks_SkipsDisabledEntries(t *testing.T) {
	sinks := []config.AuditSink{
		{
			Name: "disabled-splunk", Kind: config.SinkKindSplunkHEC, Enabled: false,
			SplunkHEC: &config.SplunkHECSinkConfig{Endpoint: "https://s.example:8088", Token: "t"},
		},
		{
			Name: "live-splunk", Kind: config.SinkKindSplunkHEC, Enabled: true,
			SplunkHEC: &config.SplunkHECSinkConfig{Endpoint: "https://s.example:8088", Token: "t"},
		},
	}

	mgr, err := buildAuditSinks(sinks, "test")
	if err != nil {
		t.Fatalf("buildAuditSinks err=%v", err)
	}
	if mgr.Len() != 1 {
		t.Fatalf("Len=%d want 1 (disabled entry must be skipped)", mgr.Len())
	}
	if got := mgr.Sinks()[0].Name(); got != "live-splunk" {
		t.Fatalf("registered sink name=%q", got)
	}
}

func TestBuildAuditSinks_AggregatesBadEntriesButKeepsGoodOnes(t *testing.T) {
	sinks := []config.AuditSink{
		// Valid OTLP (loopback + insecure → no collector required)
		{
			Name: "good", Kind: config.SinkKindOTLPLogs, Enabled: true,
			OTLPLogs: &config.OTLPLogsSinkConfig{
				Endpoint: "127.0.0.1:4318", Protocol: "http", Insecure: true,
			},
		},
		// Broken Splunk → unresolved token, must produce an error
		{
			Name: "broken-splunk", Kind: config.SinkKindSplunkHEC, Enabled: true,
			SplunkHEC: &config.SplunkHECSinkConfig{
				Endpoint: "https://splunk.example:8088",
				TokenEnv: "DC_MISSING_TOKEN_ENV_XYZ",
			},
		},
		// Broken http_jsonl → missing URL
		{
			Name: "broken-http", Kind: config.SinkKindHTTPJSONL, Enabled: true,
			HTTPJSONL: &config.HTTPJSONLSinkConfig{URL: ""},
		},
	}

	mgr, err := buildAuditSinks(sinks, "v0")
	if err == nil {
		t.Fatal("expected aggregated error for broken sinks")
	}
	// Both broken entries must be surfaced with their name + kind so the
	// operator can fix them without guessing.
	msg := err.Error()
	for _, needle := range []string{"broken-splunk", "splunk_hec", "broken-http", "http_jsonl"} {
		if !strings.Contains(msg, needle) {
			t.Errorf("error missing %q: %s", needle, msg)
		}
	}

	if mgr.Len() != 1 {
		t.Fatalf("Len=%d want 1 (good sink must still register)", mgr.Len())
	}
	if got := mgr.Sinks()[0].Kind(); got != "otlp_logs" {
		t.Fatalf("surviving sink kind=%q", got)
	}
}

func TestBuildAuditSinks_UnknownKindReported(t *testing.T) {
	sinks := []config.AuditSink{
		{Name: "weird", Kind: "kafka_topic", Enabled: true},
	}
	_, err := buildAuditSinks(sinks, "v0")
	if err == nil || !strings.Contains(err.Error(), "unknown sink kind") {
		t.Fatalf("expected unknown-kind error, got %v", err)
	}
}

func TestBuildAuditSinks_EmptyListReturnsEmptyManager(t *testing.T) {
	mgr, err := buildAuditSinks(nil, "v0")
	if err != nil {
		t.Fatalf("err=%v", err)
	}
	if mgr == nil {
		t.Fatal("manager must not be nil even when no sinks configured")
	}
	if mgr.Len() != 0 {
		t.Fatalf("Len=%d want 0", mgr.Len())
	}
}

func TestBuildAuditSinks_ResolvesEnvTokens(t *testing.T) {
	t.Setenv("DC_TEST_HEC_TOKEN", "resolved-value")

	sinks := []config.AuditSink{
		{
			Name: "env-splunk", Kind: config.SinkKindSplunkHEC, Enabled: true,
			SplunkHEC: &config.SplunkHECSinkConfig{
				Endpoint: "https://splunk.example:8088",
				TokenEnv: "DC_TEST_HEC_TOKEN",
			},
		},
	}
	mgr, err := buildAuditSinks(sinks, "v0")
	if err != nil {
		t.Fatalf("buildAuditSinks err=%v", err)
	}
	if mgr.Len() != 1 {
		t.Fatalf("expected sink to register when TokenEnv resolves, Len=%d", mgr.Len())
	}
}

func TestDefaultSinkResource_TagsServiceName(t *testing.T) {
	res := defaultSinkResource("1.2.3")
	if res == nil {
		t.Fatal("resource is nil")
	}
	found := false
	for _, attr := range res.Attributes() {
		if string(attr.Key) == "service.name" &&
			attr.Value.AsString() == "defenseclaw-audit" {
			found = true
		}
	}
	if !found {
		t.Fatalf("resource missing service.name=defenseclaw-audit: %v", res.Attributes())
	}
}

func TestDefaultSinkResource_EmptyVersionStillValid(t *testing.T) {
	res := defaultSinkResource("")
	if res == nil {
		t.Fatal("nil resource for empty version")
	}
	// Must still carry service.name.
	found := false
	for _, attr := range res.Attributes() {
		if string(attr.Key) == "service.name" {
			found = true
		}
	}
	if !found {
		t.Fatalf("missing service.name on fallback resource")
	}
}

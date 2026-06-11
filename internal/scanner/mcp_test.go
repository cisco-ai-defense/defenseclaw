// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// SPDX-License-Identifier: Apache-2.0

package scanner

import (
	"reflect"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/config"
)

// ---------------------------------------------------------------------------
// buildArgs — the MCP scanner now shells out to the SDK-backed Python
// CLI ("defenseclaw mcp scan --json <target>") instead of the
// standalone mcp-scanner binary, which never had a usable "scan"
// subcommand. Flags are options on the "scan" subcommand and the
// target is positional, so the order is: mcp scan --json [flags...]
// <target>.
// ---------------------------------------------------------------------------

func TestMCPScanner_BuildArgs_Default(t *testing.T) {
	ms := NewMCPScannerFromLLM(config.MCPScannerConfig{}, config.LLMConfig{}, config.CiscoAIDefenseConfig{})
	got := ms.buildArgs("my-server")
	want := []string{"mcp", "scan", "--json", "my-server"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("buildArgs default = %v, want %v", got, want)
	}
}

func TestMCPScanner_BuildArgs_AllKnobs(t *testing.T) {
	cfg := config.MCPScannerConfig{
		Analyzers:        "yara,llm",
		ScanPrompts:      true,
		ScanResources:    true,
		ScanInstructions: true,
	}
	ms := NewMCPScannerFromLLM(cfg, config.LLMConfig{}, config.CiscoAIDefenseConfig{})
	got := ms.buildArgs("https://example.com/mcp")
	want := []string{
		"mcp", "scan", "--json",
		"--analyzers", "yara,llm",
		"--scan-prompts", "--scan-resources", "--scan-instructions",
		"https://example.com/mcp",
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("buildArgs all knobs = %v, want %v", got, want)
	}
}

func TestMCPScanner_BinaryCoercion(t *testing.T) {
	cases := []struct {
		in   string
		want string
	}{
		{"", "defenseclaw"},
		{"mcp-scanner", "defenseclaw"},
		{"/usr/local/bin/mcp-scanner", "defenseclaw"},
		{"defenseclaw", "defenseclaw"},
		{"/opt/custom/defenseclaw", "/opt/custom/defenseclaw"},
	}
	for _, tc := range cases {
		ms := NewMCPScannerFromLLM(config.MCPScannerConfig{Binary: tc.in}, config.LLMConfig{}, config.CiscoAIDefenseConfig{})
		if ms.Config.Binary != tc.want {
			t.Errorf("binary %q coerced to %q, want %q", tc.in, ms.Config.Binary, tc.want)
		}
	}
}

// parseMCPOutput must accept the ScanResult.to_json() shape emitted by
// "defenseclaw mcp scan --json": a top-level object with a "findings"
// array. Suppressed findings are dropped; the line number arrives as
// "line_number" (Finding.to_dict in cli/defenseclaw/models.py), so the
// fixture uses the real field name rather than a bare "line".
func TestParseMCPOutput_ScanResultShape(t *testing.T) {
	payload := []byte(`{
		"scanner": "mcp-scanner",
		"target": "github",
		"timestamp": "2026-06-09T00:00:00Z",
		"findings": [
			{
				"id": "f1",
				"rule_id": "R-1",
				"severity": "HIGH",
				"title": "Suspicious tool description",
				"description": "desc",
				"location": "tools/echo",
				"line_number": 12,
				"remediation": "fix it",
				"tags": ["mcp", "yara"],
				"suppressed": false
			},
			{
				"id": "f2",
				"severity": "LOW",
				"title": "ignored",
				"suppressed": true
			}
		]
	}`)

	findings, err := parseMCPOutput(payload)
	if err != nil {
		t.Fatalf("parseMCPOutput returned error: %v", err)
	}
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding (suppressed dropped), got %d", len(findings))
	}
	f := findings[0]
	if f.ID != "f1" || f.Severity != Severity("HIGH") || f.RuleID != "R-1" {
		t.Errorf("unexpected finding fields: %+v", f)
	}
	if f.Scanner != "mcp-scanner" {
		t.Errorf("Scanner = %q, want 'mcp-scanner'", f.Scanner)
	}
	if f.LineNumber == nil || *f.LineNumber != 12 {
		t.Errorf("LineNumber = %v, want 12", f.LineNumber)
	}
	if !reflect.DeepEqual(f.Tags, []string{"mcp", "yara"}) {
		t.Errorf("Tags = %v, want [mcp yara]", f.Tags)
	}
}

func TestParseMCPOutput_EmptyFindings(t *testing.T) {
	findings, err := parseMCPOutput([]byte(`{"scanner":"mcp-scanner","target":"x","findings":[]}`))
	if err != nil {
		t.Fatalf("parseMCPOutput returned error: %v", err)
	}
	if len(findings) != 0 {
		t.Errorf("expected 0 findings, got %d", len(findings))
	}
}

// ---------------------------------------------------------------------------
// validateMCPScanTargetURL — SSRF guard for the MCP scanner's remote-URL
// targets. The default rejects loopback / private / link-local / cloud-
// metadata destinations and URLs that embed inline credentials.
//
// DEFENSECLAW_ALLOW_LOCAL_MCP_TARGETS=1 is the opt-out for local
// development; it bypasses every other check, including inline
// credentials, so it must NEVER be set in production.
// ---------------------------------------------------------------------------

func TestValidateMCPScanTargetURL_Default(t *testing.T) {
	// Make sure no leftover env from a previous test flips the gate.
	t.Setenv("DEFENSECLAW_ALLOW_LOCAL_MCP_TARGETS", "")

	cases := []struct {
		name    string
		target  string
		wantErr string
	}{
		{"loopback hostname", "http://localhost:8080/mcp", "loopback"},
		{"loopback v4 literal", "http://127.0.0.1/mcp", "loopback"},
		{"loopback v6 literal", "http://[::1]/mcp", "loopback"},
		{"rfc1918", "http://10.0.0.1/mcp", "private"},
		// 169.254/16 falls into the link-local class first, so the
		// error reads "link-local" rather than "metadata" — the IMDS
		// literal check is a belt-and-braces follow-up for the case
		// where the link-local class wasn't enough. Either rejection
		// is acceptable for this gate.
		{"link-local", "http://169.254.1.1/mcp", "link-local"},
		{"cloud IMDS v4", "http://169.254.169.254/mcp", "link-local"},
		{"GCP metadata hostname", "http://metadata.google.internal/mcp", "metadata"},
		{"inline credentials", "http://user:pass@public.example.com/mcp", "credentials"},
		{"empty host", "http:///mcp", "host"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := validateMCPScanTargetURL(tc.target)
			if err == nil {
				t.Fatalf("validateMCPScanTargetURL(%q) = nil, want error containing %q", tc.target, tc.wantErr)
			}
			if !strings.Contains(strings.ToLower(err.Error()), tc.wantErr) {
				t.Errorf("validateMCPScanTargetURL(%q) err = %q, want substring %q", tc.target, err.Error(), tc.wantErr)
			}
		})
	}
}

func TestValidateMCPScanTargetURL_AllowLocalOptIn(t *testing.T) {
	// With the opt-out engaged, even the worst cases must pass —
	// inline credentials, loopback, and IMDS. This pins exactly how
	// dangerous the env var is; the test passing means the gate is
	// genuinely bypassed.
	t.Setenv("DEFENSECLAW_ALLOW_LOCAL_MCP_TARGETS", "1")
	cases := []string{
		"http://localhost:8080/mcp",
		"http://127.0.0.1/mcp",
		"http://10.0.0.1/mcp",
		"http://169.254.169.254/mcp",
		"http://user:pass@public.example.com/mcp",
	}
	for _, target := range cases {
		if err := validateMCPScanTargetURL(target); err != nil {
			t.Errorf("DEFENSECLAW_ALLOW_LOCAL_MCP_TARGETS=1, validateMCPScanTargetURL(%q) = %v, want nil", target, err)
		}
	}
}

func TestValidateMCPScanTargetURL_OnlyExactOneOptsIn(t *testing.T) {
	// Anything other than the exact string "1" must keep the gate
	// closed. This prevents a typo like "true" / "yes" / " 1 " from
	// silently disabling the SSRF guard.
	for _, v := range []string{"", "0", "true", "yes", "TRUE", " 1 ", "1\n"} {
		t.Setenv("DEFENSECLAW_ALLOW_LOCAL_MCP_TARGETS", v)
		if err := validateMCPScanTargetURL("http://localhost:8080/mcp"); err == nil {
			t.Errorf("env=%q must NOT opt in; localhost target unexpectedly accepted", v)
		}
	}
}

func TestMcpScanTargetLooksLikeURL(t *testing.T) {
	urls := []string{
		"http://example.com/mcp",
		"https://example.com/mcp",
		"ws://example.com/mcp",
		"wss://example.com/mcp",
		"sse://example.com/mcp",
		// Case-insensitive scheme prefix.
		"HTTPS://example.com/mcp",
	}
	notURLs := []string{
		"",
		"/local/path",
		"./relative",
		"stdio://something", // unknown scheme
		"file:///etc/passwd",
		"my-server-name",
	}
	for _, u := range urls {
		if !mcpScanTargetLooksLikeURL(u) {
			t.Errorf("mcpScanTargetLooksLikeURL(%q) = false, want true", u)
		}
	}
	for _, n := range notURLs {
		if mcpScanTargetLooksLikeURL(n) {
			t.Errorf("mcpScanTargetLooksLikeURL(%q) = true, want false", n)
		}
	}
}

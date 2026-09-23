// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// SPDX-License-Identifier: Apache-2.0

package benchmark

import (
	"context"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/scanner"
)

func TestRunMCPArtifactUsesStandaloneYARAOnlyContract(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("test helper uses a POSIX executable script")
	}
	dir := t.TempDir()
	argsPath := filepath.Join(dir, "args.txt")
	binary := filepath.Join(dir, "mcp-scanner")
	script := `#!/bin/sh
printf '%s\n' "$@" > "$MCP_BENCHMARK_ARGS"
cat <<'JSON'
{"server_url":"static","scan_results":[{"status":"completed","is_safe":false,"findings":{"yara_analyzer":{"severity":"HIGH","threat_names":["PROMPT INJECTION","SYSTEM MANIPULATION"],"threat_summary":"Detected 2 threats: coercive injection, system manipulation","total_findings":2}},"tool_name":"search","item_type":"tool"}],"requested_analyzers":["yara"]}
JSON
`
	if err := os.WriteFile(binary, []byte(script), 0o700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("MCP_BENCHMARK_ARGS", argsPath)

	benchmarkCase := Case{
		SchemaVersion: SchemaVersion, ID: "mcp-yara", Surface: "mcp",
		Payload: Payload{Filename: "tools.json", Content: `[{"name":"search"}]`},
	}
	prediction := (Runner{MCPBinary: binary}).runArtifact(context.Background(), "default", benchmarkCase, Prediction{
		SchemaVersion: SchemaVersion, RunID: "mcp-test", CaseID: "mcp-yara",
		Profile: "default", Applicable: true,
		Action: "not_applicable", Severity: "NONE", Route: "none",
	})
	if prediction.Engine != "mcp-scanner-yara-static" || !prediction.Detected || prediction.Action != "alert" {
		t.Fatalf("prediction=%+v", prediction)
	}
	if prediction.FindingCount != 2 || prediction.Severity != "HIGH" || !prediction.Alerted ||
		prediction.AlertFindingCount != 2 || prediction.DetectOnlyFindingCount != 2 {
		t.Fatalf("finding projection=%+v", prediction)
	}
	wantRules := []string{"mcp_yara.coercive_injection", "mcp_yara.system_manipulation"}
	if !reflect.DeepEqual(prediction.RuleIDs, wantRules) {
		t.Fatalf("rule IDs=%v, want %v", prediction.RuleIDs, wantRules)
	}

	data, err := os.ReadFile(argsPath)
	if err != nil {
		t.Fatal(err)
	}
	args := strings.Fields(string(data))
	if len(args) != 7 || !reflect.DeepEqual(args[:6], []string{"--analyzers", "yara", "--format", "raw", "static", "--tools"}) {
		t.Fatalf("scanner args=%v", args)
	}
	if filepath.Base(args[6]) != "tools.json" {
		t.Fatalf("scanner target=%q, want tools.json", args[6])
	}
}

func TestRunMCPArtifactUsesCustomYARARulesDirectory(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("test helper uses a POSIX executable script")
	}
	dir := t.TempDir()
	argsPath := filepath.Join(dir, "args.txt")
	binary := filepath.Join(dir, "mcp-scanner")
	script := `#!/bin/sh
printf '%s\n' "$@" > "$MCP_BENCHMARK_ARGS"
cat <<'JSON'
{"server_url":"static","scan_results":[{"status":"completed","is_safe":true,"findings":{"yara_analyzer":{"severity":"SAFE","threat_names":[],"threat_summary":"No threats detected","total_findings":0}},"tool_name":"search","item_type":"tool"}],"requested_analyzers":["yara"]}
JSON
`
	if err := os.WriteFile(binary, []byte(script), 0o700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("MCP_BENCHMARK_ARGS", argsPath)

	benchmarkCase := Case{
		SchemaVersion: SchemaVersion, ID: "mcp-yara-custom", Surface: "mcp",
		Payload: Payload{Filename: "tools.json", Content: `[{"name":"search"}]`},
	}
	rulesDir := filepath.Join("policies", "yara", "mcp-tools")
	prediction := (Runner{
		RepoRoot: "/repo", MCPBinary: binary, MCPYARARulesDir: rulesDir,
	}).runArtifact(context.Background(), "default", benchmarkCase, Prediction{
		SchemaVersion: SchemaVersion, RunID: "mcp-test", CaseID: "mcp-yara-custom",
		Profile: "default", Applicable: true,
		Action: "not_applicable", Severity: "NONE", Route: "none",
	})
	if prediction.Action != "allow" || prediction.Detected {
		t.Fatalf("prediction=%+v", prediction)
	}

	data, err := os.ReadFile(argsPath)
	if err != nil {
		t.Fatal(err)
	}
	args := strings.Fields(string(data))
	want := []string{
		"--analyzers", "yara", "--format", "raw", "--rules-path",
		filepath.Join("/repo", rulesDir), "static", "--tools",
	}
	if len(args) != len(want)+1 || !reflect.DeepEqual(args[:len(want)], want) {
		t.Fatalf("scanner args=%v, want prefix %v", args, want)
	}
	if filepath.Base(args[len(want)]) != "tools.json" {
		t.Fatalf("scanner target=%q, want tools.json", args[len(want)])
	}
}

func TestParseMCPYARAOutputProjectsCleanResult(t *testing.T) {
	data := []byte(`{"scan_results":[{"status":"completed","is_safe":true,"findings":{"yara_analyzer":{"severity":"SAFE","threat_names":[],"threat_summary":"No threats detected","total_findings":0}},"tool_name":"weather"}],"requested_analyzers":["yara"]}`)
	findings, err := parseMCPYARAOutput(data)
	if err != nil {
		t.Fatal(err)
	}
	if len(findings) != 0 {
		t.Fatalf("findings=%+v, want none", findings)
	}
}

func TestMCPYARAUnknownSeverityProjectsToValidLowSeverity(t *testing.T) {
	if got := mcpYARASeverity("UNKNOWN"); got != scanner.SeverityLow {
		t.Fatalf("severity=%q, want %q", got, scanner.SeverityLow)
	}
}

func TestParseMCPYARAOutputRejectsAnalyzerContamination(t *testing.T) {
	data := []byte(`{"scan_results":[{"status":"completed","findings":{"api_analyzer":{"severity":"HIGH","total_findings":1}},"tool_name":"search"}],"requested_analyzers":["yara","api"]}`)
	_, err := parseMCPYARAOutput(data)
	if err == nil || !strings.Contains(err.Error(), "YARA-only") {
		t.Fatalf("error=%v, want YARA-only contract failure", err)
	}
}

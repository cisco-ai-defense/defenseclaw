// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// SPDX-License-Identifier: Apache-2.0

package config

import (
	"strings"
	"testing"
)

// The local Splunk setup record lives in the sink's own config. Only a
// splunk_hec destination may carry it, and only in its exact shape, so a
// record cannot be implied by anything else.
func TestParseCompileObservabilityV8LocalStackRecord(t *testing.T) {
	fullID := strings.Repeat("0123456789abcdef", 4)
	splunk := func(record string) string {
		return "config_version: 8\nobservability:\n  destinations:\n" +
			"    - name: local-splunk\n      kind: splunk_hec\n      enabled: false\n" +
			"      endpoint: http://127.0.0.1:8088/services/collector/event\n" +
			"      token_env: DEFENSECLAW_LOCAL_SPLUNK_HEC_TOKEN\n" +
			"      network_safety:\n        allow_private_networks: true\n" + record
	}
	record := func(marker, id string) string {
		return "      local_stack:\n        marker: " + marker + "\n        container_id: \"" + id + "\"\n"
	}
	compile := func(t *testing.T, raw string) (*ObservabilityV8CompiledConfig, error) {
		t.Helper()
		return ParseCompileObservabilityV8("config.yaml", []byte(raw), ObservabilityV8CompileOptions{DefaultDataDir: t.TempDir()})
	}

	compiled, err := compile(t, splunk(record("defenseclaw-local-splunk", fullID)))
	if err != nil {
		t.Fatalf("a recorded local Splunk sink must load: %v", err)
	}
	if _, ok := compiled.Plan.Destination("local-splunk"); !ok {
		t.Fatal("recorded local Splunk sink missing from the plan")
	}
	if strings.Contains(string(compiled.Plan.EffectiveJSON()), fullID) {
		t.Fatal("the setup record is CLI state and must not enter the delivery plan")
	}

	refused := map[string]string{
		"other marker":       splunk(record("someone-else", fullID)),
		"short container ID": splunk(record("defenseclaw-local-splunk", fullID[:12])),
		"upper-case ID":      splunk(record("defenseclaw-local-splunk", strings.ToUpper(fullID))),
		"no container ID":    splunk("      local_stack:\n        marker: defenseclaw-local-splunk\n"),
		"extra field": splunk(record("defenseclaw-local-splunk", fullID) +
			"        endpoint: http://127.0.0.1:8088\n"),
		"not a splunk sink": "config_version: 8\nobservability:\n  destinations:\n" +
			"    - name: archive\n      kind: http_jsonl\n      enabled: false\n" +
			"      endpoint: https://archive.example.test/defenseclaw\n      bearer_env: ARCHIVE_TOKEN\n" +
			record("defenseclaw-local-splunk", fullID),
	}
	for name, raw := range refused {
		t.Run(name, func(t *testing.T) {
			if _, err := compile(t, raw); err == nil {
				t.Fatalf("%s: config with a malformed or misplaced local setup record loaded", name)
			}
		})
	}
}

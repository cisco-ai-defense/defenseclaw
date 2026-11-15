// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package config

import (
	"strings"
	"testing"
)

// rel-1-0-10 GAP-0003: the routing.sensitive.check keys pass the embedded
// schema (which must compile under Go regexp) and bad values do not.
func TestRoutingSensitiveCheckSchema(t *testing.T) {
	src := func(sensitive string) []byte {
		return []byte("config_version: 9\nrouting:\n  enabled: true\n  models:\n    - {name: local, provider: ollama, model: m, base_url: \"http://127.0.0.1:11434\"}\n  sensitive: " + sensitive + "\n")
	}
	for _, ok := range []string{
		`{aliases: [local], check: auto}`,
		`{aliases: [local], signals: [s], check: off}`,
		`{aliases: [local], check: judge, on_unavailable: ignore, timeout_ms: 0, max_bytes: 0, definition: "patient data\tand HR"}`,
		`{aliases: [local], check: decision_model, timeout_ms: 1500, max_bytes: 4096}`,
	} {
		if err := ValidateV8SchemaBytes("config.yaml", src(ok)); err != nil {
			t.Fatalf("%s: %v", ok, err)
		}
	}
	for _, bad := range []string{
		`{aliases: [local], check: sometimes}`,
		`{aliases: [local], check: auto, timeout_ms: 10}`,
		`{aliases: [local], check: auto, max_bytes: 100}`,
		`{aliases: [local], check: off}`,
		`{aliases: [local], check: auto, definition: "a\u0001b"}`,
	} {
		if err := ValidateV8SchemaBytes("config.yaml", src(bad)); err == nil || strings.Contains(err.Error(), "compilation failed") {
			t.Fatalf("%s: want a schema refusal, got %v", bad, err)
		}
	}
}

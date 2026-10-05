// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package config

import (
	"errors"
	"testing"
)

// GAP-2234, GAP-2235: with undeclared keys in several sections, every run
// names the first one in the file, at the line of the key itself.
func TestV8SchemaNamesTheFirstUndeclaredKeyInFileOrder(t *testing.T) {
	const head = "config_version: 8\ndata_dir: /var/tmp/dc-v8-order\ngateway:\n  api_port: 19134\n"
	for name, tc := range map[string]struct {
		extra string
		path  string
		line  int
	}{
		"two sections":             {"watch:\n  debouce_ms: 500\nguardrail:\n  mdoe: observe\n", "$.watch.debouce_ms", 6},
		"unknown section first":    {"gateway2:\n  a: 1\nguardrail:\n  bogus_k: 1\n", "$.gateway2", 5},
		"deeper key first":         {"guardrail:\n  bogus_k: 1\ngateway2:\n  a: 1\n", "$.guardrail.bogus_k", 6},
		"unknown section own line": {"gateway2:\n  a: 1\n", "$.gateway2", 5},
	} {
		for run := 0; run < 20; run++ {
			err := ValidateV8SchemaBytes("config.yaml", []byte(head+tc.extra))
			var schemaErr *V8SchemaError
			if !errors.As(err, &schemaErr) {
				t.Fatalf("%s: error %v, want a schema error", name, err)
			}
			if schemaErr.Path != tc.path || schemaErr.Line != tc.line || schemaErr.Keyword != "additionalProperties" {
				t.Fatalf("%s run %d: %s line %d (%s), want %s line %d", name, run, schemaErr.Path, schemaErr.Line, schemaErr.Keyword, tc.path, tc.line)
			}
		}
	}
}

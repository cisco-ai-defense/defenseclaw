// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package config

import (
	"errors"
	"testing"
)

// GAP-1430: a YAML syntax error names the bad line itself, the same line
// that config validate, status and the TUI name.
func TestParseV8YAMLSyntaxErrorNamesTheBadLine(t *testing.T) {
	cases := map[string]struct {
		source string
		line   int
	}{
		"unclosed flow sequence at the end": {"config_version: 8\na: 1\nguardrail: [unclosed\n", 3},
		"bad indentation":                   {"config_version: 8\na:\n  b: 1\n c: 2\n", 4},
		"scanner error keeps its line":      {"config_version: 8\nb: c: d\n", 2},
	}
	for name, tc := range cases {
		_, err := ParseV8YAML("config.yaml", []byte(tc.source))
		var yamlErr *V8YAMLError
		if !errors.As(err, &yamlErr) || yamlErr.Code != V8YAMLErrorSyntax {
			t.Fatalf("%s: error = %v, want a YAML syntax error", name, err)
		}
		if yamlErr.Line != tc.line {
			t.Errorf("%s: line = %d, want %d (%v)", name, yamlErr.Line, tc.line, err)
		}
	}
}

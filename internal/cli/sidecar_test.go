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
	"testing"
)

// TestFormatDetailValue_Scalars locks in the rendering contract used
// by the gateway status panel. JSON unmarshalling reduces every numeric
// value to “float64“; whole numbers must round-trip back to ints so
// fields like “protocol: 3“ and “port: 4000“ don't render as
// “3.0“ / “4000.0“ to operators reading the terminal.
func TestFormatDetailValue_Scalars(t *testing.T) {
	cases := []struct {
		name string
		in   interface{}
		want string
		ok   bool
	}{
		{name: "string", in: "127.0.0.1:4317", want: "127.0.0.1:4317", ok: true},
		{name: "bool true", in: true, want: "true", ok: true},
		{name: "bool false", in: false, want: "false", ok: true},
		{name: "json int", in: float64(3), want: "3", ok: true},
		{name: "json large int", in: float64(18789), want: "18789", ok: true},
		{name: "json fractional", in: 1.5, want: "1.5", ok: true},
		{name: "go int", in: int(42), want: "42", ok: true},
		{name: "go int64", in: int64(42), want: "42", ok: true},
	}
	for _, tt := range cases {
		t.Run(tt.name, func(t *testing.T) {
			got, ok := formatDetailValue(tt.in)
			if ok != tt.ok {
				t.Fatalf("ok = %v, want %v (got=%q)", ok, tt.ok, got)
			}
			if got != tt.want {
				t.Errorf("got = %q, want %q", got, tt.want)
			}
		})
	}
}

// TestFormatDetailValue_NonScalarsAreSkipped confirms that structured
// fields kept on the /health JSON surface (e.g. the per-sink
// “sinks: [...]“ array) are signalled as "not renderable" so the CLI
// printer skips them rather than dumping a “[map[...]]“ blob to the
// terminal. Equivalent JSON-decoded shapes (“[]interface{}“ /
// “map[string]interface{}“) and Go-native shapes are both covered.
func TestFormatDetailValue_NonScalarsAreSkipped(t *testing.T) {
	cases := []struct {
		name string
		in   interface{}
	}{
		{
			name: "json-decoded slice of maps",
			in: []interface{}{
				map[string]interface{}{
					"name": "local-otlp-logs",
					"kind": "otlp_logs",
				},
			},
		},
		{
			name: "json-decoded slice of strings",
			in:   []interface{}{"otlp_logs", "splunk_hec"},
		},
		{
			name: "json-decoded map",
			in:   map[string]interface{}{"name": "local-otlp-logs"},
		},
		{
			name: "go native slice of maps",
			in:   []map[string]interface{}{{"name": "local-otlp-logs"}},
		},
		{
			name: "go native string slice",
			in:   []string{"otlp_logs"},
		},
		{
			name: "nil",
			in:   nil,
		},
	}
	for _, tt := range cases {
		t.Run(tt.name, func(t *testing.T) {
			got, ok := formatDetailValue(tt.in)
			if ok {
				t.Fatalf("ok = true (got=%q), want false — non-scalar must be skipped", got)
			}
		})
	}
}

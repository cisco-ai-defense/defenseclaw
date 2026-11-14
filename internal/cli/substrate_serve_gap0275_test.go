// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"fmt"
	"strings"
	"testing"
)

// GAP-0275: a Substrate gateway pod keeps its audit store in a pod volume,
// lost when the pod is replaced. Without an export destination the gateway
// says so once at start, and names the durable path.
func TestGAP0275SubstrateGatewayWarnsWithoutAnExportDestination(t *testing.T) {
	dataDir := t.TempDir()
	cases := map[string]struct {
		destinations string
		warn         bool
	}{
		"none":         {"", true},
		"console only": {"  destinations:\n    - name: out\n      kind: console\n", true},
		"disabled otlp": {"  destinations:\n    - name: off\n      kind: otlp\n      enabled: false\n" +
			"      endpoint: collector.example.com:4317\n", true},
		"otlp":       {"  destinations:\n    - name: otel\n      kind: otlp\n      endpoint: collector.example.com:4317\n", false},
		"splunk_hec": {"  destinations:\n    - name: hec\n      kind: splunk_hec\n      endpoint: https://splunk.example.com:8088/services/collector/event\n      token_env: PATH\n", false},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			raw := []byte(fmt.Sprintf("config_version: 9\ndata_dir: %q\nobservability:\n%s", dataDir, tc.destinations))
			if tc.destinations == "" {
				raw = []byte(fmt.Sprintf("config_version: 9\ndata_dir: %q\n", dataDir))
			}
			line := substrateAuditExportWarningFor("config.yaml", raw, dataDir)
			if tc.warn != (line != "") {
				t.Fatalf("warning %q, want warn=%t", line, tc.warn)
			}
			if tc.warn && (!strings.Contains(line, "lost when the pod restarts") || !strings.Contains(line, "observability.destinations")) {
				t.Fatalf("warning %q does not name the loss and the fix", line)
			}
		})
	}
}

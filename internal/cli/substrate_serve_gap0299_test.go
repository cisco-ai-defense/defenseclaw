// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"fmt"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/config"
)

// TestGAP0299OwnChartCollectorDestinationIsADurableExport: the chart keeps
// an operator's own destination named chart-collector, so only the chart's
// collector (its in-cluster Service) gets the try-out warning; a destination
// of that name pointing at a real collector gets none.
func TestGAP0299OwnChartCollectorDestinationIsADurableExport(t *testing.T) {
	dataDir := t.TempDir()
	warn := func(endpoint string) string {
		dest := "    - name: chart-collector\n      kind: otlp\n      protocol: http/protobuf\n" +
			"      endpoint: " + endpoint + "\n      network_safety: {allow_private_networks: true}\n"
		if strings.HasPrefix(endpoint, "http://") {
			dest += "      tls: {insecure: true}\n"
		}
		raw := []byte(fmt.Sprintf("config_version: 9\ndata_dir: %q\nobservability:\n  destinations:\n%s", dataDir, dest))
		// The warning is "" for a source that does not compile too: make
		// sure each case is a destination the export really runs.
		if _, err := config.ParseCompileObservabilityV8("config.yaml", raw, config.ObservabilityV8CompileOptions{DefaultDataDir: dataDir}); err != nil {
			t.Fatalf("%s does not compile: %v", endpoint, err)
		}
		return substrateAuditExportWarningFor("config.yaml", raw, dataDir)
	}
	for _, own := range []string{
		"https://otel.example.com:4318",
		"http://otel-collector.observability.svc:4318",
		"http://defenseclaw-otel-collector.dc.svc.cluster.example:4318",
		"http://defenseclaw-otel-collector.dc.svc:4319",
	} {
		if line := warn(own); line != "" {
			t.Errorf("own destination chart-collector at %s: got warning %q", own, line)
		}
	}
	for _, chart := range []string{
		"http://defenseclaw-otel-collector.dc.svc:4318",
		"http://defenseclaw-otel-collector.defenseclaw-system.svc:4318",
	} {
		if line := warn(chart); !strings.Contains(line, "the only export destination is chart-collector") {
			t.Errorf("the chart's collector at %s: warning %q", chart, line)
		}
	}
}

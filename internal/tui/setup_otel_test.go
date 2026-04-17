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

package tui

import (
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/config"
)

// ------------------------------------------------------------------
// P2-#10 — OTel section surface + per-key round-trip
// ------------------------------------------------------------------

// TestApplyConfigField_OTelFullSurface makes sure every OTel key we
// render in the Setup panel round-trips back into config.Config. This
// is the regression guard for the recurring "added a field to the
// YAML, forgot to wire it into applyConfigField, and saves silently
// drop it" bug.
func TestApplyConfigField_OTelFullSurface(t *testing.T) {
	cases := []struct {
		key    string
		val    string
		verify func(c *config.Config) bool
	}{
		// Globals
		{"otel.enabled", "true", func(c *config.Config) bool { return c.OTel.Enabled }},
		{"otel.protocol", "http/protobuf", func(c *config.Config) bool { return c.OTel.Protocol == "http/protobuf" }},
		{"otel.endpoint", "https://collector:4318", func(c *config.Config) bool { return c.OTel.Endpoint == "https://collector:4318" }},
		{"otel.tls.insecure", "true", func(c *config.Config) bool { return c.OTel.TLS.Insecure }},
		{"otel.tls.ca_cert", "/etc/ssl/ca.pem", func(c *config.Config) bool { return c.OTel.TLS.CACert == "/etc/ssl/ca.pem" }},

		// Traces
		{"otel.traces.enabled", "true", func(c *config.Config) bool { return c.OTel.Traces.Enabled }},
		{"otel.traces.sampler", "traceidratio", func(c *config.Config) bool { return c.OTel.Traces.Sampler == "traceidratio" }},
		{"otel.traces.sampler_arg", "0.1", func(c *config.Config) bool { return c.OTel.Traces.SamplerArg == "0.1" }},
		{"otel.traces.endpoint", "https://traces:4318", func(c *config.Config) bool { return c.OTel.Traces.Endpoint == "https://traces:4318" }},
		{"otel.traces.protocol", "grpc", func(c *config.Config) bool { return c.OTel.Traces.Protocol == "grpc" }},
		{"otel.traces.url_path", "/v1/traces", func(c *config.Config) bool { return c.OTel.Traces.URLPath == "/v1/traces" }},

		// Logs
		{"otel.logs.enabled", "true", func(c *config.Config) bool { return c.OTel.Logs.Enabled }},
		{"otel.logs.emit_individual_findings", "true", func(c *config.Config) bool { return c.OTel.Logs.EmitIndividualFindings }},
		{"otel.logs.endpoint", "https://logs:4318", func(c *config.Config) bool { return c.OTel.Logs.Endpoint == "https://logs:4318" }},
		{"otel.logs.protocol", "http/protobuf", func(c *config.Config) bool { return c.OTel.Logs.Protocol == "http/protobuf" }},
		{"otel.logs.url_path", "/v1/logs", func(c *config.Config) bool { return c.OTel.Logs.URLPath == "/v1/logs" }},

		// Metrics
		{"otel.metrics.enabled", "true", func(c *config.Config) bool { return c.OTel.Metrics.Enabled }},
		{"otel.metrics.export_interval_s", "30", func(c *config.Config) bool { return c.OTel.Metrics.ExportIntervalS == 30 }},
		{"otel.metrics.temporality", "cumulative", func(c *config.Config) bool { return c.OTel.Metrics.Temporality == "cumulative" }},
		{"otel.metrics.endpoint", "https://metrics:4318", func(c *config.Config) bool { return c.OTel.Metrics.Endpoint == "https://metrics:4318" }},
		{"otel.metrics.protocol", "grpc", func(c *config.Config) bool { return c.OTel.Metrics.Protocol == "grpc" }},
		{"otel.metrics.url_path", "/v1/metrics", func(c *config.Config) bool { return c.OTel.Metrics.URLPath == "/v1/metrics" }},

		// Batch
		{"otel.batch.max_export_batch_size", "1024", func(c *config.Config) bool { return c.OTel.Batch.MaxExportBatchSize == 1024 }},
		{"otel.batch.scheduled_delay_ms", "10000", func(c *config.Config) bool { return c.OTel.Batch.ScheduledDelayMs == 10000 }},
		{"otel.batch.max_queue_size", "4096", func(c *config.Config) bool { return c.OTel.Batch.MaxQueueSize == 4096 }},
	}
	for _, tc := range cases {
		t.Run(tc.key, func(t *testing.T) {
			c := &config.Config{}
			applyConfigField(c, tc.key, tc.val)
			if !tc.verify(c) {
				t.Errorf("applyConfigField(%s=%s) did not land", tc.key, tc.val)
			}
		})
	}
}

// TestSetupSections_OTelShape guards the per-signal + batch rows. A
// prior regression dropped batch + per-signal overrides when the
// section was refactored; this test makes sure that never ships
// silently again.
func TestSetupSections_OTelShape(t *testing.T) {
	c := &config.Config{}
	p := NewSetupPanel(nil, c, nil)
	p.loadSections()
	var otel *configSection
	for i := range p.sections {
		if p.sections[i].Name == "OTel" {
			otel = &p.sections[i]
			break
		}
	}
	if otel == nil {
		t.Fatal("OTel section missing")
	}
	want := []string{
		"otel.enabled",
		"otel.protocol",
		"otel.endpoint",
		"otel.tls.insecure",
		"otel.tls.ca_cert",
		"otel.headers.summary",
		"otel.traces.enabled",
		"otel.traces.sampler",
		"otel.traces.sampler_arg",
		"otel.traces.endpoint",
		"otel.traces.protocol",
		"otel.traces.url_path",
		"otel.logs.enabled",
		"otel.logs.emit_individual_findings",
		"otel.logs.endpoint",
		"otel.logs.protocol",
		"otel.logs.url_path",
		"otel.metrics.enabled",
		"otel.metrics.export_interval_s",
		"otel.metrics.temporality",
		"otel.metrics.endpoint",
		"otel.metrics.protocol",
		"otel.metrics.url_path",
		"otel.batch.max_export_batch_size",
		"otel.batch.scheduled_delay_ms",
		"otel.batch.max_queue_size",
		"otel.resource.summary",
	}
	seen := map[string]bool{}
	for _, f := range otel.Fields {
		seen[f.Key] = true
	}
	for _, k := range want {
		if !seen[k] {
			t.Errorf("OTel section missing field %q", k)
		}
	}
}

// TestFmtOTelResource covers the resource-attribute summary that
// shows up in the read-only row. Determinism matters so comparing
// saved snapshots across machines doesn't flap on map iteration.
func TestFmtOTelResource(t *testing.T) {
	if got := fmtOTelResource(nil); got != "(none)" {
		t.Errorf("nil map: got %q, want (none)", got)
	}
	if got := fmtOTelResource(map[string]string{}); got != "(none)" {
		t.Errorf("empty map: got %q, want (none)", got)
	}
	in := map[string]string{
		"service.name":        "defenseclaw-gateway",
		"service.version":     "1.0.0",
		"deployment.environ":  "prod",
	}
	got := fmtOTelResource(in)
	if !strings.Contains(got, "service.name=defenseclaw-gateway") ||
		!strings.Contains(got, "service.version=1.0.0") ||
		!strings.Contains(got, "deployment.environ=prod") {
		t.Errorf("rendering missing entries: %q", got)
	}
	// Keys must be sorted so snapshot comparisons are stable.
	// `deployment.environ` sorts before `service.*` alphabetically.
	if !strings.HasPrefix(got, "deployment.environ=") {
		t.Errorf("resource summary isn't sorted: %q", got)
	}
}

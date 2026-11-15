// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package setup

import (
	"testing"

	"gopkg.in/yaml.v3"

	"github.com/defenseclaw/defenseclaw/internal/config"
)

// gap0272RenderedConfig renders the chart and returns the gateway's
// config.yaml from the defenseclaw-config ConfigMap.
func gap0272RenderedConfig(t *testing.T, extra ...string) string {
	t.Helper()
	for _, o := range decodeMaps(t, renderChart(t, helmBinary(t), "default", extra...)) {
		if o["kind"] == "ConfigMap" && dig(o, "metadata", "name") == "defenseclaw-config" {
			text, _ := dig(o, "data", "config.yaml").(string)
			return text
		}
	}
	t.Fatal("no defenseclaw-config ConfigMap")
	return ""
}

type gap0272Destinations struct {
	Observability struct {
		Destinations []map[string]any `yaml:"destinations"`
	} `yaml:"observability"`
}

// TestChartLocalCollectorIsAWorkingExportTargetGAP0272: the documented
// try-out (observability.local.enabled) exported nothing, because no
// destination pointed at the collector. The chart now adds one that the
// gateway's compiler accepts: http/protobuf on 4318, tls.insecure for
// http, and allow_private_networks for the Service's cluster address.
func TestChartLocalCollectorIsAWorkingExportTargetGAP0272(t *testing.T) {
	text := gap0272RenderedConfig(t, "--set", "observability.local.enabled=true")
	var got gap0272Destinations
	if err := yaml.Unmarshal([]byte(text), &got); err != nil {
		t.Fatal(err)
	}
	if len(got.Observability.Destinations) != 1 {
		t.Fatalf("destinations %v, want only chart-collector", got.Observability.Destinations)
	}
	d := got.Observability.Destinations[0]
	if d["name"] != "chart-collector" || d["kind"] != "otlp" || d["protocol"] != "http/protobuf" ||
		d["endpoint"] != "http://defenseclaw-otel-collector.defenseclaw-system.svc:4318" ||
		dig(d, "tls", "insecure") != true || dig(d, "network_safety", "allow_private_networks") != true {
		t.Fatalf("chart-collector destination %v", d)
	}
	if _, err := config.ParseCompileObservabilityV8("config.yaml", []byte(text),
		config.ObservabilityV8CompileOptions{DefaultDataDir: t.TempDir()}); err != nil {
		t.Fatalf("the gateway refuses the rendered destination: %v", err)
	}
}

// The operator's own chart-collector wins, and without the local collector
// the chart adds no destination.
func TestChartLocalCollectorKeepsTheOperatorsDestinationGAP0272(t *testing.T) {
	text := gap0272RenderedConfig(t, "--set", "observability.local.enabled=true", "--set-json",
		`config.observability.destinations=[{"name":"chart-collector","kind":"otlp","protocol":"http/protobuf","endpoint":"https://otel.example.com:4318"}]`)
	var got gap0272Destinations
	if err := yaml.Unmarshal([]byte(text), &got); err != nil {
		t.Fatal(err)
	}
	if len(got.Observability.Destinations) != 1 || got.Observability.Destinations[0]["endpoint"] != "https://otel.example.com:4318" {
		t.Fatalf("destinations %v, want the operator's only", got.Observability.Destinations)
	}
	var off gap0272Destinations
	if err := yaml.Unmarshal([]byte(gap0272RenderedConfig(t)), &off); err != nil {
		t.Fatal(err)
	}
	if len(off.Observability.Destinations) != 0 {
		t.Fatalf("local collector off: destinations %v", off.Observability.Destinations)
	}
}

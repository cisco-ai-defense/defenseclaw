// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/config"
)

func gap0272Loaded(t *testing.T, destinations string) *loadedConfigV8File {
	t.Helper()
	dataDir := t.TempDir()
	raw := []byte(fmt.Sprintf("config_version: 9\ndata_dir: %q\nobservability:\n  destinations:\n%s", dataDir, destinations))
	compiled, err := config.ParseCompileObservabilityV8("config.yaml", raw, config.ObservabilityV8CompileOptions{DefaultDataDir: dataDir})
	if err != nil {
		t.Fatalf("config validate must accept the destination: %v", err)
	}
	return &loadedConfigV8File{compiled: compiled}
}

// GAP-0272: config validate accepted the SMK destination (an in-cluster
// Service, grpc by default on the OTLP/HTTP port) and the start then failed
// with no reason. Validate now names both settings.
func TestGAP0272ValidateWarnsForAClusterServiceAndTheGRPCDefaultOnPort4318(t *testing.T) {
	warnings := configValidateDestinationWarnings(gap0272Loaded(t,
		"    - name: smk-otlp\n      kind: otlp\n      endpoint: http://opentelemetry-collector.otel-system.svc:4318\n      tls: {insecure: true}\n"))
	joined := strings.Join(warnings, "\n")
	for _, want := range []string{
		`private_service_endpoint: observability destination "smk-otlp": opentelemetry-collector.otel-system.svc is a Kubernetes Service name`,
		"network_safety.allow_private_networks: true",
		`otlp_protocol_port: observability destination "smk-otlp"`,
		"protocol: http/protobuf",
	} {
		if !strings.Contains(joined, want) {
			t.Fatalf("warnings %q do not say %q", joined, want)
		}
	}
}

func TestGAP0272ValidateIsQuietForTheChartCollectorDestination(t *testing.T) {
	warnings := configValidateDestinationWarnings(gap0272Loaded(t,
		"    - name: chart-collector\n      kind: otlp\n      protocol: http/protobuf\n"+
			"      endpoint: http://defenseclaw-otel-collector.dc.svc:4318\n      tls: {insecure: true}\n"+
			"      network_safety: {allow_private_networks: true}\n"+
			"    - name: public\n      kind: otlp\n      endpoint: collector.example.com:4317\n"))
	if len(warnings) != 0 {
		t.Fatalf("unexpected warnings %q", warnings)
	}
}

// Every destination refusal line ends with "or remove the destination", so
// a laptop start names it, not only the jsonl path refusal (GAP-0097).
func TestGAP0272StartNamesAnyRefusedDestination(t *testing.T) {
	logPath := filepath.Join(t.TempDir(), "gateway.log")
	offset := gatewayLogSize(logPath)
	line := `defenseclaw: observability destination "hec": a secret it names (an env or credential reference of its token or headers) ` +
		"is not set, or the gateway cannot read it; set it or remove the destination\n"
	body := "[gateway] starting\n" + line +
		`Error: sidecar: observability v8 bootstrap: sidecar observability v8 bootstrap failed: runtime_unavailable: destination "hec": a secret it names` + "\n"
	if err := os.WriteFile(logPath, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	reason := gatewayLogExitReason(logPath, offset)
	if !strings.HasPrefix(reason, `observability destination "hec": a secret it names`) || !strings.Contains(reason, "runtime_unavailable") {
		t.Fatalf("start reason %q", reason)
	}
}

// GAP-0287: allow_cgnat alone does not admit a private ClusterIP, and a
// signal override's Service host is checked too.
func TestGAP0287ValidateWarnsForCGNATOnlyAndForOverrideHosts(t *testing.T) {
	warnings := configValidateDestinationWarnings(gap0272Loaded(t,
		"    - name: split\n      kind: otlp\n      protocol: http/protobuf\n"+
			"      endpoint: http://collector.example.com:4318\n      tls: {insecure: true}\n"+
			"      network_safety: {allow_cgnat: true}\n"+
			"      signal_overrides:\n        logs: {endpoint: http://logs.otel-system.svc:4318}\n"))
	joined := strings.Join(warnings, "\n")
	if !strings.Contains(joined, `private_service_endpoint: observability destination "split": logs.otel-system.svc is a Kubernetes Service name`) ||
		strings.Contains(joined, "collector.example.com is") {
		t.Fatalf("warnings %q", joined)
	}
}

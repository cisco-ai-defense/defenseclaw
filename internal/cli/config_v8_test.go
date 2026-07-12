// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
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
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/managed"
	"github.com/defenseclaw/defenseclaw/internal/observability"
)

func TestCompileConfigV8FileUsesCanonicalMaskedPlan(t *testing.T) {
	directory := t.TempDir()
	path := filepath.Join(directory, "config.yaml")
	raw := `config_version: 8
data_dir: ` + directory + `
observability:
  destinations:
    - name: collector
      kind: otlp
      endpoint: https://collector.example.test
      headers:
        authorization: static-secret-value
`
	if err := os.WriteFile(path, []byte(raw), 0o600); err != nil {
		t.Fatal(err)
	}
	compiled, source, gatewayAPIPort, err := compileConfigV8File(path, "")
	if err != nil {
		t.Fatal(err)
	}
	if source != path || compiled.DataDir != directory || gatewayAPIPort != config.DefaultGatewayAPIPort {
		t.Fatalf("source/data dir/API port = %q/%q/%d", source, compiled.DataDir, gatewayAPIPort)
	}
	effective := string(compiled.Plan.EffectiveJSON())
	for _, secret := range []string{"static-secret-value"} {
		if strings.Contains(effective, secret) {
			t.Fatalf("effective plan contains display secret %q: %s", secret, effective)
		}
	}
	if !strings.Contains(effective, "[REDACTED]") {
		t.Fatalf("effective plan did not mark masked values: %s", effective)
	}
	if got := compiled.Plan.Snapshot().Destinations[1].SelectedSignals; len(got) != 3 {
		t.Fatalf("general OTLP selected signals = %v, want all three", got)
	}
}

func TestCompileConfigV8FileLoadsInstallationDotEnvForValidationOnly(t *testing.T) {
	directory := t.TempDir()
	path := filepath.Join(directory, "config.yaml")
	secretName := "DEFENSECLAW_TEST_KEY"
	t.Setenv(secretName, "")
	if err := os.WriteFile(filepath.Join(directory, ".env"), []byte(secretName+"=resolved-value\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	raw := `config_version: 8
data_dir: ` + directory + `
observability:
  destinations:
    - name: collector
      kind: otlp
      endpoint: https://collector.example.test
      headers:
        authorization: {env: ` + secretName + `}
`
	if err := os.WriteFile(path, []byte(raw), 0o600); err != nil {
		t.Fatal(err)
	}
	compiled, _, _, err := compileConfigV8File(path, "")
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(compiled.Plan.EffectiveJSON()), "resolved-value") {
		t.Fatal("resolved secret entered effective output")
	}
}

func TestConfigV8MachineCommandsBypassRuntimeInitialization(t *testing.T) {
	if configV8Cmd.PersistentPreRunE == nil || configV8Cmd.PersistentPostRun == nil {
		t.Fatal("config-v8 helper must override root runtime hooks")
	}
	if err := configV8Cmd.PersistentPreRunE(configV8Cmd, nil); err != nil {
		t.Fatal(err)
	}
	if cfg != nil || auditStore != nil || auditLog != nil {
		t.Fatal("offline config helper initialized runtime state")
	}
	var schema map[string]any
	if err := json.Unmarshal(publicSchemaForTest(t), &schema); err != nil {
		t.Fatal(err)
	}
	if schema["$id"] == nil {
		t.Fatal("embedded schema is missing its identity")
	}
}

func TestConfigV8EffectiveWireEnvelopeIsVersioned(t *testing.T) {
	directory := t.TempDir()
	path := filepath.Join(directory, "config.yaml")
	raw := "config_version: 8\ndata_dir: " + directory + "\ngateway:\n  api_port: 29071\nobservability: {}\n"
	if err := os.WriteFile(path, []byte(raw), 0o600); err != nil {
		t.Fatal(err)
	}
	previousPath, previousDataDir := configV8ConfigPath, configV8DataDir
	configV8ConfigPath, configV8DataDir = path, ""
	t.Cleanup(func() { configV8ConfigPath, configV8DataDir = previousPath, previousDataDir })
	output := &strings.Builder{}
	configV8EffectiveCmd.SetOut(output)
	if err := configV8EffectiveCmd.RunE(configV8EffectiveCmd, nil); err != nil {
		t.Fatal(err)
	}
	var response configV8WireResponse
	if err := json.Unmarshal([]byte(output.String()), &response); err != nil {
		t.Fatal(err)
	}
	if response.WireVersion != configV8WireVersion || response.Kind != "effective" || len(response.Effective) == 0 {
		t.Fatalf("unexpected helper response: %+v", response)
	}
	if response.GatewayAPIPort != 29071 {
		t.Fatalf("gateway API port = %d, want 29071", response.GatewayAPIPort)
	}
	if response.NetworkValidation != "offline_syntax_and_literal_policy_only" {
		t.Fatalf("network validation marker = %q", response.NetworkValidation)
	}
}

func TestConfigV8EffectiveWireProvenanceIsLeafCompleteAndSecretSafe(t *testing.T) {
	directory := t.TempDir()
	path := filepath.Join(directory, "config.yaml")
	const secret = "provenance-bridge-secret"
	raw := "config_version: 8\ndata_dir: " + directory + `
observability:
  destinations:
    - name: collector
      kind: otlp
      endpoint: https://collector.example.test
      headers:
        authorization: ` + secret + `
`
	if err := os.WriteFile(path, []byte(raw), 0o600); err != nil {
		t.Fatal(err)
	}
	previousPath, previousDataDir := configV8ConfigPath, configV8DataDir
	configV8ConfigPath, configV8DataDir = path, ""
	t.Cleanup(func() { configV8ConfigPath, configV8DataDir = previousPath, previousDataDir })
	output := &strings.Builder{}
	configV8EffectiveCmd.SetOut(output)
	if err := configV8EffectiveCmd.RunE(configV8EffectiveCmd, nil); err != nil {
		t.Fatal(err)
	}
	encoded := output.String()
	if strings.Contains(encoded, secret) {
		t.Fatal("effective provenance wire leaked source secret")
	}
	if !strings.Contains(encoded, `"value_path":"observability.destinations[1].transport.endpoint"`) ||
		!strings.Contains(encoded, "[REDACTED]") {
		t.Fatalf("effective provenance wire omitted leaf coverage or masking: %s", encoded)
	}
}

func TestConfigV8ReadOnlyManagedPlanAndStatusUseEffectiveConfig(t *testing.T) {
	directory := t.TempDir()
	path := filepath.Join(directory, "config.yaml")
	t.Setenv(managed.DeploymentModeEnv, "")
	if err := os.WriteFile(
		filepath.Join(directory, ".env"),
		[]byte(managed.DeploymentModeEnv+"="+managed.DeploymentModeManagedEnterprise+"\n"),
		0o600,
	); err != nil {
		t.Fatal(err)
	}
	raw := []byte("config_version: 8\ndata_dir: " + directory + `
observability:
  buckets:
    platform.health:
      collect: {logs: false}
    ai.discovery:
      collect: {logs: false}
    diagnostic:
      collect: {logs: false}
`)
	if err := os.WriteFile(path, raw, 0o600); err != nil {
		t.Fatal(err)
	}

	base, err := config.ParseCompileObservabilityV8(
		path,
		raw,
		config.ObservabilityV8CompileOptions{DefaultDataDir: directory},
	)
	if err != nil {
		t.Fatal(err)
	}
	expected, err := config.WithObservabilityV8ManagedAIDDestination(
		base.Plan,
		config.ObservabilityV8ManagedAIDOptions{
			DeploymentMode: managed.DeploymentModeManagedEnterprise,
			Endpoint:       config.DefaultConfig().CiscoAIDefense.Endpoint,
		},
	)
	if err != nil {
		t.Fatal(err)
	}

	previousPath, previousDataDir := configV8ConfigPath, configV8DataDir
	previousValidateOut := configV8ValidateCmd.OutOrStdout()
	previousEffectiveOut := configV8EffectiveCmd.OutOrStdout()
	configV8ConfigPath, configV8DataDir = path, ""
	t.Cleanup(func() {
		configV8ConfigPath, configV8DataDir = previousPath, previousDataDir
		configV8ValidateCmd.SetOut(previousValidateOut)
		configV8EffectiveCmd.SetOut(previousEffectiveOut)
	})

	validationOutput := &strings.Builder{}
	configV8ValidateCmd.SetOut(validationOutput)
	if err := configV8ValidateCmd.RunE(configV8ValidateCmd, nil); err != nil {
		t.Fatal(err)
	}
	var validation configV8WireResponse
	if err := json.Unmarshal([]byte(validationOutput.String()), &validation); err != nil {
		t.Fatal(err)
	}

	effectiveOutput := &strings.Builder{}
	configV8EffectiveCmd.SetOut(effectiveOutput)
	if err := configV8EffectiveCmd.RunE(configV8EffectiveCmd, nil); err != nil {
		t.Fatal(err)
	}
	var effective configV8WireResponse
	if err := json.Unmarshal([]byte(effectiveOutput.String()), &effective); err != nil {
		t.Fatal(err)
	}
	if validation.PlanDigest != expected.Digest() || effective.PlanDigest != expected.Digest() {
		t.Fatalf(
			"read-only managed digests = validate %q, effective %q; want %q",
			validation.PlanDigest,
			effective.PlanDigest,
			expected.Digest(),
		)
	}
	if !bytes.Equal(effective.Effective, expected.EffectiveJSON()) {
		t.Fatalf("read-only effective plan does not match generated managed plan")
	}

	snapshot := expected.Snapshot()
	destination, ok := expected.RuntimeDestination(config.ObservabilityV8ManagedAIDDestinationName)
	if !ok || !destination.Generated || destination.Transport.Endpoint !=
		config.DefaultConfig().CiscoAIDefense.Endpoint+config.ObservabilityV8ManagedAIDIngestPath {
		t.Fatalf("generated managed destination = %+v, present=%v", destination, ok)
	}
	for bucket, detail := range map[observability.Bucket]string{
		observability.BucketPlatformHealth: "fail-open availability",
		observability.BucketAIDiscovery:    "endpoint inventory",
	} {
		policy, present := expected.Bucket(bucket)
		if !present || !policy.Collect.Logs {
			t.Fatalf("managed %s collection = %+v, present=%v", bucket, policy, present)
		}
		path := "observability.buckets." + string(bucket) + ".collect.logs"
		found := false
		for _, provenance := range snapshot.Provenance {
			if provenance.Path == path && provenance.Origin == "generated" &&
				strings.Contains(provenance.Detail, detail) {
				found = true
				break
			}
		}
		if !found {
			t.Fatalf("managed %s generated provenance is missing", bucket)
		}
	}
	if diagnostic, present := expected.Bucket(observability.BucketDiagnostic); !present || diagnostic.Collect.Logs {
		t.Fatalf("read-only managed plan broadened diagnostic collection: %+v", diagnostic)
	}
}

func TestReadConfigV8SourceRejectsOversizedInputWithCanonicalCode(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.yaml")
	tooLarge := strings.Repeat("x", config.ObservabilityV8MaxSourceBytes+1)
	if err := os.WriteFile(path, []byte(tooLarge), 0o600); err != nil {
		t.Fatal(err)
	}
	_, err := readConfigV8Source(path)
	if err == nil || !strings.Contains(err.Error(), "yaml_source_too_large") {
		t.Fatalf("oversized error = %v", err)
	}
}

func TestConfigV8ReferenceCommandUsesEmbeddedGeneratedArtifacts(t *testing.T) {
	previousSection, previousFormat := configV8ReferenceSection, configV8ReferenceFormat
	t.Cleanup(func() {
		configV8ReferenceSection, configV8ReferenceFormat = previousSection, previousFormat
	})
	for _, format := range []string{"yaml", "markdown"} {
		configV8ReferenceSection, configV8ReferenceFormat = "observability", format
		output := &strings.Builder{}
		configV8ReferenceCmd.SetOut(output)
		if err := configV8ReferenceCmd.RunE(configV8ReferenceCmd, nil); err != nil {
			t.Fatal(err)
		}
		if !strings.Contains(output.String(), "GENERATED FILE") || !strings.Contains(output.String(), "observability") {
			t.Fatalf("%s reference does not look like generated observability documentation", format)
		}
	}
	configV8ReferenceSection = "unknown"
	if err := configV8ReferenceCmd.RunE(configV8ReferenceCmd, nil); err == nil {
		t.Fatal("unsupported reference section was accepted")
	}
}

func publicSchemaForTest(t *testing.T) []byte {
	t.Helper()
	output := &strings.Builder{}
	configV8SchemaCmd.SetOut(output)
	if err := configV8SchemaCmd.RunE(configV8SchemaCmd, nil); err != nil {
		t.Fatal(err)
	}
	return []byte(output.String())
}

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

package schemas

import (
	"bytes"
	"compress/gzip"
	"encoding/json"
	"io"
	"os"
	"strings"
	"testing"

	jsonschema "github.com/santhosh-tekuri/jsonschema/v5"
	"gopkg.in/yaml.v3"
)

const configV8SchemaID = "https://schemas.defenseclaw.dev/config/v8/defenseclaw-config.schema.json"

func TestDefenseClawConfigV8SchemaEmbeddedExactly(t *testing.T) {
	t.Parallel()

	want, err := os.ReadFile("config/v8/defenseclaw-config.schema.json")
	if err != nil {
		t.Fatalf("read canonical schema: %v", err)
	}
	embedded := DefenseClawConfigV8Schema()
	if !bytes.Equal(embedded, want) {
		t.Fatal("embedded v8 config schema differs from canonical file bytes")
	}
	if !json.Valid(embedded) {
		t.Fatal("embedded v8 config schema is not valid JSON")
	}
	embedded[0] = 'x'
	if !bytes.Equal(DefenseClawConfigV8Schema(), want) {
		t.Fatal("caller mutated the process-wide embedded schema")
	}
}

func TestTelemetryV8LocksEmbeddedExactly(t *testing.T) {
	t.Parallel()
	for _, fixture := range []struct {
		path string
		get  func() []byte
	}{
		{path: "telemetry/v8/registry.yaml", get: TelemetryV8Registry},
		{path: "telemetry/v8/semconv.lock.yaml", get: TelemetryV8SemconvLock},
	} {
		want, err := os.ReadFile(fixture.path)
		if err != nil {
			t.Fatal(err)
		}
		got := fixture.get()
		if !bytes.Equal(got, want) {
			t.Fatalf("embedded %s differs from checked-in bytes", fixture.path)
		}
		got[0] = 'x'
		if !bytes.Equal(fixture.get(), want) {
			t.Fatalf("caller mutated embedded %s", fixture.path)
		}
	}
}

func TestGatewayEventSchemasEmbeddedExactly(t *testing.T) {
	t.Parallel()
	for _, fixture := range []struct {
		path string
		get  func() []byte
	}{
		{path: "gateway-event-envelope.json", get: GatewayEventEnvelopeSchema},
		{path: "scan-event.json", get: GatewayScanEventSchema},
		{path: "scan-finding-event.json", get: GatewayScanFindingEventSchema},
		{path: "activity-event.json", get: GatewayActivityEventSchema},
	} {
		fixture := fixture
		t.Run(fixture.path, func(t *testing.T) {
			t.Parallel()

			want, err := os.ReadFile(fixture.path)
			if err != nil {
				t.Fatal(err)
			}
			got := fixture.get()
			if !bytes.Equal(got, want) || !json.Valid(got) {
				t.Fatalf("embedded %s differs from checked-in valid JSON", fixture.path)
			}
			got[0] ^= 0xff
			if !bytes.Equal(fixture.get(), want) {
				t.Fatalf("caller mutated embedded %s", fixture.path)
			}
		})
	}
}

func TestTelemetryV8GeneratedArtifactsEmbeddedExactly(t *testing.T) {
	t.Parallel()
	for _, fixture := range []struct {
		path string
		get  func() []byte
	}{
		{path: "telemetry/runtime/telemetry.schema.json.gz", get: TelemetryV8Schema},
		{path: "telemetry/runtime/catalog.json.gz", get: TelemetryV8Catalog},
	} {
		fixture := fixture
		t.Run(fixture.path, func(t *testing.T) {
			t.Parallel()

			want := readCompressedTelemetryFixture(t, fixture.path)
			got := fixture.get()
			if !bytes.Equal(got, want) {
				t.Fatalf("embedded %s differs from checked-in bytes", fixture.path)
			}
			if !json.Valid(got) {
				t.Fatalf("embedded %s is not valid JSON", fixture.path)
			}
			got[0] ^= 0xff
			if !bytes.Equal(fixture.get(), want) {
				t.Fatalf("caller mutated embedded %s", fixture.path)
			}
		})
	}
}

func TestTelemetryV8CompatibilityProfilesEmbeddedExactly(t *testing.T) {
	t.Parallel()
	for _, profileID := range []string{
		"galileo-rich-v2",
		"local-observability-v1",
		"openinference-v1",
	} {
		profileID := profileID
		t.Run(profileID, func(t *testing.T) {
			t.Parallel()
			path := "telemetry/runtime/compatibility/" + profileID + ".json.gz"
			want := readCompressedTelemetryFixture(t, path)
			got := TelemetryV8CompatibilityProfile(profileID)
			if !bytes.Equal(got, want) || !json.Valid(got) {
				t.Fatalf("embedded %s differs from checked-in valid JSON", path)
			}
			got[0] ^= 0xff
			if !bytes.Equal(TelemetryV8CompatibilityProfile(profileID), want) {
				t.Fatalf("caller mutated embedded %s", path)
			}
		})
	}
	if got := TelemetryV8CompatibilityProfile("unknown-v1"); got != nil {
		t.Fatalf("unknown profile returned %d bytes", len(got))
	}
}

func readCompressedTelemetryFixture(t *testing.T, path string) []byte {
	t.Helper()
	encoded, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(encoded) < 10 || !bytes.Equal(encoded[:10], []byte{0x1f, 0x8b, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0xff}) {
		t.Fatalf("%s is not canonical deterministic gzip", path)
	}
	reader, err := gzip.NewReader(bytes.NewReader(encoded))
	if err != nil {
		t.Fatal(err)
	}
	defer reader.Close()
	payload, err := io.ReadAll(io.LimitReader(reader, maxTelemetryRuntimeAssetBytes+1))
	if err != nil {
		t.Fatal(err)
	}
	if len(payload) > maxTelemetryRuntimeAssetBytes {
		t.Fatalf("%s expands beyond the runtime size bound", path)
	}
	return payload
}

func TestDefenseClawConfigV8SchemaIdentityAndClosure(t *testing.T) {
	t.Parallel()

	var root map[string]any
	if err := json.Unmarshal(DefenseClawConfigV8Schema(), &root); err != nil {
		t.Fatalf("decode schema: %v", err)
	}
	if got := root["$id"]; got != configV8SchemaID {
		t.Fatalf("$id = %v, want %q", got, configV8SchemaID)
	}
	if got := root["x-defenseclaw-owner"]; got != "internal/config" {
		t.Fatalf("x-defenseclaw-owner = %v, want internal/config", got)
	}
	if got := root["additionalProperties"]; got != false {
		t.Fatalf("top-level additionalProperties = %v, want false", got)
	}
	assertClosedObjectSchemas(t, root, "$")
	raw := string(DefenseClawConfigV8Schema())
	for _, forbidden := range []string{"deferred-existing-section", "existingConfigSection"} {
		if strings.Contains(raw, forbidden) {
			t.Errorf("schema retains forbidden deferred coverage marker %q", forbidden)
		}
	}

	properties := schemaMap(t, root, "properties")
	allowedTopLevel := []string{
		"config_version",
		"llm",
		"default_llm_api_key_env",
		"default_llm_model",
		"data_dir",
		"quarantine_dir",
		"plugin_dir",
		"policy_dir",
		"environment",
		"tenant_id",
		"workspace_id",
		"deployment_mode",
		"discovery_source",
		"claw",
		"agent",
		"inspect_llm",
		"cisco_ai_defense",
		"scanners",
		"openshell",
		"watch",
		"firewall",
		"guardrail",
		"gateway",
		"cloud_auth",
		"skill_actions",
		"mcp_actions",
		"plugin_actions",
		"asset_policy",
		"registries",
		"claude_code",
		"codex",
		"connector_hooks",
		"webhooks",
		"observability",
		"privacy",
		"ai_discovery",
		"application_protection",
		"notifications",
		"managed",
	}
	if len(properties) != len(allowedTopLevel) {
		t.Errorf("top-level property count = %d, want %d", len(properties), len(allowedTopLevel))
	}
	for _, name := range allowedTopLevel {
		if _, ok := properties[name]; !ok {
			t.Errorf("current v8 top-level property %q is not enumerated", name)
		}
	}
	version := schemaMap(t, properties, "config_version")
	if got := version["const"]; got != float64(8) {
		t.Fatalf("config_version const = %v, want 8", got)
	}
	for _, legacy := range []string{"audit_db", "audit_sinks", "judge_bodies_db", "otel", "splunk"} {
		if _, ok := properties[legacy]; ok {
			t.Errorf("legacy top-level property %q must be omitted", legacy)
		}
	}

	defs := schemaMap(t, root, "$defs")
	for _, name := range []string{
		"observability",
		"resource",
		"tracePolicy",
		"traceLimits",
		"metricPolicy",
		"collectPolicy",
		"defaultBucketPolicy",
		"bucketPolicy",
		"customRedactionProfile",
		"fieldClassModes",
		"connectorObservability",
		"localStore",
		"jsonlDestination",
		"consoleDestination",
		"prometheusDestination",
		"splunkHECDestination",
		"httpJSONLDestination",
		"otlpDestination",
		"rotation",
		"batch",
		"networkSafety",
		"httpTLS",
		"otlpTLS",
		"secretEnvRef",
		"signalOverrides",
		"signalOverride",
		"logSend",
		"metricSend",
		"traceSend",
		"otlpSend",
		"logRoute",
		"metricRoute",
		"traceRoute",
		"otlpRoute",
		"selector",
	} {
		definition := schemaMap(t, defs, name)
		if got := definition["additionalProperties"]; got != false {
			t.Errorf("$defs.%s additionalProperties = %v, want false", name, got)
		}
	}

	connectors := schemaMap(t, defs, "connectorObservability")
	connectorProperties := schemaMap(t, connectors, "properties")
	if _, ok := connectorProperties["audit_sinks"]; ok {
		t.Error("observability.connectors.*.audit_sinks must be rejected")
	}

	llmProperties := schemaMap(t, schemaMap(t, defs, "llm"), "properties")
	if got := schemaMap(t, llmProperties, "timeout")["default"]; got != float64(30) {
		t.Errorf("llm.timeout default = %v, want 30", got)
	}
	if got := schemaMap(t, llmProperties, "max_retries")["default"]; got != float64(2) {
		t.Errorf("llm.max_retries default = %v, want 2", got)
	}
	guardrailProperties := schemaMap(t, schemaMap(t, defs, "guardrail"), "properties")
	if got := schemaMap(t, guardrailProperties, "hook_fail_mode")["default"]; got != "closed" {
		t.Errorf("guardrail.hook_fail_mode default = %v, want closed", got)
	}
	localProperties := schemaMap(t, schemaMap(t, defs, "localStore"), "properties")
	for _, name := range []string{"path", "judge_bodies_path"} {
		if _, ok := schemaMap(t, localProperties, name)["default"]; ok {
			t.Errorf("observability.local.%s must use the data_dir-dependent compiler default", name)
		}
	}
	if _, ok := schemaMap(t, defs, "profileName")["default"]; ok {
		t.Error("shared profileName must not default route-level inheritance to none")
	}
}

func assertClosedObjectSchemas(t *testing.T, value any, path string) {
	t.Helper()
	switch node := value.(type) {
	case map[string]any:
		if node["type"] == "object" {
			additional, ok := node["additionalProperties"]
			if !ok {
				t.Errorf("%s is an object schema without additionalProperties", path)
			} else {
				switch policy := additional.(type) {
				case bool:
					if policy {
						t.Errorf("%s is an open catch-all object schema", path)
					}
				case map[string]any:
					if len(policy) == 0 {
						t.Errorf("%s has an untyped additionalProperties catch-all", path)
					}
				default:
					t.Errorf("%s has invalid additionalProperties type %T", path, additional)
				}
			}
		}
		for key, child := range node {
			assertClosedObjectSchemas(t, child, path+"."+key)
		}
	case []any:
		for _, child := range node {
			assertClosedObjectSchemas(t, child, path+"[]")
		}
	}
}

func TestDefenseClawConfigV8SchemaCompilesAndValidates(t *testing.T) {
	t.Parallel()

	schema := compileConfigV8Schema(t)
	valid := map[string]any{
		"config_version": 8,
		"observability": map[string]any{
			"bucket_catalog_version": 1,
			"resource": map[string]any{
				"attributes": map[string]any{"service.name": "defenseclaw-gateway"},
			},
			"trace_policy": map[string]any{
				"sampler":          "parentbased_traceidratio",
				"sampler_arg":      "0.10",
				"semantic_profile": "defenseclaw-genai-rich-v1",
				"limits": map[string]any{
					"max_attributes_per_span": 128,
				},
			},
			"metric_policy": map[string]any{
				"export_interval_seconds": 60,
				"temporality":             "delta",
			},
			"defaults": map[string]any{
				"collect":           map[string]any{"logs": true, "traces": true, "metrics": true},
				"redaction_profile": "none",
			},
			"buckets": map[string]any{
				"security.finding": map[string]any{
					"collect":           map[string]any{"logs": true},
					"redaction_profile": "soc",
				},
			},
			"redaction_profiles": map[string]any{
				"soc": map[string]any{
					"extends":   "sensitive",
					"detectors": []any{"pii", "credentials", "secrets"},
					"field_classes": map[string]any{
						"content":    "detect",
						"credential": "remove",
					},
				},
			},
			"connectors": map[string]any{
				"codex": map[string]any{"webhooks": []any{}},
			},
			"local": map[string]any{
				"path":              "~/.defenseclaw/audit.db",
				"judge_bodies_path": "~/.defenseclaw/judge_bodies.db",
				"retention_days":    90,
			},
			"destinations": []any{
				map[string]any{
					"name": "local-jsonl", "kind": "jsonl", "path": "~/.defenseclaw/gateway.jsonl",
					"rotation": map[string]any{"max_size_mb": 50, "max_backups": 5, "max_age_days": 30, "compress": true},
				},
				map[string]any{
					"name": "console", "kind": "console",
					"send": map[string]any{"signals": []any{"logs"}, "buckets": []any{"*"}, "redaction_profile": "strict"},
				},
				map[string]any{
					"name": "prometheus", "kind": "prometheus", "listen": "127.0.0.1:9464", "path": "/metrics",
					"send": map[string]any{"signals": []any{"metrics"}, "buckets": []any{"platform.health"}},
				},
				map[string]any{
					"name": "splunk", "kind": "splunk_hec", "endpoint": "https://splunk.example.test/services/collector/event", "token_env": "SPLUNK_HEC_TOKEN",
				},
				map[string]any{
					"name": "archive", "kind": "http_jsonl", "endpoint": "https://archive.example.test/events",
					"headers": map[string]any{"X-Tenant": map[string]any{"env": "TENANT_ID"}},
				},
				map[string]any{
					"name": "otel", "kind": "otlp", "protocol": "http/protobuf", "endpoint": "https://otel.example.test",
					"signal_overrides": map[string]any{"traces": map[string]any{"path": "/v1/traces"}},
					"routes": []any{
						map[string]any{
							"name": "runtime", "signals": []any{"traces", "metrics"},
							"selector": map[string]any{"buckets": []any{"model.io", "tool.activity"}},
							"action":   "send", "redaction_profile": "sensitive",
						},
					},
				},
				map[string]any{
					"name": "override-only-otel", "kind": "otlp", "protocol": "http/protobuf",
					"signal_overrides": map[string]any{"traces": map[string]any{"endpoint": "https://traces.example.test/v1/traces"}},
					"send":             map[string]any{"signals": []any{"traces"}, "buckets": []any{"agent.lifecycle"}},
				},
			},
		},
	}
	if err := schema.Validate(valid); err != nil {
		t.Fatalf("representative v8 config rejected: %v", err)
	}

	invalid := []struct {
		name string
		doc  map[string]any
	}{
		{name: "unknown top level", doc: map[string]any{"config_version": 8, "mystery": true}},
		{name: "legacy audit database path", doc: map[string]any{"config_version": 8, "audit_db": "/tmp/audit.db"}},
		{name: "legacy otel", doc: map[string]any{"config_version": 8, "otel": map[string]any{}}},
		{name: "privacy disable redaction", doc: map[string]any{"config_version": 8, "privacy": map[string]any{"disable_redaction": true}}},
		{name: "ai discovery emit otel", doc: map[string]any{"config_version": 8, "ai_discovery": map[string]any{"emit_otel": false}}},
		{name: "connector audit sinks", doc: map[string]any{"config_version": 8, "observability": map[string]any{"connectors": map[string]any{"codex": map[string]any{"audit_sinks": []any{}}}}}},
		{name: "unknown observability field", doc: map[string]any{"config_version": 8, "observability": map[string]any{"mystery": true}}},
		{name: "send and routes", doc: map[string]any{"config_version": 8, "observability": map[string]any{"destinations": []any{map[string]any{
			"name": "console", "kind": "console",
			"send":   map[string]any{"signals": []any{"logs"}, "buckets": []any{"*"}},
			"routes": []any{map[string]any{"name": "all", "signals": []any{"logs"}, "selector": map[string]any{}}},
		}}}}},
		{name: "mixed wildcard", doc: map[string]any{"config_version": 8, "observability": map[string]any{"destinations": []any{map[string]any{
			"name": "console", "kind": "console",
			"send": map[string]any{"signals": []any{"logs"}, "buckets": []any{"*", "diagnostic"}},
		}}}}},
		{name: "unsupported OTLP JSON wire format", doc: map[string]any{"config_version": 8, "observability": map[string]any{"destinations": []any{map[string]any{
			"name": "otel", "kind": "otlp", "protocol": "http/json", "endpoint": "https://otel.example.test",
		}}}}},
		{name: "trace limit below family minimum", doc: map[string]any{"config_version": 8, "observability": map[string]any{
			"trace_policy": map[string]any{"limits": map[string]any{"max_attributes_per_span": 31}},
		}}},
	}
	for _, tc := range invalid {
		t.Run(tc.name, func(t *testing.T) {
			if err := schema.Validate(tc.doc); err == nil {
				t.Fatalf("invalid config unexpectedly passed: %#v", tc.doc)
			}
		})
	}
}

func TestDefenseClawConfigV8CurrentNonObservabilitySectionsValidate(t *testing.T) {
	t.Parallel()

	const fixture = `
config_version: 8
llm:
  model: openai/gpt-4o
  provider: openai
  api_key_env: DEFENSECLAW_LLM_KEY
  base_url: https://llm.example.test/v1
  timeout: 30
  max_retries: 3
  instance_name: primary
  forward_custom_headers: true
  region: us-east-1
  tls:
    ca_cert_file: /etc/defenseclaw/ca.pem
    insecure_skip_verify: false
  bedrock:
    region: us-east-1
    auth_mode: iam_credentials
    access_key_env: AWS_ACCESS_KEY_ID
    secret_key_env: AWS_SECRET_ACCESS_KEY
    deployment_aliases: {haiku: anthropic.claude-haiku}
  vertex:
    project_id: example-project
    region: us-central1
    auth_mode: workload_identity
  azure:
    endpoint: https://example.openai.azure.com
    api_version: 2025-01-01-preview
    auth_mode: managed_identity
  extra_headers: {X-Route: primary}
inspect_llm:
  provider: openai
  model: gpt-4o-mini
  api_key_env: INSPECT_LLM_KEY
  timeout: 30
  max_retries: 3
cisco_ai_defense:
  endpoint: https://us.api.inspect.aidefense.security.cisco.com
  api_key_env: CISCO_AI_DEFENSE_API_KEY
  timeout_ms: 3000
  enabled_rules: [prompt-injection]
  scan_hook_surface: true
scanners:
  skill_scanner:
    binary: skill-scanner
    use_llm: true
    use_behavioral: true
    enable_meta: true
    use_trigger: true
    use_virustotal: false
    use_aidefense: true
    llm_consensus_runs: 3
    policy: permissive
    lenient: true
    llm: {model: openai/gpt-4o-mini}
    virustotal_api_key_env: VIRUSTOTAL_API_KEY
  mcp_scanner:
    binary: mcp-scanner
    analyzers: auto
    scan_prompts: true
    scan_resources: true
    scan_instructions: true
    llm: {model: openai/gpt-4o-mini}
  plugin_scanner: plugin-scanner
  plugin_llm: {model: openai/gpt-4o-mini}
  codeguard: codeguard
openshell:
  binary: openshell
  policy_dir: /etc/openshell/policies
  mode: standalone
  version: 0.6.2
  sandbox_home: /home/sandbox
  auto_pair: true
  host_networking: true
watch:
  debounce_ms: 500
  auto_block: true
  allow_list_bypass_scan: true
  rescan_enabled: true
  rescan_interval_min: 60
  rescan_content_gated: true
firewall:
  config_file: /etc/pf.conf
  rules_file: /etc/defenseclaw/rules.conf
  anchor_name: defenseclaw
guardrail:
  enabled: true
  mode: action
  scanner_mode: both
  host: 127.0.0.1
  port: 18789
  connector: codex
  allow_empty_providers: false
  llm: {model: openai/gpt-4o}
  model: gpt-4o
  model_name: gpt-4o
  api_key_env: DEFENSECLAW_LLM_KEY
  api_base: https://llm.example.test/v1
  original_model: gpt-4o
  block_message: Request blocked by policy
  stream_buffer_bytes: 1048576
  rule_pack_dir: /etc/defenseclaw/guardrail
  detection_strategy: regex_judge
  detection_strategy_prompt: judge_first
  detection_strategy_completion: regex_judge
  detection_strategy_tool_call: regex_only
  judge_sweep: true
  retain_judge_bodies: true
  judge_persist_queue_depth: 1024
  allow_unknown_llm_domains: false
  hook_fail_mode: open
  hook_self_heal: true
  hook_self_heal_debounce_ms: 500
  hilt: {enabled: true, min_severity: HIGH}
  judge:
    enabled: true
    injection: true
    pii: true
    pii_prompt: true
    pii_completion: true
    tool_injection: true
    exfil: true
    timeout: 30
    hook_connectors: ['*']
    hook_timeout: 5
    llm: {model: openai/gpt-4o-mini}
    model: gpt-4o-mini
    api_key_env: DEFENSECLAW_LLM_KEY
    api_base: https://llm.example.test/v1
    fallbacks: [openai/gpt-4o-mini]
    adjudication_timeout: 5
  connectors:
    codex:
      mode: observe
      hilt: {enabled: true, min_severity: MEDIUM}
      hook_fail_mode: closed
      block_message: Connector request blocked
      rule_pack_dir: /etc/defenseclaw/codex-rules
      enabled: true
gateway:
  host: 127.0.0.1
  port: 18789
  token_env: DEFENSECLAW_GATEWAY_TOKEN
  tls: false
  tls_skip_verify: false
  device_key_file: /etc/defenseclaw/device.key
  auto_approve_safe: false
  reconnect_ms: 800
  max_reconnect_ms: 15000
  approval_timeout_s: 30
  api_port: 18970
  api_bind: 127.0.0.1
  fleet_mode: auto
  config_reload: {mode: hot}
  watcher:
    enabled: true
    skill: {enabled: true, take_action: true, dirs: [/opt/skills]}
    plugin: {enabled: true, take_action: true, dirs: [/opt/plugins]}
    mcp: {take_action: true}
  watchdog: {enabled: true, interval: 30, debounce: 2}
skill_actions: &actions
  critical: {file: quarantine, runtime: disable, install: block}
  high: {file: quarantine, runtime: disable, install: block}
  medium: {file: none, runtime: enable, install: allow}
  low: {file: none, runtime: enable, install: allow}
  info: {file: none, runtime: enable, install: none}
mcp_actions: *actions
plugin_actions: *actions
asset_policy:
  enabled: true
  mode: action
  mcp:
    default: deny
    registry_required: true
    registry_empty_action: warn
    registry:
      - {name: approved-mcp, connector: codex, url: 'https://mcp.example.test', transport: http}
    allowed: [{name: local-mcp, command: mcp-server, args_prefix: [serve]}]
    denied: [{name: unsafe-mcp, reason: prohibited}]
    runtime_detection: {enabled: true, terminal_commands: true, unknown_terminal_mcp: observe}
  skill: {default: allow, registry_required: false, registry_empty_action: deny, registry: [], allowed: [], denied: []}
  plugin: {default: block, registry_required: false, registry_empty_action: allow, registry: [], allowed: [], denied: []}
  connectors:
    codex:
      mode: observe
      mcp: {default: allow, registry_required: false, registry_empty_action: warn}
registries:
  sources:
    - id: company-skills
      kind: http_yaml
      url: https://registry.example.test/skills.yaml
      content: skill
      auth_env: REGISTRY_TOKEN
      enabled: true
      auto_sync: true
      sync_interval_hours: 24
      last_sync: '2026-01-01T00:00:00Z'
      last_status: ok
application_protection:
  enabled: true
  min_confidence: 0.8
  remove_when_gone: false
  gone_after_min: 60
  include_connectors: [codex, claudecode]
  exclude_connectors: [cursor]
  guardrail: {mode: observe, hook_fail_mode: open, enabled: true}
  asset_policy: {mode: observe}
  connectors:
    codex:
      enabled: true
      min_confidence: 0.9
      guardrail: {mode: action, enabled: true}
      asset_policy: {mode: action}
notifications:
  enabled: true
  block_enforced: true
  block_would_block: false
  hitl_approval: true
  sources: {hook: true, guardrail: true, asset_policy: true}
  dedup_window: 30s
  max_per_minute: 12
`

	var document any
	if err := yaml.Unmarshal([]byte(fixture), &document); err != nil {
		t.Fatalf("parse representative current config: %v", err)
	}
	if err := compileConfigV8Schema(t).Validate(document); err != nil {
		t.Fatalf("representative current non-observability config rejected: %v", err)
	}

	defaultsCompatible := map[string]any{"config_version": 8}
	for _, section := range []string{
		"llm", "inspect_llm", "cisco_ai_defense", "scanners", "openshell", "watch", "firewall",
		"guardrail", "gateway", "skill_actions", "mcp_actions", "plugin_actions", "asset_policy",
		"registries", "application_protection", "notifications",
	} {
		defaultsCompatible[section] = map[string]any{}
	}
	if err := compileConfigV8Schema(t).Validate(defaultsCompatible); err != nil {
		t.Fatalf("empty sections that receive current runtime defaults were rejected: %v", err)
	}
}

func TestDefenseClawConfigV8RejectsUnknownNestedCurrentFields(t *testing.T) {
	t.Parallel()
	schema := compileConfigV8Schema(t)
	for _, tc := range []struct {
		name string
		doc  map[string]any
	}{
		{"llm", map[string]any{"config_version": 8, "llm": map[string]any{"mystery": true}}},
		{"scanner", map[string]any{"config_version": 8, "scanners": map[string]any{"skill_scanner": map[string]any{"mystery": true}}}},
		{"guardrail", map[string]any{"config_version": 8, "guardrail": map[string]any{"mystery": true}}},
		{"guardrail connector", map[string]any{"config_version": 8, "guardrail": map[string]any{"connectors": map[string]any{"codex": map[string]any{"mystery": true}}}}},
		{"gateway", map[string]any{"config_version": 8, "gateway": map[string]any{"watcher": map[string]any{"mystery": true}}}},
		{"action matrix", map[string]any{"config_version": 8, "skill_actions": map[string]any{"critical": map[string]any{"mystery": true}}}},
		{"asset policy", map[string]any{"config_version": 8, "asset_policy": map[string]any{"mcp": map[string]any{"mystery": true}}}},
		{"registry", map[string]any{"config_version": 8, "registries": map[string]any{"sources": []any{map[string]any{"mystery": true}}}}},
		{"application protection", map[string]any{"config_version": 8, "application_protection": map[string]any{"connectors": map[string]any{"codex": map[string]any{"mystery": true}}}}},
		{"notifications", map[string]any{"config_version": 8, "notifications": map[string]any{"sources": map[string]any{"mystery": true}}}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if err := schema.Validate(tc.doc); err == nil {
				t.Fatalf("unknown nested field unexpectedly passed: %#v", tc.doc)
			}
		})
	}
}

func TestDefenseClawConfigV8ReferenceValidates(t *testing.T) {
	t.Parallel()

	raw := DefenseClawConfigV8ObservabilityReferenceYAML()
	var document any
	if err := yaml.Unmarshal(raw, &document); err != nil {
		t.Fatalf("parse v8 reference config: %v", err)
	}
	if err := compileConfigV8Schema(t).Validate(document); err != nil {
		t.Fatalf("v8 observability reference violates canonical schema: %v", err)
	}

	onDisk, err := os.ReadFile("config/v8/reference/observability.yaml")
	if err != nil {
		t.Fatalf("read canonical v8 reference: %v", err)
	}
	if !bytes.Equal(raw, onDisk) {
		t.Fatal("embedded v8 YAML reference differs from canonical file")
	}
	markdown := DefenseClawConfigV8ObservabilityReferenceMarkdown()
	if len(markdown) == 0 || !bytes.Contains(markdown, []byte("Complete source field catalog")) {
		t.Fatal("embedded v8 Markdown reference is empty or incomplete")
	}
}

func compileConfigV8Schema(t *testing.T) *jsonschema.Schema {
	t.Helper()
	compiler := jsonschema.NewCompiler()
	compiler.Draft = jsonschema.Draft2020
	if err := compiler.AddResource(configV8SchemaID, strings.NewReader(string(DefenseClawConfigV8Schema()))); err != nil {
		t.Fatalf("add schema resource: %v", err)
	}
	compiled, err := compiler.Compile(configV8SchemaID)
	if err != nil {
		t.Fatalf("compile schema: %v", err)
	}
	return compiled
}

func schemaMap(t *testing.T, parent map[string]any, key string) map[string]any {
	t.Helper()
	value, ok := parent[key]
	if !ok {
		t.Fatalf("schema object missing %q", key)
	}
	result, ok := value.(map[string]any)
	if !ok {
		t.Fatalf("schema %q has type %T, want object", key, value)
	}
	return result
}

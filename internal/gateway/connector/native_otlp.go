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

package connector

import (
	"fmt"
	"net/url"
	"sort"
	"strings"
)

// NativeOTLPKind enumerates the shapes a vendor CLI accepts for telling
// it where to ship OTLP. It exists so a single installer can drive every
// connector's native-OTLP wiring without per-connector branching in the
// gateway core. See unify-hook-collector_*.plan.md (Phase A.3).
//
//   - NativeOTLPEnvBlock — env vars baked into the agent's config file
//     (claudecode's settings.json `env`, copilot's process env).
//   - NativeOTLPTOMLBlock — a TOML table inserted into the agent's
//     config file (codex's `[otel.exporter.otlp-http]` block).
//   - NativeOTLPJSONBlock — a JSON object inserted into the agent's
//     settings file (geminicli's `telemetry` block).
//   - NativeOTLPFileSink — the agent writes OTLP to a local JSONL file
//     instead of (or in addition to) the network endpoint (copilot CLI
//     `--telemetry-file`, gemini `--outfile`).
type NativeOTLPKind string

const (
	NativeOTLPEnvBlock  NativeOTLPKind = "env_block"
	NativeOTLPTOMLBlock NativeOTLPKind = "toml_block"
	NativeOTLPJSONBlock NativeOTLPKind = "json_block"
	NativeOTLPFileSink  NativeOTLPKind = "file_sink"
)

// NativeOTLPSignal identifies one of the three OTLP signal kinds.
type NativeOTLPSignal string

const (
	NativeOTLPSignalTraces  NativeOTLPSignal = "traces"
	NativeOTLPSignalMetrics NativeOTLPSignal = "metrics"
	NativeOTLPSignalLogs    NativeOTLPSignal = "logs"
)

// AllNativeOTLPSignals returns every supported signal in a stable order.
// Used by per-signal env writers (Claude Code, Goose-style agents) and
// by the parity tests in connector_test.go so the comparison is order-
// independent.
func AllNativeOTLPSignals() []NativeOTLPSignal {
	return []NativeOTLPSignal{NativeOTLPSignalTraces, NativeOTLPSignalMetrics, NativeOTLPSignalLogs}
}

// NativeOTLPSpec describes how DefenseClaw should configure a connector's
// native OTLP exporter. The spec is intentionally generic enough to
// accommodate the four connectors that ship native OTLP today (codex,
// claudecode, geminicli, copilot) AND the next wave the web survey
// surfaced (OpenCode, Cline, Goose, HolmesGPT, Kilo Code) without
// per-connector code in the gateway.
//
// Field rules:
//
//   - Endpoint: the OTLP-HTTP endpoint URL. For path-token connectors
//     (geminicli) PathToken is set instead and Endpoint is constructed
//     by the installer.
//   - Protocol: "http/json" or "http/protobuf". Default "http/json".
//   - Headers: HTTP headers the exporter should set on every outbound
//     OTLP request. Used for tenant-aware tokens. Keys are canonicalized
//     (lower-case) by the installer so equality checks downstream are
//     case-insensitive.
//   - PerSignal: when true the installer emits per-signal exporter env
//     vars (OTEL_TRACES_EXPORTER / OTEL_METRICS_EXPORTER /
//     OTEL_LOGS_EXPORTER) and per-signal endpoint env vars. Required
//     for Claude Code / Copilot / Goose-style agents that distinguish
//     the three signals; ignored for path-token connectors.
//   - SignalPaths: optional, maps each signal to a URL-path suffix
//     (e.g. {traces: "/v1/traces", metrics: "/v1/metrics"}). When unset
//     the installer defaults to /v1/<signal>.
//   - PathToken: optional. When non-empty the installer wires a
//     /otlp/<scope>/<token>/v1/<signal> URL pattern instead of carrying
//     the token in a header. Required for connectors whose exporter
//     can't set arbitrary HTTP headers (geminicli).
//   - PathScope: paired with PathToken. The connector-scoped namespace
//     used in /otlp/<scope>/<token>/v1/<signal>. Validated against the
//     closed allow-list in OTLPPathTokenScopes().
//   - FilePath: for NativeOTLPFileSink kinds. The local path the agent
//     writes OTLP-JSON to. Mutually exclusive with Endpoint.
//   - ExtraEnv: connector-specific env vars (e.g.
//     CLAUDE_CODE_ENHANCED_TELEMETRY_BETA=1, COPILOT_OTEL_ENABLED=true)
//     that the connector needs in addition to the standard OTEL_*
//     family. Merged into the env block in deterministic key order.
//   - ServiceName / ResourceAttributes: identify the source connector
//     to downstream OTLP consumers. ResourceAttributes is a flat
//     map[string]string serialized as "k=v,k=v" per the OTLP spec.
//   - LogUserPrompts: when true (and DefenseClaw redaction is disabled)
//     the installer flips the connector-specific prompt-capture switch
//     (codex `log_user_prompt = true`, claudecode `OTEL_LOG_USER_PROMPTS=1`).
type NativeOTLPSpec struct {
	Kind               NativeOTLPKind
	Endpoint           string
	Protocol           string
	Headers            map[string]string
	PerSignal          bool
	SignalPaths        map[NativeOTLPSignal]string
	PathToken          string
	PathScope          OTLPPathTokenScope
	FilePath           string
	ExtraEnv           map[string]string
	ServiceName        string
	ResourceAttributes map[string]string
	LogUserPrompts     bool
}

// Validate returns a non-nil error when the spec is internally
// inconsistent. Useful in tests and during connector setup to catch
// "endpoint set on a file-sink" or "path-token on an env-block" before
// the installer produces a malformed config file.
func (s NativeOTLPSpec) Validate() error {
	if s.Kind == "" {
		return fmt.Errorf("NativeOTLPSpec: Kind is required")
	}
	switch s.Kind {
	case NativeOTLPEnvBlock, NativeOTLPTOMLBlock, NativeOTLPJSONBlock, NativeOTLPFileSink:
	default:
		return fmt.Errorf("NativeOTLPSpec: unknown Kind %q", s.Kind)
	}
	if s.Kind == NativeOTLPFileSink && strings.TrimSpace(s.FilePath) == "" {
		return fmt.Errorf("NativeOTLPSpec: FilePath is required for file_sink")
	}
	if s.Kind != NativeOTLPFileSink && strings.TrimSpace(s.Endpoint) == "" && strings.TrimSpace(s.PathToken) == "" {
		return fmt.Errorf("NativeOTLPSpec: Endpoint or PathToken is required for kind %q", s.Kind)
	}
	if strings.TrimSpace(s.PathToken) != "" && !validOTLPScope(s.PathScope) {
		return fmt.Errorf("NativeOTLPSpec: PathToken requires a valid PathScope")
	}
	return nil
}

// normalizedProtocol returns the protocol value the spec advertises with
// "http/json" as the safe default. Codex's deserializer is case-sensitive
// (rename_all = "kebab-case"); this normalization is deterministic so
// connectors don't drift on the wire format.
func (s NativeOTLPSpec) normalizedProtocol() string {
	p := strings.TrimSpace(s.Protocol)
	if p == "" {
		return "http/json"
	}
	return p
}

// signalPath returns the URL path for *signal*, defaulting to
// /v1/<signal> when not overridden in SignalPaths.
func (s NativeOTLPSpec) signalPath(signal NativeOTLPSignal) string {
	if s.SignalPaths != nil {
		if path, ok := s.SignalPaths[signal]; ok && path != "" {
			return path
		}
	}
	return "/v1/" + string(signal)
}

// signalEndpoint returns the absolute URL the connector should target
// for *signal*. When PathToken is set the URL embeds it; otherwise the
// Endpoint base is used.
func (s NativeOTLPSpec) signalEndpoint(signal NativeOTLPSignal) string {
	path := s.signalPath(signal)
	if strings.TrimSpace(s.PathToken) != "" {
		base := strings.TrimRight(strings.TrimSpace(s.Endpoint), "/")
		if base == "" {
			return ""
		}
		return base + "/otlp/" + string(s.PathScope) + "/" + url.PathEscape(s.PathToken) + path
	}
	return strings.TrimRight(strings.TrimSpace(s.Endpoint), "/") + path
}

// pathTokenBaseEndpoint returns the path-token endpoint WITHOUT a
// signal suffix. Vendor exporters that auto-append /v1/<signal> to
// their configured base (Gemini CLI's settings.json otlpEndpoint
// field) consume this; signalEndpoint() is for vendors that expect a
// fully-qualified per-signal URL (Codex's [otel.*_exporter.otlp-http]).
func (s NativeOTLPSpec) pathTokenBaseEndpoint() string {
	if strings.TrimSpace(s.PathToken) == "" {
		return strings.TrimRight(strings.TrimSpace(s.Endpoint), "/")
	}
	base := strings.TrimRight(strings.TrimSpace(s.Endpoint), "/")
	if base == "" {
		return ""
	}
	return base + "/otlp/" + string(s.PathScope) + "/" + url.PathEscape(s.PathToken)
}

// EnvBlock renders an env-block spec into a deterministically-ordered
// map[string]string suitable for writing into Claude Code's settings.json
// `env`, OpenCode's experimental.openTelemetry config, Goose's
// ~/.config/goose/config.yaml, etc. The returned map is a fresh copy.
//
// When PerSignal is true the renderer emits the three per-signal exporter
// vars AND OTEL_EXPORTER_OTLP_<SIGNAL>_ENDPOINT vars in addition to the
// combined endpoint. This matches what Claude Code, Copilot CLI, and
// Goose all accept.
//
// Returns an error if the spec is not an env-block. Callers that want a
// non-strict renderer (e.g. tests that check parity across kinds) should
// switch on Kind before calling.
func (s NativeOTLPSpec) EnvBlock() (map[string]string, error) {
	if s.Kind != NativeOTLPEnvBlock {
		return nil, fmt.Errorf("NativeOTLPSpec.EnvBlock: kind %q is not env_block", s.Kind)
	}
	if err := s.Validate(); err != nil {
		return nil, err
	}
	out := map[string]string{}

	endpoint := strings.TrimRight(strings.TrimSpace(s.Endpoint), "/")
	if endpoint != "" {
		out["OTEL_EXPORTER_OTLP_ENDPOINT"] = endpoint
	}
	out["OTEL_EXPORTER_OTLP_PROTOCOL"] = s.normalizedProtocol()

	if len(s.Headers) > 0 {
		out["OTEL_EXPORTER_OTLP_HEADERS"] = serializeOTLPHeaders(s.Headers)
	}

	if s.PerSignal {
		out["OTEL_METRICS_EXPORTER"] = "otlp"
		out["OTEL_LOGS_EXPORTER"] = "otlp"
		out["OTEL_TRACES_EXPORTER"] = "otlp"
		for _, signal := range AllNativeOTLPSignals() {
			ep := s.signalEndpoint(signal)
			if ep == "" {
				continue
			}
			key := "OTEL_EXPORTER_OTLP_" + strings.ToUpper(string(signal)) + "_ENDPOINT"
			out[key] = ep
		}
	}

	if strings.TrimSpace(s.ServiceName) != "" {
		out["OTEL_SERVICE_NAME"] = s.ServiceName
	}
	if len(s.ResourceAttributes) > 0 {
		out["OTEL_RESOURCE_ATTRIBUTES"] = serializeOTLPAttributes(s.ResourceAttributes)
	}

	for k, v := range s.ExtraEnv {
		if strings.TrimSpace(k) == "" {
			continue
		}
		out[k] = v
	}
	return out, nil
}

// TOMLBlock renders a TOML-block spec into a map suitable for embedding
// into codex's config.toml under the `otel` key. The shape matches
// codex's serde schema exactly — see buildCodexOtelBlock in codex.go.
func (s NativeOTLPSpec) TOMLBlock() (map[string]interface{}, error) {
	if s.Kind != NativeOTLPTOMLBlock {
		return nil, fmt.Errorf("NativeOTLPSpec.TOMLBlock: kind %q is not toml_block", s.Kind)
	}
	if err := s.Validate(); err != nil {
		return nil, err
	}
	headers := map[string]interface{}{}
	for k, v := range s.Headers {
		headers[strings.ToLower(strings.TrimSpace(k))] = v
	}
	exporterFor := func(signal NativeOTLPSignal) map[string]interface{} {
		ep := s.signalEndpoint(signal)
		return map[string]interface{}{
			"otlp-http": map[string]interface{}{
				"endpoint": ep,
				"protocol": s.normalizedProtocol(),
				"headers":  headers,
			},
		}
	}
	return map[string]interface{}{
		"log_user_prompt":  s.LogUserPrompts,
		"exporter":         exporterFor(NativeOTLPSignalLogs),
		"trace_exporter":   exporterFor(NativeOTLPSignalTraces),
		"metrics_exporter": exporterFor(NativeOTLPSignalMetrics),
	}, nil
}

// JSONBlock renders a JSON-block spec into a map suitable for embedding
// into Gemini CLI's settings.json `telemetry` block. The shape matches
// the Gemini schema described in patchGeminiTelemetry (hook_only.go).
//
// The endpoint emitted is the path-token BASE (no /v1/<signal> suffix)
// because Gemini's OTel exporter auto-appends the signal path. Adding
// it here would produce /otlp/<scope>/<token>/v1/traces/v1/traces at
// request time which the gateway's tokenAuth middleware rejects.
func (s NativeOTLPSpec) JSONBlock() (map[string]interface{}, error) {
	if s.Kind != NativeOTLPJSONBlock {
		return nil, fmt.Errorf("NativeOTLPSpec.JSONBlock: kind %q is not json_block", s.Kind)
	}
	if err := s.Validate(); err != nil {
		return nil, err
	}
	out := map[string]interface{}{
		"enabled":      true,
		"target":       "local",
		"useCollector": true,
		"otlpProtocol": "http",
		"logPrompts":   s.LogUserPrompts,
	}
	endpoint := s.pathTokenBaseEndpoint()
	if endpoint != "" {
		out["otlpEndpoint"] = endpoint
	}
	return out, nil
}

// FileSinkPath returns the configured local sink path for a FileSink
// spec. Returns an error for any other kind so callers cannot mix the
// path-sink and network paths up.
func (s NativeOTLPSpec) FileSinkPath() (string, error) {
	if s.Kind != NativeOTLPFileSink {
		return "", fmt.Errorf("NativeOTLPSpec.FileSinkPath: kind %q is not file_sink", s.Kind)
	}
	if err := s.Validate(); err != nil {
		return "", err
	}
	return s.FilePath, nil
}

// serializeOTLPHeaders renders Headers as the comma-separated key=value
// string the OTel spec defines for OTEL_EXPORTER_OTLP_HEADERS. Sorted
// by lowercase key so the output is deterministic across runs (env
// blocks are written into agent config files that operators read and
// diff).
func serializeOTLPHeaders(h map[string]string) string {
	keys := make([]string, 0, len(h))
	for k := range h {
		if strings.TrimSpace(k) == "" {
			continue
		}
		keys = append(keys, strings.ToLower(k))
	}
	sort.Strings(keys)
	parts := make([]string, 0, len(keys))
	for _, k := range keys {
		// Look up the original value preserving the input's case
		// for the value; only the key is canonicalized to lower-case.
		for origKey, v := range h {
			if strings.ToLower(origKey) == k {
				parts = append(parts, k+"="+v)
				break
			}
		}
	}
	return strings.Join(parts, ",")
}

// serializeOTLPAttributes renders ResourceAttributes as the
// comma-separated key=value string the OTel spec defines for
// OTEL_RESOURCE_ATTRIBUTES. Sorted for determinism. Keys are NOT
// case-canonicalized because attribute names like
// "defenseclaw.connector" are case-sensitive on the receiver side.
func serializeOTLPAttributes(a map[string]string) string {
	keys := make([]string, 0, len(a))
	for k := range a {
		if strings.TrimSpace(k) == "" {
			continue
		}
		keys = append(keys, k)
	}
	sort.Strings(keys)
	parts := make([]string, 0, len(keys))
	for _, k := range keys {
		parts = append(parts, k+"="+a[k])
	}
	return strings.Join(parts, ",")
}

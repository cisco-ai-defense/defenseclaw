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

package config

import (
	"fmt"
	"os"
	"sort"
	"strings"
)

// AuditSinkKind enumerates the built-in sink implementations. Adding a
// new sink requires (1) a new constant here, (2) a per-kind config struct
// below, (3) a builder branch in internal/cli/audit_sinks.go, and (4) a
// TUI editor entry in internal/tui/configedit.go.
type AuditSinkKind string

const (
	SinkKindSplunkHEC AuditSinkKind = "splunk_hec"
	SinkKindOTLPLogs  AuditSinkKind = "otlp_logs"
	SinkKindHTTPJSONL AuditSinkKind = "http_jsonl"
)

// AuditSink is the YAML-facing configuration for a single audit-event
// destination. The Manager fans out every audit event to every enabled
// sink whose action/severity filters match.
//
// Exactly one of {SplunkHEC, OTLPLogs, HTTPJSONL} must be populated, and
// it must match Kind. Validate() enforces this.
type AuditSink struct {
	Name    string        `mapstructure:"name"    yaml:"name"`
	Kind    AuditSinkKind `mapstructure:"kind"    yaml:"kind"`
	Enabled bool          `mapstructure:"enabled" yaml:"enabled"`

	// Common batching/retry knobs. Sink kinds may interpret 0 as a
	// per-kind default; see the corresponding sinks impl.
	BatchSize      int `mapstructure:"batch_size"       yaml:"batch_size,omitempty"`
	FlushIntervalS int `mapstructure:"flush_interval_s" yaml:"flush_interval_s,omitempty"`
	TimeoutS       int `mapstructure:"timeout_s"        yaml:"timeout_s,omitempty"`

	// Per-sink filtering. MinSeverity follows the standard ranking
	// (INFO < LOW < MEDIUM < HIGH < CRITICAL); empty matches all. Actions
	// is an allowlist of audit-action names (e.g. "guardrail-verdict",
	// "scan"); empty matches all.
	MinSeverity string   `mapstructure:"min_severity" yaml:"min_severity,omitempty"`
	Actions     []string `mapstructure:"actions"      yaml:"actions,omitempty"`

	// Kind-specific blocks. Pointers so unset blocks are absent from YAML.
	SplunkHEC *SplunkHECSinkConfig `mapstructure:"splunk_hec" yaml:"splunk_hec,omitempty"`
	OTLPLogs  *OTLPLogsSinkConfig  `mapstructure:"otlp_logs"  yaml:"otlp_logs,omitempty"`
	HTTPJSONL *HTTPJSONLSinkConfig `mapstructure:"http_jsonl" yaml:"http_jsonl,omitempty"`
}

// Validate ensures required fields are present and exactly one kind block
// is populated. Returns a descriptive error suitable for surfacing to the
// operator.
func (s *AuditSink) Validate() error {
	if s.Name == "" {
		return fmt.Errorf("audit sink: name is required")
	}
	switch s.Kind {
	case SinkKindSplunkHEC:
		if s.SplunkHEC == nil {
			return fmt.Errorf("audit sink %q: kind=splunk_hec requires splunk_hec block", s.Name)
		}
		return s.SplunkHEC.Validate(s.Name)
	case SinkKindOTLPLogs:
		if s.OTLPLogs == nil {
			return fmt.Errorf("audit sink %q: kind=otlp_logs requires otlp_logs block", s.Name)
		}
		return s.OTLPLogs.Validate(s.Name)
	case SinkKindHTTPJSONL:
		if s.HTTPJSONL == nil {
			return fmt.Errorf("audit sink %q: kind=http_jsonl requires http_jsonl block", s.Name)
		}
		return s.HTTPJSONL.Validate(s.Name)
	case "":
		return fmt.Errorf("audit sink %q: kind is required (one of: splunk_hec, otlp_logs, http_jsonl)", s.Name)
	default:
		return fmt.Errorf("audit sink %q: unknown kind %q", s.Name, s.Kind)
	}
}

// SplunkHECSinkConfig configures a single Splunk HTTP Event Collector
// destination. Tokens come from the env (TokenEnv) — direct Token is
// supported only for ergonomic local development and triggers a startup
// warning.
type SplunkHECSinkConfig struct {
	Endpoint   string `mapstructure:"endpoint"    yaml:"endpoint"`
	Token      string `mapstructure:"token"       yaml:"token,omitempty"`
	TokenEnv   string `mapstructure:"token_env"   yaml:"token_env,omitempty"`
	Index      string `mapstructure:"index"       yaml:"index,omitempty"`
	Source     string `mapstructure:"source"      yaml:"source,omitempty"`
	SourceType string `mapstructure:"sourcetype"  yaml:"sourcetype,omitempty"`
	// VerifyTLS is the LEGACY opt-in-to-security flag. Pre-the
	// transport defaulted to InsecureSkipVerify and operators had to
	// set verify_tls=true to enable certificate validation. The field
	// is retained for backward compatibility — if explicitly true it
	// is honoured (no-op against the new secure default); explicit
	// false is silently IGNORED. Operators who want the old insecure
	// behaviour must set insecure_skip_verify=true.
	VerifyTLS bool `mapstructure:"verify_tls"  yaml:"verify_tls,omitempty"`
	// InsecureSkipVerify is the fix. When true, the sink does
	// NOT validate the HEC server's certificate — required only for
	// dev environments with self-signed HEC. Defaults to false (TLS
	// verification enabled) so omitting the field never silently
	// downgrades audit-token transport.
	InsecureSkipVerify bool `mapstructure:"insecure_skip_verify" yaml:"insecure_skip_verify,omitempty"`

	// SourceTypeOverrides lets operators map a canonical audit
	// action onto a dedicated Splunk sourcetype, e.g.:
	//
	//   sourcetype_overrides:
	//     llm-judge-response: defenseclaw:judge
	//     guardrail-verdict:  defenseclaw:verdict
	//
	// When omitted, the sink still emits Phase 3 defaults
	// (defenseclaw:judge for judge events, defenseclaw:verdict
	// for guardrail verdicts) so out-of-the-box Splunk
	// dashboards work without any operator wiring.
	SourceTypeOverrides map[string]string `mapstructure:"sourcetype_overrides" yaml:"sourcetype_overrides,omitempty"`
}

// ResolvedToken returns the env-resolved HEC token, falling back to the
// inline Token field. Empty string means no token configured.
func (c *SplunkHECSinkConfig) ResolvedToken() string {
	if c == nil {
		return ""
	}
	if c.TokenEnv != "" {
		if v := os.Getenv(c.TokenEnv); v != "" {
			return v
		}
	}
	return c.Token
}

func (c *SplunkHECSinkConfig) Validate(sinkName string) error {
	if c.Endpoint == "" {
		return fmt.Errorf("audit sink %q: splunk_hec.endpoint is required", sinkName)
	}
	if !strings.HasPrefix(strings.ToLower(c.Endpoint), "http") {
		return fmt.Errorf("audit sink %q: splunk_hec.endpoint must start with http(s):// (got %q)",
			sinkName, c.Endpoint)
	}
	if c.ResolvedToken() == "" {
		return fmt.Errorf("audit sink %q: splunk_hec token is empty (set token_env or token)", sinkName)
	}
	return nil
}

// OTLPLogsSinkConfig configures an OTLP-logs destination *separate* from
// the global telemetry exporter. This is the recommended way to ship
// audit events to a SIEM-specific OTLP collector while keeping
// application traces/metrics flowing to a different backend.
//
// All header values support ${ENV_VAR} substitution at sink-build time.
// No vendor-specific defaults are injected (unlike the legacy code that
// auto-set X-SF-Token).
type OTLPLogsSinkConfig struct {
	Endpoint   string            `mapstructure:"endpoint"   yaml:"endpoint"`
	Protocol   string            `mapstructure:"protocol"   yaml:"protocol,omitempty"` // grpc|http (default grpc)
	URLPath    string            `mapstructure:"url_path"   yaml:"url_path,omitempty"`
	Headers    map[string]string `mapstructure:"headers"    yaml:"headers,omitempty"`
	Insecure   bool              `mapstructure:"insecure"   yaml:"insecure,omitempty"`
	CACertPath string            `mapstructure:"ca_cert"    yaml:"ca_cert,omitempty"`
	LoggerName string            `mapstructure:"logger_name" yaml:"logger_name,omitempty"`
}

func (c *OTLPLogsSinkConfig) Validate(sinkName string) error {
	if c.Endpoint == "" {
		return fmt.Errorf("audit sink %q: otlp_logs.endpoint is required", sinkName)
	}
	if c.Protocol != "" && c.Protocol != "grpc" && c.Protocol != "http" {
		return fmt.Errorf("audit sink %q: otlp_logs.protocol must be grpc or http (got %q)",
			sinkName, c.Protocol)
	}
	return nil
}

// HTTPJSONLSinkConfig configures a generic webhook sink. Each event is
// POSTed (or PUTed) as a single JSON object, or batched as line-delimited
// JSON when batch_size > 1.
type HTTPJSONLSinkConfig struct {
	URL         string            `mapstructure:"url"          yaml:"url"`
	Method      string            `mapstructure:"method"       yaml:"method,omitempty"`
	Headers     map[string]string `mapstructure:"headers"      yaml:"headers,omitempty"`
	BearerEnv   string            `mapstructure:"bearer_env"   yaml:"bearer_env,omitempty"`
	BearerToken string            `mapstructure:"bearer_token" yaml:"bearer_token,omitempty"`
	// VerifyTLS is the LEGACY opt-in-to-security flag (see
	// SplunkHECSinkConfig.VerifyTLS for the history). Retained
	// for backward compatibility; operators who want the old insecure
	// behaviour must set insecure_skip_verify=true.
	VerifyTLS bool `mapstructure:"verify_tls"   yaml:"verify_tls,omitempty"`
	// InsecureSkipVerify is the fix. When true, the sink does
	// NOT validate the HTTPS endpoint's certificate. Defaults to false
	// so audit payloads (and any bearer token) cannot be silently
	// captured by an on-path attacker.
	InsecureSkipVerify bool `mapstructure:"insecure_skip_verify" yaml:"insecure_skip_verify,omitempty"`
}

// ResolvedBearer returns the env-resolved bearer token, falling back to
// the inline BearerToken field.
func (c *HTTPJSONLSinkConfig) ResolvedBearer() string {
	if c == nil {
		return ""
	}
	if c.BearerEnv != "" {
		if v := os.Getenv(c.BearerEnv); v != "" {
			return v
		}
	}
	return c.BearerToken
}

func (c *HTTPJSONLSinkConfig) Validate(sinkName string) error {
	if c.URL == "" {
		return fmt.Errorf("audit sink %q: http_jsonl.url is required", sinkName)
	}
	low := strings.ToLower(c.URL)
	if !strings.HasPrefix(low, "http://") && !strings.HasPrefix(low, "https://") {
		return fmt.Errorf("audit sink %q: http_jsonl.url must be http(s):// (got %q)",
			sinkName, c.URL)
	}
	if c.Method != "" {
		switch strings.ToUpper(c.Method) {
		case "POST", "PUT", "PATCH":
		default:
			return fmt.Errorf("audit sink %q: http_jsonl.method must be POST/PUT/PATCH (got %q)",
				sinkName, c.Method)
		}
	}
	return nil
}

// ---------------------------------------------------------------------------
// Per-connector observability routing (D5b) — Go honor-half.
//
// This is the runtime counterpart of the Python config + resolver surface in
// cli/defenseclaw/config.py (ObservabilityConfig / PerConnectorObservability /
// effective_audit_sinks / effective_webhooks). The Python side persists and
// round-trips the `observability.connectors[<name>]` block and resolves it for
// Python consumers; honoring the routing at event-emit time is the Go change
// implemented here and consumed by internal/audit/sinks (audit sinks) and
// internal/gateway (webhooks).
// ---------------------------------------------------------------------------

// PerConnectorObservability is one connector's observability override. A
// connector's events route to ITS configured sinks/webhooks, falling back to
// the GLOBAL list (top-level audit_sinks: / webhooks:) when a dimension is
// unset. Each dimension is independently tri-state, mirroring the Python
// None / present-list / empty-list semantics with a Go pointer-to-slice:
//
//   - nil pointer    — key absent; INHERIT the global list. This is the
//     default and the safety fallback: a connector with no
//     per-connector config still emits to the global sinks
//     (no silent drop).
//   - present slice  — OVERRIDE: route this connector's events to exactly
//     these entries. A non-nil pointer to an EMPTY slice
//     ([] in YAML) suppresses the global list for that
//     connector.
//
// AuditSinks reuses the typed AuditSink (the Go gateway owns the sink schema,
// unlike the Python side which keeps raw mappings); Webhooks reuses
// WebhookConfig, parity with the top-level webhooks: list.
type PerConnectorObservability struct {
	AuditSinks *[]AuditSink     `mapstructure:"audit_sinks" yaml:"audit_sinks,omitempty"`
	Webhooks   *[]WebhookConfig `mapstructure:"webhooks"     yaml:"webhooks,omitempty"`
}

// ObservabilityConfig carries the per-connector observability routing map
// (D5b). Connectors maps a connector name to its PerConnectorObservability
// override. An empty/absent map preserves the legacy global-only behavior.
// Resolution goes through EffectiveAuditSinks / EffectiveWebhooks (which take
// the global list and fall back to it), never by reading the map directly —
// mirroring AssetPolicyConfig and guardrail.connectors. Mirrors
// ObservabilityConfig in cli/defenseclaw/config.py.
type ObservabilityConfig struct {
	Connectors map[string]PerConnectorObservability `mapstructure:"connectors" yaml:"connectors,omitempty"`
}

// connectorOverride returns the override block for connector if configured.
// Mirrors GuardrailConfig.connectorOverride / AssetPolicyConfig.connectorOverride:
// an empty connector / nil receiver / empty map yields (zero, false); lookup is
// connector-name-insensitive (exact key first, then normalizeConnectorKey).
func (o *ObservabilityConfig) connectorOverride(connector string) (PerConnectorObservability, bool) {
	if o == nil || connector == "" || len(o.Connectors) == 0 {
		return PerConnectorObservability{}, false
	}
	if pc, ok := o.Connectors[connector]; ok {
		return pc, true
	}
	want := normalizeConnectorKey(connector)
	if want == "" {
		return PerConnectorObservability{}, false
	}
	for name, pc := range o.Connectors {
		if normalizeConnectorKey(name) == want {
			return pc, true
		}
	}
	return PerConnectorObservability{}, false
}

// EffectiveAuditSinks resolves the audit sinks a connector's events route to:
// the per-connector override (when the audit_sinks dimension is set, including
// an explicit empty list = suppress) wins; otherwise inherit global. global is
// the top-level cfg.AuditSinks. The returned slice is always a fresh copy so
// callers cannot mutate config state. Mirrors
// ObservabilityConfig.effective_audit_sinks in config.py.
func (o *ObservabilityConfig) EffectiveAuditSinks(connector string, global []AuditSink) []AuditSink {
	if pc, ok := o.connectorOverride(connector); ok && pc.AuditSinks != nil {
		return append([]AuditSink(nil), (*pc.AuditSinks)...)
	}
	return append([]AuditSink(nil), global...)
}

// EffectiveWebhooks resolves the webhooks a connector's events route to: the
// per-connector override (when the webhooks dimension is set, including an
// explicit empty list = suppress) wins; otherwise inherit global. global is
// the top-level cfg.Webhooks. Mirrors
// ObservabilityConfig.effective_webhooks in config.py.
func (o *ObservabilityConfig) EffectiveWebhooks(connector string, global []WebhookConfig) []WebhookConfig {
	if pc, ok := o.connectorOverride(connector); ok && pc.Webhooks != nil {
		return append([]WebhookConfig(nil), (*pc.Webhooks)...)
	}
	return append([]WebhookConfig(nil), global...)
}

// HasConnectorAuditSinksOverride reports whether connector has an explicit
// per-connector audit_sinks dimension set (a present list, possibly empty).
// A true result with zero effective sinks means "suppress global for this
// connector"; the build/registration wiring uses this to distinguish
// suppression from inheritance. Connector-name-insensitive.
func (o *ObservabilityConfig) HasConnectorAuditSinksOverride(connector string) bool {
	pc, ok := o.connectorOverride(connector)
	return ok && pc.AuditSinks != nil
}

// HasConnectorWebhooksOverride is the webhooks counterpart of
// HasConnectorAuditSinksOverride.
func (o *ObservabilityConfig) HasConnectorWebhooksOverride(connector string) bool {
	pc, ok := o.connectorOverride(connector)
	return ok && pc.Webhooks != nil
}

// ConnectorNames returns the configured connector keys in deterministic
// (sorted) order. Used by the build/registration wiring to fan out over
// per-connector overrides without depending on Go map iteration order.
func (o *ObservabilityConfig) ConnectorNames() []string {
	if o == nil || len(o.Connectors) == 0 {
		return nil
	}
	names := make([]string, 0, len(o.Connectors))
	for name := range o.Connectors {
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}

// Validate rejects empty / alias-duplicate connector names. Value-only check
// mirroring AssetPolicyConfig.Validate / ObservabilityConfig.validate in
// config.py — it never touches the connector registry. Returns the first
// violation.
func (o *ObservabilityConfig) Validate() error {
	if o == nil || len(o.Connectors) == 0 {
		return nil
	}
	seen := make(map[string]string, len(o.Connectors))
	for _, name := range o.ConnectorNames() {
		if strings.TrimSpace(name) == "" {
			return fmt.Errorf("observability.connectors: empty connector name is not allowed")
		}
		norm := normalizeConnectorKey(name)
		if prev, ok := seen[norm]; ok {
			return fmt.Errorf("observability.connectors: %q and %q refer to the same "+
				"connector %q; keep only one", prev, name, norm)
		}
		seen[norm] = name
	}
	return nil
}

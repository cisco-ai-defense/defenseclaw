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
	VerifyTLS  bool   `mapstructure:"verify_tls"  yaml:"verify_tls,omitempty"`

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
	VerifyTLS   bool              `mapstructure:"verify_tls"   yaml:"verify_tls,omitempty"`
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

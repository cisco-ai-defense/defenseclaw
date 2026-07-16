// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// SPDX-License-Identifier: Apache-2.0

package config

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/observability"
	"gopkg.in/yaml.v3"
)

// Parser-visible hard limits from the v8 configuration contract. Raw YAML
// limits belong here so every parser and the typed compiler share one ceiling.
const (
	ObservabilityV8MaxSourceBytes = 4 * 1024 * 1024
	ObservabilityV8MaxYAMLNodes   = 65_536
	ObservabilityV8MaxYAMLDepth   = 32
	// ObservabilityV8MaxSourceDestinations is the operator-authored ceiling.
	// ObservabilityV8MaxDestinations also accounts for the service-owned
	// managed-enterprise destination that can be added after source compilation;
	// the generated local SQLite destination remains the additional +1 used by
	// runtime health bounds.
	ObservabilityV8MaxSourceDestinations   = 64
	ObservabilityV8MaxDestinations         = ObservabilityV8MaxSourceDestinations + 1
	ObservabilityV8MaxRoutesPerDestination = 256
	ObservabilityV8MaxRoutesTotal          = 4_096
	ObservabilityV8MaxRedactionProfiles    = 128
	ObservabilityV8MaxMappingEntries       = 1_024
	ObservabilityV8MaxResourceAttributes   = 64
	ObservabilityV8MaxResourceKeyBytes     = 128
	ObservabilityV8MaxResourceValueBytes   = 1_024
	ObservabilityV8MaxResourceTotalBytes   = 16 * 1_024
	// ObservabilityV8MaxRetentionDays is the largest whole-day retention
	// period that can be represented as a time.Duration without overflow.
	ObservabilityV8MaxRetentionDays = int((1<<63 - 1) / int64(24*time.Hour))
)

const (
	ObservabilityV8ConfigVersion        = 8
	ObservabilityV8BucketCatalogVersion = 1
)

// ObservabilityV8Source is the typed source form of the v8 observability block.
// A nil *ObservabilityV8Source and an empty value compile identically.
type ObservabilityV8Source struct {
	BucketCatalogVersion *int                                                       `json:"bucket_catalog_version,omitempty" mapstructure:"bucket_catalog_version" yaml:"bucket_catalog_version,omitempty"`
	Resource             ObservabilityV8ResourceSource                              `json:"resource,omitempty" mapstructure:"resource" yaml:"resource,omitempty"`
	TracePolicy          ObservabilityV8TracePolicySource                           `json:"trace_policy,omitempty" mapstructure:"trace_policy" yaml:"trace_policy,omitempty"`
	MetricPolicy         ObservabilityV8MetricPolicySource                          `json:"metric_policy,omitempty" mapstructure:"metric_policy" yaml:"metric_policy,omitempty"`
	Defaults             ObservabilityV8BucketPolicySource                          `json:"defaults,omitempty" mapstructure:"defaults" yaml:"defaults,omitempty"`
	Buckets              map[observability.Bucket]ObservabilityV8BucketPolicySource `json:"buckets,omitempty" mapstructure:"buckets" yaml:"buckets,omitempty"`
	RedactionProfiles    map[string]ObservabilityV8RedactionProfileSource           `json:"redaction_profiles,omitempty" mapstructure:"redaction_profiles" yaml:"redaction_profiles,omitempty"`
	Connectors           map[string]ObservabilityV8ConnectorSource                  `json:"connectors,omitempty" mapstructure:"connectors" yaml:"connectors,omitempty"`
	Local                ObservabilityV8LocalSource                                 `json:"local,omitempty" mapstructure:"local" yaml:"local,omitempty"`
	Destinations         []ObservabilityV8DestinationSource                         `json:"destinations,omitempty" mapstructure:"destinations" yaml:"destinations,omitempty"`
	localPathDefaulted   bool
	judgePathDefaulted   bool
}

type ObservabilityV8ResourceSource struct {
	Attributes map[string]string `json:"attributes,omitempty" mapstructure:"attributes" yaml:"attributes,omitempty"`
}

type ObservabilityV8TracePolicySource struct {
	Sampler              string                           `json:"sampler,omitempty" mapstructure:"sampler" yaml:"sampler,omitempty"`
	SamplerArg           string                           `json:"sampler_arg,omitempty" mapstructure:"sampler_arg" yaml:"sampler_arg,omitempty"`
	SemanticProfile      string                           `json:"semantic_profile,omitempty" mapstructure:"semantic_profile" yaml:"semantic_profile,omitempty"`
	CompatibilityAliases *bool                            `json:"compatibility_aliases,omitempty" mapstructure:"compatibility_aliases" yaml:"compatibility_aliases,omitempty"`
	Limits               ObservabilityV8TraceLimitsSource `json:"limits,omitempty" mapstructure:"limits" yaml:"limits,omitempty"`
}

type ObservabilityV8TraceLimitsSource struct {
	MaxAttributesPerSpan   int `json:"max_attributes_per_span,omitempty" mapstructure:"max_attributes_per_span" yaml:"max_attributes_per_span,omitempty"`
	MaxEventsPerSpan       int `json:"max_events_per_span,omitempty" mapstructure:"max_events_per_span" yaml:"max_events_per_span,omitempty"`
	MaxLinksPerSpan        int `json:"max_links_per_span,omitempty" mapstructure:"max_links_per_span" yaml:"max_links_per_span,omitempty"`
	MaxAttributesPerEvent  int `json:"max_attributes_per_event,omitempty" mapstructure:"max_attributes_per_event" yaml:"max_attributes_per_event,omitempty"`
	MaxAttributeValueBytes int `json:"max_attribute_value_bytes,omitempty" mapstructure:"max_attribute_value_bytes" yaml:"max_attribute_value_bytes,omitempty"`
	MaxProjectedSpanBytes  int `json:"max_projected_span_bytes,omitempty" mapstructure:"max_projected_span_bytes" yaml:"max_projected_span_bytes,omitempty"`
	MaxStacktraceBytes     int `json:"max_stacktrace_bytes,omitempty" mapstructure:"max_stacktrace_bytes" yaml:"max_stacktrace_bytes,omitempty"`
	MaxMessageItems        int `json:"max_message_items,omitempty" mapstructure:"max_message_items" yaml:"max_message_items,omitempty"`
}

type ObservabilityV8MetricPolicySource struct {
	ExportIntervalSeconds int    `json:"export_interval_seconds,omitempty" mapstructure:"export_interval_seconds" yaml:"export_interval_seconds,omitempty"`
	Temporality           string `json:"temporality,omitempty" mapstructure:"temporality" yaml:"temporality,omitempty"`
}

type ObservabilityV8BucketPolicySource struct {
	Collect          ObservabilityV8CollectSource `json:"collect,omitempty" mapstructure:"collect" yaml:"collect,omitempty"`
	RedactionProfile string                       `json:"redaction_profile,omitempty" mapstructure:"redaction_profile" yaml:"redaction_profile,omitempty"`
}

type ObservabilityV8CollectSource struct {
	Logs    *bool `json:"logs,omitempty" mapstructure:"logs" yaml:"logs,omitempty"`
	Traces  *bool `json:"traces,omitempty" mapstructure:"traces" yaml:"traces,omitempty"`
	Metrics *bool `json:"metrics,omitempty" mapstructure:"metrics" yaml:"metrics,omitempty"`
}

type ObservabilityV8DetectorGroup string

const (
	ObservabilityV8DetectorPII         ObservabilityV8DetectorGroup = "pii"
	ObservabilityV8DetectorCredentials ObservabilityV8DetectorGroup = "credentials"
	ObservabilityV8DetectorSecrets     ObservabilityV8DetectorGroup = "secrets"
)

type ObservabilityV8FieldClass string

const (
	ObservabilityV8FieldMetadata   ObservabilityV8FieldClass = "metadata"
	ObservabilityV8FieldIdentifier ObservabilityV8FieldClass = "identifier"
	ObservabilityV8FieldContent    ObservabilityV8FieldClass = "content"
	ObservabilityV8FieldReason     ObservabilityV8FieldClass = "reason"
	ObservabilityV8FieldEvidence   ObservabilityV8FieldClass = "evidence"
	ObservabilityV8FieldError      ObservabilityV8FieldClass = "error"
	ObservabilityV8FieldPath       ObservabilityV8FieldClass = "path"
	ObservabilityV8FieldCredential ObservabilityV8FieldClass = "credential"
)

type ObservabilityV8FieldMode string

const (
	ObservabilityV8ModePreserve ObservabilityV8FieldMode = "preserve"
	ObservabilityV8ModeDetect   ObservabilityV8FieldMode = "detect"
	ObservabilityV8ModeWhole    ObservabilityV8FieldMode = "whole"
	ObservabilityV8ModeHash     ObservabilityV8FieldMode = "hash"
	ObservabilityV8ModeRemove   ObservabilityV8FieldMode = "remove"
)

type ObservabilityV8RedactionProfileSource struct {
	Extends      string                                                 `json:"extends" mapstructure:"extends" yaml:"extends"`
	Detectors    []ObservabilityV8DetectorGroup                         `json:"detectors,omitempty" mapstructure:"detectors" yaml:"detectors,omitempty"`
	FieldClasses map[ObservabilityV8FieldClass]ObservabilityV8FieldMode `json:"field_classes,omitempty" mapstructure:"field_classes" yaml:"field_classes,omitempty"`
}

type ObservabilityV8LocalSource struct {
	Path            string `json:"path,omitempty" mapstructure:"path" yaml:"path,omitempty"`
	JudgeBodiesPath string `json:"judge_bodies_path,omitempty" mapstructure:"judge_bodies_path" yaml:"judge_bodies_path,omitempty"`
	RetentionDays   *int   `json:"retention_days,omitempty" mapstructure:"retention_days" yaml:"retention_days,omitempty"`
}

// ObservabilityV8ConnectorSource preserves the v7 notification-only webhook
// override. It is not a telemetry destination and never enters signal routes.
type ObservabilityV8ConnectorSource struct {
	Webhooks *[]WebhookConfig `json:"webhooks,omitempty" mapstructure:"webhooks" yaml:"webhooks,omitempty"`
}

type ObservabilityV8DestinationKind string

const (
	ObservabilityV8DestinationJSONL      ObservabilityV8DestinationKind = "jsonl"
	ObservabilityV8DestinationConsole    ObservabilityV8DestinationKind = "console"
	ObservabilityV8DestinationPrometheus ObservabilityV8DestinationKind = "prometheus"
	ObservabilityV8DestinationSplunkHEC  ObservabilityV8DestinationKind = "splunk_hec"
	ObservabilityV8DestinationHTTPJSONL  ObservabilityV8DestinationKind = "http_jsonl"
	ObservabilityV8DestinationOTLP       ObservabilityV8DestinationKind = "otlp"

	// ObservabilityV8DestinationLocalSQLite is effective-plan-only.
	ObservabilityV8DestinationLocalSQLite ObservabilityV8DestinationKind = "sqlite"
)

type ObservabilityV8DestinationSource struct {
	Name    string                         `json:"name" mapstructure:"name" yaml:"name"`
	Kind    ObservabilityV8DestinationKind `json:"kind" mapstructure:"kind" yaml:"kind"`
	Enabled *bool                          `json:"enabled,omitempty" mapstructure:"enabled" yaml:"enabled,omitempty"`
	Preset  string                         `json:"preset,omitempty" mapstructure:"preset" yaml:"preset,omitempty"`

	Send   *ObservabilityV8SendSource   `json:"send,omitempty" mapstructure:"send" yaml:"send,omitempty"`
	Routes []ObservabilityV8RouteSource `json:"routes,omitempty" mapstructure:"routes" yaml:"routes,omitempty"`

	Path     string                        `json:"path,omitempty" mapstructure:"path" yaml:"path,omitempty"`
	Rotation ObservabilityV8RotationSource `json:"rotation,omitempty" mapstructure:"rotation" yaml:"rotation,omitempty"`
	Listen   string                        `json:"listen,omitempty" mapstructure:"listen" yaml:"listen,omitempty"`

	Endpoint            string                                                       `json:"endpoint,omitempty" mapstructure:"endpoint" yaml:"endpoint,omitempty"`
	Protocol            string                                                       `json:"protocol,omitempty" mapstructure:"protocol" yaml:"protocol,omitempty"`
	Method              string                                                       `json:"method,omitempty" mapstructure:"method" yaml:"method,omitempty"`
	Headers             map[string]ObservabilityV8HeaderValue                        `json:"headers,omitempty" mapstructure:"headers" yaml:"headers,omitempty"`
	TokenEnv            string                                                       `json:"token_env,omitempty" mapstructure:"token_env" yaml:"token_env,omitempty"`
	BearerEnv           string                                                       `json:"bearer_env,omitempty" mapstructure:"bearer_env" yaml:"bearer_env,omitempty"`
	Index               string                                                       `json:"index,omitempty" mapstructure:"index" yaml:"index,omitempty"`
	Source              string                                                       `json:"source,omitempty" mapstructure:"source" yaml:"source,omitempty"`
	SourceType          string                                                       `json:"sourcetype,omitempty" mapstructure:"sourcetype" yaml:"sourcetype,omitempty"`
	SourceTypeOverrides map[observability.ProducerKey]string                         `json:"sourcetype_overrides,omitempty" mapstructure:"sourcetype_overrides" yaml:"sourcetype_overrides,omitempty"`
	LoggerName          string                                                       `json:"logger_name,omitempty" mapstructure:"logger_name" yaml:"logger_name,omitempty"`
	TimeoutMS           int                                                          `json:"timeout_ms,omitempty" mapstructure:"timeout_ms" yaml:"timeout_ms,omitempty"`
	TLS                 ObservabilityV8TLSSource                                     `json:"tls,omitempty" mapstructure:"tls" yaml:"tls,omitempty"`
	Batch               ObservabilityV8BatchSource                                   `json:"batch,omitempty" mapstructure:"batch" yaml:"batch,omitempty"`
	NetworkSafety       ObservabilityV8NetworkSafetySource                           `json:"network_safety,omitempty" mapstructure:"network_safety" yaml:"network_safety,omitempty"`
	SignalOverrides     map[observability.Signal]ObservabilityV8SignalOverrideSource `json:"signal_overrides,omitempty" mapstructure:"signal_overrides" yaml:"signal_overrides,omitempty"`
}

// ObservabilityV8SecretRef is source-declared secret identity only. Resolution
// is deliberately outside the pure compiler.
type ObservabilityV8SecretRef struct {
	Env string `json:"env" mapstructure:"env" yaml:"env"`
}

// ObservabilityV8HeaderValue is a scalar-or-secret-reference source union.
// Exactly one of Static and Secret may be populated.
type ObservabilityV8HeaderValue struct {
	Static *string                   `json:"static,omitempty" mapstructure:"-" yaml:"-"`
	Secret *ObservabilityV8SecretRef `json:"secret,omitempty" mapstructure:"-" yaml:"-"`
}

func (value ObservabilityV8HeaderValue) MarshalJSON() ([]byte, error) {
	switch {
	case value.Static != nil && value.Secret == nil:
		return json.Marshal(*value.Static)
	case value.Static == nil && value.Secret != nil:
		return json.Marshal(value.Secret)
	default:
		return nil, fmt.Errorf("header value must contain exactly one static value or secret reference")
	}
}

func (value *ObservabilityV8HeaderValue) UnmarshalJSON(data []byte) error {
	if value == nil {
		return fmt.Errorf("header value target is nil")
	}
	if bytes.Equal(bytes.TrimSpace(data), []byte("null")) {
		return fmt.Errorf("header value must be a string or an object containing only nonempty env")
	}
	var static string
	if err := json.Unmarshal(data, &static); err == nil {
		*value = ObservabilityV8StaticHeader(static)
		return nil
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	var secret ObservabilityV8SecretRef
	if err := decoder.Decode(&secret); err != nil || secret.Env == "" {
		return fmt.Errorf("header value must be a string or an object containing only nonempty env")
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return fmt.Errorf("header value must contain exactly one JSON value")
	}
	*value = ObservabilityV8EnvironmentHeader(secret.Env)
	return nil
}

func (value *ObservabilityV8HeaderValue) UnmarshalYAML(node *yaml.Node) error {
	if value == nil || node == nil {
		return fmt.Errorf("header value target is nil")
	}
	if node.Kind == yaml.ScalarNode && node.ShortTag() == "!!str" {
		*value = ObservabilityV8StaticHeader(node.Value)
		return nil
	}
	if node.Kind != yaml.MappingNode || len(node.Content) != 2 ||
		node.Content[0].Kind != yaml.ScalarNode || node.Content[0].Value != "env" ||
		node.Content[1].Kind != yaml.ScalarNode || node.Content[1].ShortTag() != "!!str" ||
		node.Content[1].Value == "" {
		return fmt.Errorf("header value must be a string or an object containing only nonempty env")
	}
	*value = ObservabilityV8EnvironmentHeader(node.Content[1].Value)
	return nil
}

func ObservabilityV8StaticHeader(value string) ObservabilityV8HeaderValue {
	return ObservabilityV8HeaderValue{Static: &value}
}

func ObservabilityV8EnvironmentHeader(name string) ObservabilityV8HeaderValue {
	return ObservabilityV8HeaderValue{Secret: &ObservabilityV8SecretRef{Env: name}}
}

type ObservabilityV8RotationSource struct {
	MaxSizeMB  int   `json:"max_size_mb,omitempty" mapstructure:"max_size_mb" yaml:"max_size_mb,omitempty"`
	MaxBackups *int  `json:"max_backups,omitempty" mapstructure:"max_backups" yaml:"max_backups,omitempty"`
	MaxAgeDays *int  `json:"max_age_days,omitempty" mapstructure:"max_age_days" yaml:"max_age_days,omitempty"`
	Compress   *bool `json:"compress,omitempty" mapstructure:"compress" yaml:"compress,omitempty"`
}

type ObservabilityV8TLSSource struct {
	Insecure           bool   `json:"insecure,omitempty" mapstructure:"insecure" yaml:"insecure,omitempty"`
	InsecureSkipVerify bool   `json:"insecure_skip_verify,omitempty" mapstructure:"insecure_skip_verify" yaml:"insecure_skip_verify,omitempty"`
	CACert             string `json:"ca_cert,omitempty" mapstructure:"ca_cert" yaml:"ca_cert,omitempty"`
}

type ObservabilityV8BatchSource struct {
	MaxQueueSize        int `json:"max_queue_size,omitempty" mapstructure:"max_queue_size" yaml:"max_queue_size,omitempty"`
	MaxQueueBytes       int `json:"max_queue_bytes,omitempty" mapstructure:"max_queue_bytes" yaml:"max_queue_bytes,omitempty"`
	MaxExportBatchSize  int `json:"max_export_batch_size,omitempty" mapstructure:"max_export_batch_size" yaml:"max_export_batch_size,omitempty"`
	MaxExportBatchBytes int `json:"max_export_batch_bytes,omitempty" mapstructure:"max_export_batch_bytes" yaml:"max_export_batch_bytes,omitempty"`
	ScheduledDelayMS    int `json:"scheduled_delay_ms,omitempty" mapstructure:"scheduled_delay_ms" yaml:"scheduled_delay_ms,omitempty"`
}

type ObservabilityV8NetworkSafetySource struct {
	AllowPrivateNetworks bool `json:"allow_private_networks,omitempty" mapstructure:"allow_private_networks" yaml:"allow_private_networks,omitempty"`
	AllowCGNAT           bool `json:"allow_cgnat,omitempty" mapstructure:"allow_cgnat" yaml:"allow_cgnat,omitempty"`
}

type ObservabilityV8SignalOverrideSource struct {
	Endpoint string `json:"endpoint,omitempty" mapstructure:"endpoint" yaml:"endpoint,omitempty"`
	Path     string `json:"path,omitempty" mapstructure:"path" yaml:"path,omitempty"`
}

type ObservabilityV8SendSource struct {
	Signals          []observability.Signal `json:"signals" mapstructure:"signals" yaml:"signals"`
	Buckets          []observability.Bucket `json:"buckets" mapstructure:"buckets" yaml:"buckets"`
	RedactionProfile string                 `json:"redaction_profile,omitempty" mapstructure:"redaction_profile" yaml:"redaction_profile,omitempty"`
}

type ObservabilityV8RouteAction string

const (
	ObservabilityV8RouteSend ObservabilityV8RouteAction = "send"
	ObservabilityV8RouteDrop ObservabilityV8RouteAction = "drop"
)

type ObservabilityV8RouteSource struct {
	Name             string                         `json:"name" mapstructure:"name" yaml:"name"`
	Signals          []observability.Signal         `json:"signals" mapstructure:"signals" yaml:"signals"`
	Selector         *ObservabilityV8SelectorSource `json:"selector" mapstructure:"selector" yaml:"selector"`
	Action           ObservabilityV8RouteAction     `json:"action,omitempty" mapstructure:"action" yaml:"action,omitempty"`
	RedactionProfile string                         `json:"redaction_profile,omitempty" mapstructure:"redaction_profile" yaml:"redaction_profile,omitempty"`
}

type ObservabilityV8SelectorSource struct {
	Buckets     []observability.Bucket      `json:"buckets,omitempty" mapstructure:"buckets" yaml:"buckets,omitempty"`
	Sources     []observability.Source      `json:"sources,omitempty" mapstructure:"sources" yaml:"sources,omitempty"`
	Connectors  []string                    `json:"connectors,omitempty" mapstructure:"connectors" yaml:"connectors,omitempty"`
	Actions     []observability.ProducerKey `json:"actions,omitempty" mapstructure:"actions" yaml:"actions,omitempty"`
	EventNames  []observability.EventName   `json:"event_names,omitempty" mapstructure:"event_names" yaml:"event_names,omitempty"`
	MinSeverity observability.Severity      `json:"min_severity,omitempty" mapstructure:"min_severity" yaml:"min_severity,omitempty"`
}

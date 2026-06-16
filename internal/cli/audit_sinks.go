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
	"context"
	"errors"
	"fmt"

	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/sdk/resource"
	semconv "go.opentelemetry.io/otel/semconv/v1.26.0"

	"github.com/defenseclaw/defenseclaw/internal/audit/sinks"
	"github.com/defenseclaw/defenseclaw/internal/config"
)

// buildAuditSinks translates the operator-supplied AuditSink list into a
// concrete sinks.Manager. Sinks that fail to construct are skipped with
// a wrapped error so the operator sees the misconfig but a single bad
// entry never blocks the rest from starting.
//
// This function deliberately lives in internal/cli (not internal/audit
// or internal/audit/sinks) because it is the *composition* layer: it
// knows about config types and sink-package types, and bridges them.
//
// obs carries the per-connector observability routing overrides (D5b): for
// each connector whose audit_sinks dimension is set, its sinks are built and
// registered against the Manager so that connector's events route to them
// (RegisterForConnector). An override that resolves to zero sinks (explicit
// empty list) is still recorded (MarkConnectorOverride) so the connector's
// events are SUPPRESSED rather than inheriting the global list. A connector
// with no override is left untouched and inherits the global sinks — the
// safety default that prevents a silent drop.
func buildAuditSinks(declared []config.AuditSink, obs config.ObservabilityConfig, appVersion string) (*sinks.Manager, error) {
	mgr := sinks.NewManager()
	res := defaultSinkResource(appVersion)

	var errs []error
	buildInto := func(decls []config.AuditSink, connector string, register func(sinks.Sink)) {
		for _, decl := range decls {
			if !decl.Enabled {
				continue
			}
			s, err := buildOneSink(context.Background(), decl, res)
			if err != nil {
				label := fmt.Sprintf("audit_sinks[%q] (%s)", decl.Name, decl.Kind)
				if connector != "" {
					label = fmt.Sprintf("observability.connectors[%q].%s", connector, label)
				}
				errs = append(errs, fmt.Errorf("%s: %w", label, err))
				continue
			}
			if s != nil {
				register(s)
			}
		}
	}

	buildInto(declared, "", mgr.Register)

	// Per-connector overrides (D5b). ConnectorNames yields a deterministic
	// order; each connector with a non-nil audit_sinks dimension overrides
	// the global routing for its own events.
	for _, name := range obs.ConnectorNames() {
		if !obs.HasConnectorAuditSinksOverride(name) {
			continue // audit_sinks unset → inherit global (no marking).
		}
		// EffectiveAuditSinks(name, nil) returns exactly the connector's
		// override list (global is irrelevant here because the override is
		// present). An empty result is the suppress case.
		connSinks := obs.EffectiveAuditSinks(name, nil)
		// Record the override up front so the empty-list suppress case takes
		// effect even when no sink is built (e.g. all disabled / all errored).
		mgr.MarkConnectorOverride(name)
		conn := name
		buildInto(connSinks, conn, func(s sinks.Sink) { mgr.RegisterForConnector(conn, s) })
	}

	if len(errs) > 0 {
		return mgr, errors.Join(errs...)
	}
	return mgr, nil
}

// buildOneSink constructs a single Sink from its config.AuditSink decl.
// Returning (nil, nil) is treated as "skipped" by the caller (e.g. when
// a sink kind is recognized but disabled at runtime).
func buildOneSink(ctx context.Context, decl config.AuditSink, res *resource.Resource) (sinks.Sink, error) {
	filter := sinks.SinkFilter{
		MinSeverity: decl.MinSeverity,
		Actions:     decl.Actions,
	}

	switch decl.Kind {
	case config.SinkKindSplunkHEC:
		c := decl.SplunkHEC
		if c == nil {
			return nil, fmt.Errorf("missing splunk_hec block")
		}
		token := c.ResolvedToken()
		if token == "" {
			return nil, fmt.Errorf("splunk_hec token unresolved (set token_env=%q)", c.TokenEnv)
		}
		return sinks.NewSplunkHECSink(sinks.SplunkHECConfig{
			Name:                decl.Name,
			Endpoint:            c.Endpoint,
			Token:               token,
			Index:               c.Index,
			Source:              c.Source,
			SourceType:          c.SourceType,
			VerifyTLS:           c.VerifyTLS,
			InsecureSkipVerify:  c.InsecureSkipVerify,
			BatchSize:           decl.BatchSize,
			FlushIntervalS:      decl.FlushIntervalS,
			TimeoutS:            decl.TimeoutS,
			Filter:              filter,
			SourceTypeOverrides: c.SourceTypeOverrides,
		})

	case config.SinkKindHTTPJSONL:
		c := decl.HTTPJSONL
		if c == nil {
			return nil, fmt.Errorf("missing http_jsonl block")
		}
		return sinks.NewHTTPJSONLSink(sinks.HTTPJSONLConfig{
			Name:               decl.Name,
			URL:                c.URL,
			Method:             c.Method,
			Headers:            c.Headers,
			BearerToken:        c.ResolvedBearer(),
			VerifyTLS:          c.VerifyTLS,
			InsecureSkipVerify: c.InsecureSkipVerify,
			BatchSize:          decl.BatchSize,
			FlushIntervalS:     decl.FlushIntervalS,
			TimeoutS:           decl.TimeoutS,
			Filter:             filter,
		})

	case config.SinkKindOTLPLogs:
		c := decl.OTLPLogs
		if c == nil {
			return nil, fmt.Errorf("missing otlp_logs block")
		}
		// expandHeaders is intentionally identity here — env-var
		// substitution happens at config load time when the operator
		// references ${VAR} in the headers block (handled by the
		// sink itself in a future commit).
		return sinks.NewOTLPLogsSink(ctx, sinks.OTLPLogsConfig{
			Name:        decl.Name,
			Endpoint:    c.Endpoint,
			Protocol:    c.Protocol,
			URLPath:     c.URLPath,
			Headers:     c.Headers,
			Insecure:    c.Insecure,
			CACertPath:  c.CACertPath,
			BatchSizeMx: decl.BatchSize,
			IntervalMs:  decl.FlushIntervalS * 1000,
			TimeoutS:    decl.TimeoutS,
			Filter:      filter,
			LoggerName:  c.LoggerName,
			Resource:    res,
		})

	default:
		return nil, fmt.Errorf("unknown sink kind %q", decl.Kind)
	}
}

// defaultSinkResource builds the OTel resource attached to every audit
// log record. We intentionally tag service.name=defenseclaw-audit so
// receivers can route audit events on a stable identifier independent
// of the global telemetry resource.
func defaultSinkResource(appVersion string) *resource.Resource {
	if appVersion == "" {
		appVersion = "dev"
	}
	r, err := resource.Merge(resource.Default(), resource.NewSchemaless(
		semconv.ServiceName("defenseclaw-audit"),
		semconv.ServiceVersion(appVersion),
		attribute.String("defenseclaw.component", "audit-sink"),
	))
	if err != nil {
		// Resource.Merge only errors when schema URLs disagree, which we
		// do not set. Falling back to the default keeps the audit
		// pipeline alive even if a future SDK upgrade tightens this.
		return resource.Default()
	}
	return r
}

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
func buildAuditSinks(declared []config.AuditSink, appVersion string) (*sinks.Manager, error) {
	mgr := sinks.NewManager()
	res := defaultSinkResource(appVersion)

	var errs []error
	for _, decl := range declared {
		if !decl.Enabled {
			continue
		}
		s, err := buildOneSink(context.Background(), decl, res)
		if err != nil {
			errs = append(errs, fmt.Errorf("audit_sinks[%q] (%s): %w", decl.Name, decl.Kind, err))
			continue
		}
		if s != nil {
			mgr.Register(s)
		}
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
			Name:           decl.Name,
			Endpoint:       c.Endpoint,
			Token:          token,
			Index:          c.Index,
			Source:         c.Source,
			SourceType:     c.SourceType,
			VerifyTLS:      c.VerifyTLS,
			BatchSize:      decl.BatchSize,
			FlushIntervalS: decl.FlushIntervalS,
			TimeoutS:       decl.TimeoutS,
			Filter:         filter,
		})

	case config.SinkKindHTTPJSONL:
		c := decl.HTTPJSONL
		if c == nil {
			return nil, fmt.Errorf("missing http_jsonl block")
		}
		return sinks.NewHTTPJSONLSink(sinks.HTTPJSONLConfig{
			Name:           decl.Name,
			URL:            c.URL,
			Method:         c.Method,
			Headers:        c.Headers,
			BearerToken:    c.ResolvedBearer(),
			VerifyTLS:      c.VerifyTLS,
			BatchSize:      decl.BatchSize,
			FlushIntervalS: decl.FlushIntervalS,
			TimeoutS:       decl.TimeoutS,
			Filter:         filter,
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

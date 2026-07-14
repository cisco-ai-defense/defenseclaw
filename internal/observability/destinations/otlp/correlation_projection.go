// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package otlp

import (
	"strings"
	"unicode/utf8"

	"github.com/defenseclaw/defenseclaw/internal/observability"
	commonpb "go.opentelemetry.io/proto/otlp/common/v1"
)

// correlationAttributeBindings is deliberately closed. Trace and span IDs are
// OTLP topology fields and are never copied into attributes. Request, turn,
// model, tool, session, agent, and provider-native identities remain governed
// by their generated connector/family contracts. These three occurrence-level
// identities are the only common log/trace overlay.
var correlationAttributeBindings = [...]struct {
	wire string
	otlp string
}{
	{"semantic_event_id", "defenseclaw.semantic_event.id"},
	{"logical_event_id", "defenseclaw.logical_event.id"},
	{"connector_instance_id", "defenseclaw.connector.instance.id"},
}

func isCanonicalCorrelationAttribute(key string) bool {
	for _, binding := range correlationAttributeBindings {
		if binding.otlp == key {
			return true
		}
	}
	return false
}

func canonicalCorrelationKeyValues(correlation map[string]any) ([]*commonpb.KeyValue, bool) {
	values := make([]*commonpb.KeyValue, 0, len(correlationAttributeBindings))
	for _, binding := range correlationAttributeBindings {
		raw, present := correlation[binding.wire]
		if !present {
			continue
		}
		value, ok := raw.(string)
		if !ok || value == "" || !utf8.ValidString(value) || len(value) > observability.MaxCorrelationIDBytes {
			return nil, false
		}
		values = append(values, stringAttribute(binding.otlp, strings.Clone(value)))
	}
	return values, true
}

func withCanonicalCorrelationAttributes(
	attributes map[string]any,
	correlation map[string]any,
) (map[string]any, bool) {
	result := make(map[string]any, len(attributes)+len(correlationAttributeBindings))
	for key, value := range attributes {
		result[key] = value
	}
	for _, binding := range correlationAttributeBindings {
		raw, present := correlation[binding.wire]
		if !present {
			continue
		}
		value, ok := raw.(string)
		if !ok || value == "" || !utf8.ValidString(value) || len(value) > observability.MaxCorrelationIDBytes {
			return nil, false
		}
		if existing, conflict := result[binding.otlp]; conflict {
			existingString, same := existing.(string)
			if !same || existingString != value {
				return nil, false
			}
			continue
		}
		result[binding.otlp] = strings.Clone(value)
	}
	return result, true
}

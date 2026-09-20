// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/observability"
)

func FuzzOTLPInboundNoRawBypass(f *testing.F) {
	f.Add([]byte(`{"resourceLogs":[]}`), uint8(0))
	f.Add([]byte(`{"resourceSpans":[]}`), uint8(1))
	f.Add([]byte(`{"resourceMetrics":[]}`), uint8(2))
	f.Add([]byte(`{"type":"text","content":"[REDACTED:email:sender]","dynamic":{"x":1}}`), uint8(3))

	f.Fuzz(func(t *testing.T, body []byte, selector uint8) {
		if len(body) > 1<<20 {
			t.Skip()
		}
		if selector%4 == 3 {
			value, err := inboundJSONAnyValue(body, 0)
			if err != nil {
				return
			}
			// The structured normalizer is the only open-member path. It must
			// either produce a generated typed arm or reject; it can never hand
			// an untyped map to a family builder.
			_, _ = inboundGenAIMessagePart(value)
			return
		}

		signals := []otelIngestSignal{otelSignalLogs, otelSignalTraces, otelSignalMetrics}
		signal := signals[int(selector)%len(signals)]
		decoded, err := decodeOTLPIngestBody(body, signal, "application/json")
		if err != nil {
			return
		}
		classifier := mustOTLPInboundClassifierV8(t)
		_, err = walkDecodedOTLPLeaves(decoded.message, signal, func(leaf otlpDecodedLeaf) error {
			classification, classifyErr := classifier.classify(leaf, "fixture-source")
			if classifyErr != nil || classification.identityState != otlpInboundIdentityMatched {
				return nil
			}
			if classification.match.ID() == "" || len(classification.match.Targets()) == 0 {
				t.Fatal("matched fuzz leaf escaped the generated target catalog")
			}
			for _, target := range classification.match.Targets() {
				if target.Signal() != observability.Signal(signal) || target.ID() == "" || target.Family() == "" {
					t.Fatalf("matched fuzz leaf reached invalid target %#v", target)
				}
			}
			return nil
		})
		if err != nil {
			return
		}
	})
}

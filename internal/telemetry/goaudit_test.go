// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package telemetry

import (
	"context"
	"errors"
	"testing"

	sdkmetric "go.opentelemetry.io/otel/sdk/metric"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"

	"github.com/defenseclaw/defenseclaw/internal/observability"
)

func TestV8FactoriesRejectTypedNilDependencies(t *testing.T) {
	t.Run("metric reader", func(t *testing.T) {
		var missing *sdkmetric.ManualReader
		provider, err := NewProviderV8Inactive(context.Background(),
			metricPlanForTest(t, observability.BucketAssetScan), 1,
			V8ProviderOptions{Version: "test", Environment: "test", MetricReaderFactories: []V8MetricReaderFactory{
				func(uint64, V8MetricReaderSpec) (sdkmetric.Reader, error) { return missing, nil },
			}},
		)
		var providerErr *V8ProviderError
		if provider != nil || !errors.As(err, &providerErr) || providerErr.Code() != V8ProviderErrorReaderInitialization {
			t.Fatalf("typed nil reader result = %v/%v", provider, err)
		}
	})
	t.Run("span processor", func(t *testing.T) {
		var missing *v8TrackingProcessor
		provider, err := NewProviderV8Inactive(context.Background(),
			v8PlanForTest(t, "always_on", "", nil), 1,
			V8ProviderOptions{Version: "test", Environment: "test", SpanProcessorFactory: func(uint64) (sdktrace.SpanProcessor, error) {
				return missing, nil
			}},
		)
		var providerErr *V8ProviderError
		if provider != nil || !errors.As(err, &providerErr) || providerErr.Code() != V8ProviderErrorProcessorInitialization {
			t.Fatalf("typed nil processor result = %v/%v", provider, err)
		}
	})
}

// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package otlp

import (
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/observability/delivery"
)

var goauditMetricHealthCalls chan struct{}

type goauditMetricHealthObserver struct{}

func (*goauditMetricHealthObserver) Observe(delivery.HealthTransition) {
	goauditMetricHealthCalls <- struct{}{}
}

func TestMetricTransitionSkipsTypedNilObserver(t *testing.T) {
	goauditMetricHealthCalls = make(chan struct{}, 2)
	var missing *goauditMetricHealthObserver
	exporter := &MetricExporter{}
	exporter.config.health = missing
	exporter.healthGeneration.Store(1)
	exporter.observeTransition(delivery.HealthHealthy, delivery.HealthReasonRecovered,
		delivery.HealthFailing, delivery.HealthReasonDeliveryFailed, "", time.Now())
	select {
	case <-goauditMetricHealthCalls:
		t.Fatal("nil observer was invoked")
	case <-time.After(300 * time.Millisecond):
	}
	exporter.config.health = &goauditMetricHealthObserver{}
	exporter.observeTransition(delivery.HealthHealthy, delivery.HealthReasonRecovered,
		delivery.HealthFailing, delivery.HealthReasonDeliveryFailed, "", time.Now())
	select {
	case <-goauditMetricHealthCalls:
	case <-time.After(time.Second):
		t.Fatal("live observer was not invoked")
	}
}

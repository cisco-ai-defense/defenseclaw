// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package sandbox

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	sdkmetric "go.opentelemetry.io/otel/sdk/metric"
	"go.opentelemetry.io/otel/sdk/metric/metricdata"

	"github.com/defenseclaw/defenseclaw/internal/gatewaylog"
	"github.com/defenseclaw/defenseclaw/internal/telemetry"
)

func TestOpenShell_ReloadPolicyExitRecordsMetric(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	dir := t.TempDir()
	script := filepath.Join(dir, "fake-openshell")
	if err := os.WriteFile(script, []byte("#!/bin/sh\nexit 7\n"), 0o700); err != nil {
		t.Fatal(err)
	}
	r := sdkmetric.NewManualReader()
	p, err := telemetry.NewProviderForTest(r)
	if err != nil {
		t.Fatal(err)
	}
	gw, err := gatewaylog.New(gatewaylog.Config{})
	if err != nil {
		t.Fatal(err)
	}
	o := New(script, dir)
	o.BindObservability(p, gw)
	if err := o.ReloadPolicy(); err == nil {
		t.Fatal("expected reload error")
	}
	var rm metricdata.ResourceMetrics
	if err := r.Collect(context.Background(), &rm); err != nil {
		t.Fatal(err)
	}
	found := false
	for _, sm := range rm.ScopeMetrics {
		for _, m := range sm.Metrics {
			if m.Name != "defenseclaw.openshell.exit" {
				continue
			}
			sum, ok := m.Data.(metricdata.Sum[int64])
			if !ok || sum.IsMonotonic != true {
				t.Fatalf("unexpected metric data: %#v", m.Data)
			}
			for _, dp := range sum.DataPoints {
				if dp.Value >= 1 {
					found = true
				}
			}
		}
	}
	if !found {
		t.Fatal("expected defenseclaw.openshell.exit counter increment")
	}
}

func TestOpenShell_StartNonZeroExitEmitted(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	dir := t.TempDir()
	script := filepath.Join(dir, "fake-openshell")
	if err := os.WriteFile(script, []byte("#!/bin/sh\nif [ \"$1\" = start ]; then echo fail >&2; exit 127; fi\nexit 0\n"), 0o700); err != nil {
		t.Fatal(err)
	}
	r := sdkmetric.NewManualReader()
	p, err := telemetry.NewProviderForTest(r)
	if err != nil {
		t.Fatal(err)
	}
	gw, err := gatewaylog.New(gatewaylog.Config{})
	if err != nil {
		t.Fatal(err)
	}
	o := New(script, dir)
	o.BindObservability(p, gw)
	if err := o.Start(filepath.Join(dir, "p.yaml")); err != nil {
		t.Fatal(err)
	}
	// OpenShell.Start launches a goroutine that calls cmd.Wait() and then
	// records the exit metric. There's no synchronisation hook, so we
	// poll the manual reader instead of sleeping a fixed window — the
	// previous 200ms wait was not enough on loaded test runners and
	// produced an intermittent flake (n=0). 5s is a safety net; a
	// healthy run completes within tens of milliseconds.
	deadline := time.Now().Add(5 * time.Second)
	var n int64
	for time.Now().Before(deadline) {
		var rm metricdata.ResourceMetrics
		if err := r.Collect(context.Background(), &rm); err != nil {
			t.Fatal(err)
		}
		n = 0
		for _, sm := range rm.ScopeMetrics {
			for _, m := range sm.Metrics {
				if m.Name != "defenseclaw.openshell.exit" {
					continue
				}
				sum := m.Data.(metricdata.Sum[int64])
				for _, dp := range sum.DataPoints {
					n += dp.Value
				}
			}
		}
		if n >= 1 {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("expected openshell exit metric, got %d", n)
}

// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package sandbox

import (
	"context"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"
)

type openShellMetricCall struct {
	command  string
	exitCode int
}

type openShellAlertCall struct {
	subsystem, severity, code string
	details                   map[string]any
}

type openShellActionCall struct {
	action, target, details string
}

type openShellObservabilityCapture struct {
	mu      sync.Mutex
	metrics []openShellMetricCall
	alerts  []openShellAlertCall
	actions []openShellActionCall
	wake    chan struct{}
}

func newOpenShellObservabilityCapture() *openShellObservabilityCapture {
	return &openShellObservabilityCapture{wake: make(chan struct{}, 8)}
}

func (capture *openShellObservabilityCapture) RecordOpenShellExitMetric(
	_ context.Context,
	command string,
	exitCode int,
) error {
	capture.mu.Lock()
	capture.metrics = append(capture.metrics, openShellMetricCall{command: command, exitCode: exitCode})
	capture.mu.Unlock()
	capture.wake <- struct{}{}
	return nil
}

func (capture *openShellObservabilityCapture) LogAlertCtx(
	_ context.Context,
	subsystem, severity, code string,
	details map[string]any,
) error {
	capture.mu.Lock()
	capture.alerts = append(capture.alerts, openShellAlertCall{
		subsystem: subsystem, severity: severity, code: code, details: details,
	})
	capture.mu.Unlock()
	capture.wake <- struct{}{}
	return nil
}

func (capture *openShellObservabilityCapture) LogActionCtx(
	_ context.Context,
	action, target, details string,
) error {
	capture.mu.Lock()
	capture.actions = append(capture.actions, openShellActionCall{
		action: action, target: target, details: details,
	})
	capture.mu.Unlock()
	capture.wake <- struct{}{}
	return nil
}

func (capture *openShellObservabilityCapture) snapshot() (
	[]openShellMetricCall,
	[]openShellAlertCall,
	[]openShellActionCall,
) {
	capture.mu.Lock()
	defer capture.mu.Unlock()
	return append([]openShellMetricCall(nil), capture.metrics...),
		append([]openShellAlertCall(nil), capture.alerts...),
		append([]openShellActionCall(nil), capture.actions...)
}

func TestOpenShellReloadPolicyExitUsesCanonicalObservability(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	dir := t.TempDir()
	script := filepath.Join(dir, "fake-openshell")
	if err := os.WriteFile(script, []byte("#!/bin/sh\necho 'token=user@example.com' >&2\nexit 7\n"), 0o700); err != nil {
		t.Fatal(err)
	}
	capture := newOpenShellObservabilityCapture()
	o := New(script, dir)
	o.BindObservabilityV8(capture)
	if err := o.ReloadPolicy(); err == nil {
		t.Fatal("expected reload error")
	}
	metrics, alerts, actions := capture.snapshot()
	if len(metrics) != 1 || metrics[0].command != "openshell policy reload" || metrics[0].exitCode != 7 {
		t.Fatalf("metrics = %#v", metrics)
	}
	if len(alerts) != 1 || alerts[0].subsystem != "openshell" ||
		alerts[0].severity != "HIGH" || alerts[0].code != "subprocess_exit" {
		t.Fatalf("alerts = %#v", alerts)
	}
	// The producer must retain source content. Destination-specific central
	// redaction decides whether this value is raw, detected, or removed.
	if got := alerts[0].details["error"]; got != "token=user@example.com\n" {
		t.Fatalf("raw error = %#v", got)
	}
	if len(actions) != 0 {
		t.Fatalf("unexpected success actions = %#v", actions)
	}
}

func TestOpenShellStartNonZeroExitUsesCanonicalObservability(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	dir := t.TempDir()
	script := filepath.Join(dir, "fake-openshell")
	if err := os.WriteFile(script, []byte("#!/bin/sh\nif [ \"$1\" = start ]; then echo fail >&2; exit 127; fi\nexit 0\n"), 0o700); err != nil {
		t.Fatal(err)
	}
	capture := newOpenShellObservabilityCapture()
	o := New(script, dir)
	o.BindObservabilityV8(capture)
	if err := o.Start(filepath.Join(dir, "p.yaml")); err != nil {
		t.Fatal(err)
	}
	deadline := time.NewTimer(5 * time.Second)
	defer deadline.Stop()
	for {
		metrics, alerts, _ := capture.snapshot()
		if len(metrics) == 1 && len(alerts) == 1 {
			if metrics[0].command != "openshell start" || metrics[0].exitCode != 127 {
				t.Fatalf("metrics = %#v", metrics)
			}
			if alerts[0].details["error"] != "fail\n" {
				t.Fatalf("alerts = %#v", alerts)
			}
			return
		}
		select {
		case <-capture.wake:
		case <-deadline.C:
			t.Fatalf("timed out waiting for OpenShell observability: metrics=%#v alerts=%#v", metrics, alerts)
		}
	}
}

func TestOpenShellReloadPolicySuccessAuditsConfigurationChange(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	dir := t.TempDir()
	script := filepath.Join(dir, "fake-openshell")
	if err := os.WriteFile(script, []byte("#!/bin/sh\nexit 0\n"), 0o700); err != nil {
		t.Fatal(err)
	}
	capture := newOpenShellObservabilityCapture()
	o := New(script, dir)
	o.BindObservabilityV8(capture)
	if err := o.ReloadPolicy(); err != nil {
		t.Fatal(err)
	}
	metrics, alerts, actions := capture.snapshot()
	if len(metrics) != 0 || len(alerts) != 0 {
		t.Fatalf("unexpected failure signals: metrics=%#v alerts=%#v", metrics, alerts)
	}
	if len(actions) != 1 || actions[0].action != "policy-reload" ||
		actions[0].target != o.PolicyPath() || actions[0].details != "OpenShell sandbox policy reloaded" {
		t.Fatalf("actions = %#v", actions)
	}
}

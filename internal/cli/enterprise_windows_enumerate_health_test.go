// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"bytes"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/managed"
)

func TestEnterpriseWindowsEnumerateHealthDegradesOnceAndBacksOff(t *testing.T) {
	events := captureResilienceEvents(t)
	health := enterpriseWindowsEnumerateHealth{interval: 5 * time.Minute}
	var out bytes.Buffer
	failure := errors.New("write manifest: sharing violation")

	var delays []time.Duration
	for i := 0; i < 6; i++ {
		delay, retry := health.observe(&out, `D:\state\targets.yaml`, failure)
		if !retry {
			delays = append(delays, 0)
			continue
		}
		delays = append(delays, delay)
	}
	want := []time.Duration{15 * time.Second, 30 * time.Second, time.Minute, 2 * time.Minute, 4 * time.Minute, 0}
	for i := range want {
		if delays[i] != want[i] {
			t.Fatalf("delays = %v, want %v", delays, want)
		}
	}
	if len(*events) != 1 || !strings.HasPrefix((*events)[0], managed.MarkerDegraded+" ") {
		t.Fatalf("events = %v", *events)
	}
	if _, retry := health.observe(&out, `D:\state\targets.yaml`, nil); retry {
		t.Fatal("success scheduled a retry")
	}
	if !strings.Contains(out.String(), "recovered") {
		t.Fatalf("output = %q", out.String())
	}
	if _, retry := health.observe(&out, `D:\state\targets.yaml`, failure); !retry || len(*events) != 2 {
		t.Fatalf("a new failure streak must log degraded again: %v", *events)
	}
}

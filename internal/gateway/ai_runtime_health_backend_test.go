// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/sensor"
	"github.com/defenseclaw/defenseclaw/internal/sensor/plane"
	"github.com/defenseclaw/defenseclaw/internal/sensor/platform"
)

// TestRuntimeHealthCarriesThePlaneCBackend: /health
// ai_runtime.details.planes.c.backend is the runtime API's backend object,
// with the kernel floor, because `defenseclaw-gateway status` reads exactly that path;
// a plane without a backend keeps its old keys.
func TestRuntimeHealthCarriesThePlaneCBackend(t *testing.T) {
	t.Parallel()
	s := &Sidecar{health: NewSidecarHealth()}
	s.publishAIRuntimeHealth(sensor.Snapshot{
		ScannedAt: time.Date(2026, 10, 7, 12, 0, 0, 0, time.UTC),
		Planes: []sensor.PlaneHealth{
			{Plane: platform.PlaneA, Available: true, Running: true, Mechanism: "helper"},
			{Plane: platform.PlaneC, Available: true, Running: true,
				Mechanism: "Tetragon v1.7.1 (gRPC) + fanotify (via the sensor helper)",
				Backend: &plane.Backend{Kind: plane.BackendTetragon, Version: "v1.7.1", Mode: "enforce",
					Socket: "/var/run/tetragon/tetragon.sock", EventsLost: 3, LossKnown: true}},
		},
		Kernel: enforcingKernelState(),
	})
	body := decodeJSONMap(t, s.health.Snapshot())
	details := body["ai_runtime"].(map[string]interface{})["details"].(map[string]interface{})
	planes := details["planes"].(map[string]interface{})
	if _, ok := planes["a"].(map[string]interface{})["backend"]; ok {
		t.Fatal("plane a carried a backend")
	}
	backend, ok := planes["c"].(map[string]interface{})["backend"].(map[string]interface{})
	if !ok {
		t.Fatalf("plane c has no backend: %v", planes["c"])
	}
	if backend["kind"] != "tetragon" || backend["version"] != "v1.7.1" || backend["mode"] != "enforce" ||
		backend["events_lost"] != float64(3) || backend["loss_known"] != true {
		t.Fatalf("backend = %v", backend)
	}
	floor, _ := backend["kernel_floor"].(map[string]interface{})
	if floor["enforced_users"] != float64(1) || floor["burn_in_users"] != float64(1) || floor["paused_until"] != "2026-10-07T14:05:00Z" {
		t.Fatalf("kernel_floor = %v", backend["kernel_floor"])
	}
}

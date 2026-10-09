// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// SPDX-License-Identifier: Apache-2.0

package sensor

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/sensor/netprobe"
	"github.com/defenseclaw/defenseclaw/internal/sensor/plane"
	"github.com/defenseclaw/defenseclaw/internal/sensor/platform"
	"github.com/defenseclaw/defenseclaw/internal/sensor/procprobe"
)

// A kernel tcp_connect (Tetragon, observe and enforce) is a connection of
// its process at the next poll: a short connect that no /proc/net read saw
// is scored by Plane B per binary, even after the process exited, and the
// Plane B mechanism says the connects are in it.
func TestKernelConnectsAreScoredByPlaneB(t *testing.T) {
	t.Parallel()
	now := time.Unix(1_760_000_000, 0)
	coverage := fullCoverage()
	coverage.Kinds = append(coverage.Kinds, plane.KindConnect)
	uid := 1001
	source := newFake(coverage,
		plane.Event{Kind: plane.KindConnect, PID: 4100, Name: "curl", Cmdline: "curl https://api.anthropic.com/v1/messages",
			User: "alice", UID: &uid, Remote: "160.79.104.10:443", Source: plane.SourceTetragon},
		plane.Event{Kind: plane.KindConnect, PID: 4100, Name: "curl", Remote: "160.79.104.10:443"}, // a repeat
		plane.Event{Kind: plane.KindConnect, PID: 4200, Name: "gateway", Remote: "160.79.104.10:443", Self: true},
		plane.Event{Kind: plane.KindConnect, PID: 4300, Name: "nc", Remote: "not-an-address"},
	)
	service, err := New(Options{
		Config:    config.AIRuntimeConfig{Enabled: true, EnableHostPlane: true},
		Providers: testCatalog(),
		Platform:  allPlanesAvailable(),
		Resolver:  StaticResolver{Names: map[string]string{"160.79.104.10": "api.anthropic.com"}, Confidence: ConfidenceDNSAnswer, Source: "dns_answer"},
		Acquirer:  &kernelAcquirer{source: source},
		Now:       func() time.Time { return now },
	})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	service.startHostPlane(ctx)
	deadline := time.After(5 * time.Second)
	for service.hostPlane.handled.Load() < 4 {
		select {
		case <-deadline:
			t.Fatal("the connects were not handled")
		case <-time.After(2 * time.Millisecond):
		}
	}
	snapshot := service.Poll(ctx)
	var found *Finding
	for i := range snapshot.Findings {
		if snapshot.Findings[i].PID == 4100 {
			found = &snapshot.Findings[i]
		}
		if snapshot.Findings[i].PID == 4200 || snapshot.Findings[i].PID == 4300 {
			t.Fatalf("scored %+v", snapshot.Findings[i])
		}
	}
	if found == nil {
		t.Fatalf("the exited curl's connect was not scored: %+v", snapshot.Findings)
	}
	if found.Process != "curl" || found.User != "alice" || len(found.Providers) != 1 || found.Providers[0].Hostname != "api.anthropic.com" {
		t.Fatalf("finding = %+v", found)
	}
	if snapshot.ProcessesObserved != 0 || snapshot.ConnectionsObserved != 0 {
		t.Fatalf("the table counts are the tables': processes %d connections %d", snapshot.ProcessesObserved, snapshot.ConnectionsObserved)
	}
	if mechanism := planeOf(snapshot, platform.PlaneB).Mechanism; !strings.Contains(mechanism, "kernel connects (Tetragon)") {
		t.Fatalf("plane b mechanism = %q", mechanism)
	}
	if again := service.Poll(ctx); len(again.Findings) != 0 {
		t.Fatalf("a drained connect was scored twice: %+v", again.Findings)
	}
}

// A connect the connection table also lists is one connection, and a live
// process keeps its own table entry.
func TestMergeKernelConnectsDeduplicates(t *testing.T) {
	t.Parallel()
	live := []procprobe.Process{{PID: 10, Name: "node"}}
	table := []netprobe.Connection{{PID: 10, RemoteIP: []byte{160, 79, 104, 10}, RemotePort: 443, State: netprobe.StateEstablished}}
	connects := []kernelConnect{
		{PID: 10, Name: "node", IP: []byte{160, 79, 104, 10}, Port: 443},
		{PID: 10, Name: "node", IP: []byte{160, 79, 104, 11}, Port: 443},
		{PID: 11, Name: "curl", IP: []byte{160, 79, 104, 10}, Port: 443},
	}
	merged, exited := mergeKernelConnects(live, table, connects)
	if len(merged) != 3 || len(exited) != 1 || exited[0].PID != 11 || exited[0].Name != "curl" {
		t.Fatalf("merged %+v exited %+v", merged, exited)
	}
}

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

//go:build linux || darwin

package gateway

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/audit"
	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/sandboxreg"
	"github.com/defenseclaw/defenseclaw/internal/sandboxrelay"
)

func TestGAP0667ManagedProcessAndEgressAudit(t *testing.T) {
	f := newSandboxFixture(t, config.EnterpriseEnrollmentConfig{}, nil)
	f.setGroups(sbxAlice, "dc-sbx-contractors")
	store, logger := testStoreAndLogger(t)
	f.api.store, f.api.logger = store, logger
	t.Cleanup(func() { managedSandboxRecorders.Delete(f.api) })
	id := f.resolve(sbxAlice, claudeResolve()).Registration.ID
	if rec := f.bind(sbxAlice, id, 1); rec.Code != http.StatusOK {
		t.Fatalf("bind: %d %s", rec.Code, rec.Body.String())
	}
	relay := newDaemonRelayTelemetry(fixtureEventsRelay{f: f, peer: sbxAlice}, func(string) (string, bool) { return id, true }, t.Logf)
	relay.flushEvery = time.Hour
	ctx := context.Background()
	box := audit.SandboxIdentity{Name: "dc-claude-1", ID: "sbx-1", Runtime: audit.SandboxRuntimeOpenShell}
	at := time.Now().UTC()
	for _, event := range []string{audit.SandboxProcessStart, audit.SandboxProcessExit} {
		if err := relay.RecordSandboxProcess(ctx, audit.SandboxProcessEvent{Sandbox: box, Event: event, Source: audit.SandboxProcessSourceSample,
			PID: 47, ParentPID: 1, Executable: "/usr/bin/curl", Name: "curl", CommandLine: "curl -sI https://example.org",
			Timestamp: at, UserID: "unverified", UserName: "unverified"}); err != nil {
			t.Fatal(err)
		}
	}
	relay.flush(ctx)
	registrations := sandboxreg.NewFileStore(sandboxreg.RegistrationsDir(f.cfg.DataDir))
	reg, ok, err := registrations.Get(sbxAlice.UID, id)
	if err != nil || !ok || !reg.GuestSeenAt.IsZero() {
		t.Fatalf("process telemetry changed the guest sighting: %+v %v %v", reg, ok, err)
	}
	for _, blocked := range []bool{false, true} {
		if err := relay.RecordSandboxEgress(ctx, audit.SandboxEgressEvent{Sandbox: box, Source: audit.SandboxEgressSourceProxy,
			Host: "example.org", Port: 443, Blocked: blocked, PID: 47, Executable: "/usr/bin/curl", Timestamp: at}); err != nil {
			t.Fatal(err)
		}
	}
	relay.flush(ctx)
	processes := sandboxAuditRows(t, store, audit.ActionSandboxProcess)
	egress := sandboxAuditRows(t, store, audit.ActionSandboxEgress)
	if len(processes) != 2 || len(egress) != 2 {
		t.Fatalf("process=%d egress=%d, want two of each", len(processes), len(egress))
	}
	for _, row := range append(processes, egress...) {
		fields := row.Structured
		if fields["defenseclaw.sandbox.name"] != box.Name || fields["user.id"] != "94404076" ||
			fields["defenseclaw.sandbox.process.executable"] != "/usr/bin/curl" {
			t.Fatalf("sandbox, person, or executable was not recorded: %v", fields)
		}
	}
	for _, row := range processes {
		fields := row.Structured
		if fields["defenseclaw.sandbox.process.pid"] != float64(47) || fields["defenseclaw.sandbox.process.command_line"] != "curl -sI https://example.org" ||
			fields["defenseclaw.sandbox.process.source"] != audit.SandboxProcessSourceSample || fields["defenseclaw.sandbox.process.event"] == nil {
			t.Fatalf("process fields: %v", fields)
		}
	}
	foreign := box
	foreign.Name = "dc-other-1"
	if err := relay.RecordSandboxProcess(ctx, audit.SandboxProcessEvent{Sandbox: foreign, Event: audit.SandboxProcessStart,
		Source: audit.SandboxProcessSourceSample, PID: 93, Executable: "/usr/bin/curl", Timestamp: at}); err != nil {
		t.Fatal(err)
	}
	relay.flush(ctx)
	if got := len(sandboxAuditRows(t, store, audit.ActionSandboxProcess)); got != 2 {
		t.Fatalf("foreign sandbox process produced %d rows, want two", got)
	}
}

func TestGAP0667ProcessRelayKeepsBatchesWithinByteLimit(t *testing.T) {
	const registration = "reg-aaaaaaaaaaaaaaaaaaaaaaaaaa"
	recorder := &eventsRecorder{}
	relay := newDaemonRelayTelemetry(recorder, func(string) (string, bool) { return registration, true }, t.Logf)
	relay.flushEvery = time.Hour
	for i := 1; i <= sandboxrelay.MaxTelemetryBatchRecords; i++ {
		if err := relay.RecordSandboxProcess(context.Background(), audit.SandboxProcessEvent{
			Sandbox: audit.SandboxIdentity{Name: "box"}, Event: audit.SandboxProcessStart,
			Source: audit.SandboxProcessSourceSample, PID: i, CommandLine: strings.Repeat("x", 3000), Timestamp: time.Now(),
		}); err != nil {
			t.Fatal(err)
		}
	}
	if relay.flush(context.Background()) {
		t.Fatal("the process queue was not drained")
	}
	if len(recorder.batches) < 2 {
		t.Fatalf("%d batch, want the long records split by bytes", len(recorder.batches))
	}
	total := 0
	for _, batch := range recorder.batches {
		raw, err := json.Marshal(batch)
		if err != nil || len(raw) > sandboxrelay.MaxEventBatchBytes {
			t.Fatalf("batch size %d: %v", len(raw), err)
		}
		total += len(batch.Events)
	}
	if total != sandboxrelay.MaxTelemetryBatchRecords {
		t.Fatalf("%d process records relayed", total)
	}
}

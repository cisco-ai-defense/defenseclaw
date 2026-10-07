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

package audit

import (
	"context"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/observability"
	"github.com/defenseclaw/defenseclaw/internal/observability/router"
)

func TestSandboxProcessFamily(t *testing.T) {
	harness := newSandboxHarness(t)
	identity := testSandboxIdentity()
	code := 3
	_, record := harness.recordOne(t, router.AdmissionOrdinary, SandboxProcessEvent{
		Sandbox: identity, Event: SandboxProcessExit, Source: SandboxProcessSourceSample, PID: 42, ParentPID: 1,
		Executable: "/usr/bin/node", Name: "node", CommandLine: "node cli.js", WorkingDirectory: "/sandbox/work/myapp",
		ExitCode: &code, Lineage: []string{"bash", "claude"},
	})
	if record.EventName() != observability.EventName(observability.TelemetryEventSandboxProcessTree) ||
		record.Bucket() != observability.BucketAgentLifecycle || record.Mandatory() {
		t.Fatalf("record %s bucket %s mandatory %v", record.EventName(), record.Bucket(), record.Mandatory())
	}
	body := sandboxBody(t, record)
	assertSandboxCorrelation(t, body, identity)
	assertSandboxFields(t, body, map[string]any{
		"defenseclaw.sandbox.process.event": "exit", "defenseclaw.sandbox.process.source": "sample",
		"defenseclaw.sandbox.process.pid": int64(42), "defenseclaw.sandbox.process.parent_pid": int64(1),
		"defenseclaw.sandbox.process.name": "node", "defenseclaw.sandbox.process.exit_code": int64(3),
	})
}

// Agent-chosen text never fails the record; an unregistered event, source
// or pid does, before anything is emitted.
func TestSandboxProcessRecordBoundsItsInput(t *testing.T) {
	harness := newSandboxHarness(t)
	identity := testSandboxIdentity()
	_, record := harness.recordOne(t, router.AdmissionOrdinary, SandboxProcessEvent{
		Sandbox: identity, Event: SandboxProcessStart, PID: 7, Name: strings.Repeat("n", 300),
		CommandLine: strings.Repeat("dccert-block-marker ", 200), Lineage: make([]string, 100),
	})
	body := sandboxBody(t, record)
	if name, _ := body["defenseclaw.sandbox.process.name"].(string); len(name) > maxSandboxProcessName {
		t.Fatalf("name of %d bytes", len(name))
	}
	if _, present := body["defenseclaw.sandbox.process.parent_pid"]; present {
		t.Fatal("an unknown parent is recorded")
	}
	for _, bad := range []SandboxProcessEvent{
		{Sandbox: identity, Event: "spawn", PID: 7},
		{Sandbox: identity, Event: SandboxProcessStart, Source: "guess", PID: 7},
		{Sandbox: identity, Event: SandboxProcessStart, PID: 0},
		{Sandbox: identity, Event: SandboxProcessStart, PID: maxSandboxProcessPID + 1},
		{Sandbox: SandboxIdentity{}, Event: SandboxProcessStart, PID: 7},
	} {
		runtime, recorder := harness.bind(t, router.AdmissionOrdinary)
		if err := recorder.RecordSandboxProcess(context.Background(), bad); err == nil {
			t.Fatalf("%+v accepted", bad)
		}
		if metadata, _ := runtime.snapshot(); len(metadata) != 0 {
			t.Fatalf("%+v emitted before it was refused", bad)
		}
	}
}

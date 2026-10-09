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
	identity.BindingID = "sb_3f9a7c21d04e5b6a8c9d0e1f2a3b4c5d"
	code := 3
	_, record := harness.recordOne(t, router.AdmissionOrdinary, SandboxProcessEvent{
		Sandbox: identity, Event: SandboxProcessExit, Source: SandboxProcessSourceSample, PID: 42, ParentPID: 1,
		Executable: "/usr/bin/node", Name: "node", CommandLine: "node cli.js", WorkingDirectory: "/sandbox/work/myapp",
		ExitCode: &code, Lineage: []string{"bash", "claude"},
		UserID: "1000", UserName: "dev", ConversationID: "hook-session-7",
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
		"defenseclaw.sandbox.binding.id": identity.BindingID, "user.id": "1000", "defenseclaw.user.name": "dev",
		"gen_ai.conversation.id": "hook-session-7",
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
		{Sandbox: identity, Event: SandboxProcessStart, PID: maxSandboxPID + 1},
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

// A process the sandbox kernel feed reported carries its host pid and
// Tetragon's exec id; without a captured in-sandbox pid it is recorded by
// those alone. Only the tetragon source records them, and an exec id of
// another shape is left out rather than failing the record.
func TestSandboxProcessFromTheKernelFeed(t *testing.T) {
	harness := newSandboxHarness(t)
	identity := testSandboxIdentity()
	execID := "ZGNjZXJ0LWhvc3Q6NDEyMTc3NDA4ODc4MDoyMTc0MDA="
	code := 0
	_, record := harness.recordOne(t, router.AdmissionOrdinary, SandboxProcessEvent{
		Sandbox: identity, Event: SandboxProcessExit, Source: SandboxProcessSourceTetragon, HostPID: 217400, ExecID: execID,
		Executable: "/usr/bin/cat", Name: "cat", CommandLine: "/usr/bin/cat dccert-block-marker", ExitCode: &code,
	})
	body := sandboxBody(t, record)
	assertSandboxFields(t, body, map[string]any{
		"defenseclaw.sandbox.process.source": "tetragon", "defenseclaw.sandbox.process.host_pid": int64(217400),
		"defenseclaw.sandbox.process.exec_id": execID, "defenseclaw.sandbox.process.exit_code": int64(0),
	})
	if _, present := body["defenseclaw.sandbox.process.pid"]; present {
		t.Fatal("an in-sandbox pid nobody captured is recorded")
	}

	_, record = harness.recordOne(t, router.AdmissionOrdinary, SandboxProcessEvent{
		Sandbox: identity, Event: SandboxProcessStart, Source: SandboxProcessSourceTetragon, PID: 57, HostPID: 217400,
		ExecID: "not base64: dccert-block-marker",
	})
	body = sandboxBody(t, record)
	assertSandboxFields(t, body, map[string]any{"defenseclaw.sandbox.process.pid": int64(57), "defenseclaw.sandbox.process.host_pid": int64(217400)})
	if _, present := body["defenseclaw.sandbox.process.exec_id"]; present {
		t.Fatal("an exec id of another shape is recorded")
	}

	_, record = harness.recordOne(t, router.AdmissionOrdinary, SandboxProcessEvent{
		Sandbox: identity, Event: SandboxProcessStart, Source: SandboxProcessSourceSample, PID: 42, HostPID: 217400, ExecID: execID,
	})
	body = sandboxBody(t, record)
	for _, key := range []string{"defenseclaw.sandbox.process.host_pid", "defenseclaw.sandbox.process.exec_id"} {
		if _, present := body[key]; present {
			t.Fatalf("a sample record carries %s", key)
		}
	}

	for _, bad := range []SandboxProcessEvent{
		{Sandbox: identity, Event: SandboxProcessStart, Source: SandboxProcessSourceTetragon},
		{Sandbox: identity, Event: SandboxProcessStart, Source: SandboxProcessSourceSample, HostPID: 217400},
		{Sandbox: identity, Event: SandboxProcessStart, Source: SandboxProcessSourceTetragon, PID: -1, HostPID: 217400},
	} {
		_, recorder := harness.bind(t, router.AdmissionOrdinary)
		if err := recorder.RecordSandboxProcess(context.Background(), bad); err == nil {
			t.Fatalf("%+v accepted", bad)
		}
	}
}

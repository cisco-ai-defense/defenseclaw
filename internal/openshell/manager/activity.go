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

package manager

import (
	"context"
	"net"
	"strconv"
	"strings"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/audit"
	"github.com/defenseclaw/defenseclaw/internal/openshell/ocsf"
)

// Sandbox activity: OpenShell's OCSF records of what runs in a sandbox and
// what reaches into it, recorded as log.sandbox.process (PROC LAUNCH and
// TERMINATE), log.sandbox.ssh (SSH) and log.sandbox.inference
// (API:INFERENCE). A workload starts processes, and a client opens SSH
// sessions, as fast as it likes, so each sandbox's process and SSH records
// are paced (activityBurst, activityRate); the egress sink's report logs
// what the pacing held back. Model calls are as frequent as the harness's
// turns and are not paced.
const activityBurst, activityRate = 200, 20

// ocsfPID is the actor process ID a record names, 0 when it names none.
func ocsfPID(r ocsf.Record) int {
	if !r.HasPID {
		return 0
	}
	return r.PID
}

// processEvent records a process the sandbox started or that exited.
func (m *Manager) processEvent(ctx context.Context, id audit.SandboxIdentity, r ocsf.Record, at time.Time) {
	var event string
	switch strings.ToUpper(r.Activity) {
	case "LAUNCH":
		event = audit.SandboxProcessStart
	case "TERMINATE":
		event = audit.SandboxProcessExit
	default:
		return
	}
	if !m.procGate.take(id.Name, m.now()) {
		return
	}
	m.tel.RecordSandboxActivity(ctx, audit.SandboxActivityEvent{
		Sandbox: id, Kind: audit.SandboxActivityProcess, ProcessEvent: event, ProcessSource: audit.SandboxProcessSourceOCSF,
		PID: ocsfPID(r), Executable: r.Binary, CommandLine: r.CmdLine, ExitCode: r.ExitCode, Timestamp: at,
	})
}

// sshEvent records an SSH listener or connection event of the sandbox
// (`sandbox connect`, `sandbox exec`, an upload or pull).
func (m *Manager) sshEvent(ctx context.Context, id audit.SandboxIdentity, r ocsf.Record, at time.Time) {
	if r.Activity == "" || !m.procGate.take(id.Name+"\x00ssh", m.now()) {
		return
	}
	peer := r.Host
	if peer != "" && r.Port > 0 {
		peer = net.JoinHostPort(peer, strconv.Itoa(r.Port))
	}
	m.tel.RecordSandboxActivity(ctx, audit.SandboxActivityEvent{
		Sandbox: id, Kind: audit.SandboxActivitySSH, SSHActivity: r.Activity, SSHAllowed: r.Allowed(), SSHDenied: r.Denied(),
		SSHAuth: r.Auth, Peer: peer, Timestamp: at,
	})
}

// inferenceEvent records a model call OpenShell's inference route reported
// and counts it in the sandbox's destinations view.
func (m *Manager) inferenceEvent(ctx context.Context, b *box, id audit.SandboxIdentity, r ocsf.Record, at time.Time) {
	if !strings.EqualFold(r.Activity, "INFERENCE") {
		return
	}
	m.tel.RecordSandboxActivity(ctx, audit.SandboxActivityEvent{
		Sandbox: id, Kind: audit.SandboxActivityInference, Provider: r.Provider, Model: r.Model, Status: r.Status,
		Latency: time.Duration(r.LatencyMS) * time.Millisecond, Operation: r.Operation, Timestamp: at,
	})
	// A record without a status says nothing of a failure.
	status := strings.TrimSpace(r.Status)
	m.observeInference(b, r.Provider, r.Model, status != "" && !strings.EqualFold(status, "success"), at)
}

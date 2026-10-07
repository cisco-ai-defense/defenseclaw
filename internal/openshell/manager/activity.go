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
	"sync"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/audit"
	"github.com/defenseclaw/defenseclaw/internal/openshell"
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
	// The command line the process tree keeps: values that name secrets
	// replaced, at most maxCmdlineBytes.
	var cmdline string
	if r.CmdLine != "" {
		cmdline = processCmdline(strings.Fields(r.CmdLine))
	}
	m.tel.RecordSandboxActivity(ctx, audit.SandboxActivityEvent{
		Sandbox: id, Kind: audit.SandboxActivityProcess, ProcessEvent: event, ProcessSource: audit.SandboxProcessSourceOCSF,
		PID: ocsfPID(r), Executable: r.Binary, CommandLine: cmdline, ExitCode: r.ExitCode, Timestamp: at,
	})
}

// sshEvent records an SSH listener or connection event of the sandbox
// (`sandbox connect`, `sandbox exec`, an upload or pull). Every exec is an
// SSH session in the sandbox: the OPEN of one DefenseClaw ran itself
// (ownExec) is not the sandbox's activity, and is dropped.
func (m *Manager) sshEvent(ctx context.Context, id audit.SandboxIdentity, r ocsf.Record, at time.Time) {
	if r.Activity == "" || strings.EqualFold(r.Activity, "OPEN") && m.ownExecs.claim(id.Name, m.now()) ||
		!m.procGate.take(id.Name+"\x00ssh", m.now()) {
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

// ownExecs are the execs DefenseClaw runs in each sandbox itself (process
// samples every 5 s, discovery, verification, the end-of-session steps).
// OpenShell reports each as an SSH OPEN, without anything that tells it
// from a user's `sandbox exec`: sshEvent drops one OPEN for each exec that
// started at most ownExecWindow before it arrived.
type ownExecs struct {
	mu sync.Mutex
	at map[string][]time.Time
}

// ownExecWindow bounds how late an exec's SSH OPEN arrives; ownExecMax
// bounds the execs remembered per sandbox.
const (
	ownExecWindow = 30 * time.Second
	ownExecMax    = 64
)

func (o *ownExecs) started(sandbox string, at time.Time) {
	o.mu.Lock()
	defer o.mu.Unlock()
	if o.at == nil {
		o.at = map[string][]time.Time{}
	}
	q := append(o.at[sandbox], at)
	if len(q) > ownExecMax {
		q = q[len(q)-ownExecMax:]
	}
	o.at[sandbox] = q
}

// claim reports whether an SSH OPEN that arrived at at is one of
// DefenseClaw's own execs, which it then no longer waits for.
func (o *ownExecs) claim(sandbox string, at time.Time) bool {
	o.mu.Lock()
	defer o.mu.Unlock()
	q := o.at[sandbox]
	for len(q) > 0 && q[0].Before(at.Add(-ownExecWindow)) {
		q = q[1:]
	}
	own := len(q) > 0 && !q[0].After(at)
	if own {
		q = q[1:]
	}
	if len(q) == 0 {
		delete(o.at, sandbox)
	} else {
		o.at[sandbox] = q
	}
	return own
}

// ownExec runs one of DefenseClaw's own commands in a sandbox
// (Client.Exec), noting it for sshEvent first.
func (m *Manager) ownExec(ctx context.Context, gw *Gateway, sandbox string, argv []string, opts openshell.ExecOptions) (*openshell.ExecResult, error) {
	m.ownExecs.started(sandbox, m.now())
	return gw.Client.Exec(ctx, sandbox, argv, opts)
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

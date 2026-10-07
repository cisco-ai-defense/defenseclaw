// Copyright 2026 Cisco Systems, Inc. and its affiliates
// Copyright (c) 2026 Mike Storm. All rights reserved.
//
// Derived from ShadowClaw -- Universal Shadow AI Detector, by Mike Storm,
// Distinguished Engineer, CCIE Security 13847. Reimplemented in Go and
// absorbed into the DefenseClaw gateway; see NOTICE for the modifications.
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

package acquire

import (
	"net"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/sensor/netprobe"
	"github.com/defenseclaw/defenseclaw/internal/sensor/plane"
	"github.com/defenseclaw/defenseclaw/internal/sensor/procprobe"
)

// The wire types are declared separately from the domain types on purpose.
//
// Encoding the domain structs directly would make every field addition a
// silent protocol change between two processes that may be upgraded at
// different times. Keeping an explicit projection means a new field has to
// be added here to cross, which is the moment to think about whether it
// should.

type wireProcess struct {
	PID       int    `json:"pid"`
	PPID      int    `json:"ppid,omitempty"`
	Name      string `json:"name,omitempty"`
	Cmdline   string `json:"cmdline,omitempty"`
	User      string `json:"user,omitempty"`
	CPUNanos  int64  `json:"cpu_ns,omitempty"`
	RSSBytes  int64  `json:"rss,omitempty"`
	StartedAt int64  `json:"started_unix_ns,omitempty"`
}

func encodeProcess(row procprobe.Process) wireProcess {
	out := wireProcess{
		PID: row.PID, PPID: row.PPID, Name: row.Name, Cmdline: row.Cmdline,
		User: row.User, CPUNanos: int64(row.CPUTime), RSSBytes: row.RSSBytes,
	}
	if !row.StartedAt.IsZero() {
		out.StartedAt = row.StartedAt.UnixNano()
	}
	return out
}

func decodeProcess(row wireProcess) procprobe.Process {
	out := procprobe.Process{
		PID: row.PID, PPID: row.PPID, Name: row.Name, Cmdline: row.Cmdline,
		User: row.User, CPUTime: time.Duration(row.CPUNanos), RSSBytes: row.RSSBytes,
	}
	if row.StartedAt != 0 {
		out.StartedAt = time.Unix(0, row.StartedAt)
	}
	return out
}

type wireConnection struct {
	PID        int    `json:"pid,omitempty"`
	LocalPort  int    `json:"local_port,omitempty"`
	RemoteIP   string `json:"remote_ip,omitempty"`
	RemotePort int    `json:"remote_port,omitempty"`
	State      string `json:"state,omitempty"`
}

func encodeConnection(row netprobe.Connection) wireConnection {
	out := wireConnection{
		PID: row.PID, LocalPort: row.LocalPort,
		RemotePort: row.RemotePort, State: string(row.State),
	}
	if row.RemoteIP != nil {
		out.RemoteIP = row.RemoteIP.String()
	}
	return out
}

func decodeConnection(row wireConnection) netprobe.Connection {
	out := netprobe.Connection{
		PID: row.PID, LocalPort: row.LocalPort,
		RemotePort: row.RemotePort, State: netprobe.State(row.State),
	}
	if row.RemoteIP != "" {
		// A peer address that will not parse is dropped rather than carried
		// as a nil-but-present field: a connection with a port and no
		// address is the shape the netprobe tests reject as impossible.
		if parsed := net.ParseIP(row.RemoteIP); parsed != nil {
			out.RemoteIP = parsed
		}
	}
	return out
}

type wireEvent struct {
	Kind           string `json:"kind"`
	PID            int    `json:"pid,omitempty"`
	PPID           int    `json:"ppid,omitempty"`
	ResponsiblePID int    `json:"responsible_pid,omitempty"`
	Name           string `json:"name,omitempty"`
	Cmdline        string `json:"cmdline,omitempty"`
	Path           string `json:"path,omitempty"`
	Detail         string `json:"detail,omitempty"`
	User           string `json:"user,omitempty"`
	AtUnixNano     int64  `json:"at_unix_ns,omitempty"`
	// The Tetragon fields. Every one is omitempty, so a gateway that
	// predates them ignores them and a helper that predates them simply
	// never sends them; protocolVersion is unchanged.
	Exe          string `json:"exe,omitempty"`
	UID          *int   `json:"uid,omitempty"`
	AUID         *int   `json:"auid,omitempty"`
	ExecID       string `json:"exec_id,omitempty"`
	ParentExecID string `json:"parent_exec_id,omitempty"`
	StartNS      int64  `json:"start_ns,omitempty"`
	ContainerID  string `json:"container_id,omitempty"`
	Source       string `json:"source,omitempty"`
	Policy       string `json:"policy,omitempty"`
	Outcome      string `json:"outcome,omitempty"`
	Control      string `json:"control,omitempty"`
	Remote       string `json:"remote,omitempty"`
	Self         bool   `json:"self,omitempty"`
	Hook         string `json:"hook,omitempty"`
	HookTools    int    `json:"hook_tools,omitempty"`
}

func encodeEvent(event plane.Event) wireEvent {
	out := wireEvent{
		Kind: string(event.Kind), PID: event.PID, PPID: event.PPID,
		ResponsiblePID: event.ResponsiblePID, Name: event.Name,
		Cmdline: event.Cmdline, Path: event.Path, Detail: event.Detail,
		User: event.User,
		Exe:  event.Exe, UID: copyInt(event.UID), AUID: copyInt(event.AUID),
		ExecID: event.ExecID, ParentExecID: event.ParentExecID, StartNS: event.StartNS,
		ContainerID: event.ContainerID, Source: string(event.Source),
		Policy: event.Policy, Outcome: string(event.Outcome), Control: event.Control, Remote: event.Remote,
		Self: event.Self, Hook: string(event.Hook), HookTools: event.HookTools,
	}
	if !event.At.IsZero() {
		out.AtUnixNano = event.At.UnixNano()
	}
	return out
}

func decodeEvent(event wireEvent) plane.Event {
	out := plane.Event{
		Kind: plane.Kind(event.Kind), PID: event.PID, PPID: event.PPID,
		ResponsiblePID: event.ResponsiblePID, Name: event.Name,
		Cmdline: event.Cmdline, Path: event.Path, Detail: event.Detail,
		User: event.User,
		Exe:  event.Exe, UID: copyInt(event.UID), AUID: copyInt(event.AUID),
		ExecID: event.ExecID, ParentExecID: event.ParentExecID, StartNS: event.StartNS,
		ContainerID: event.ContainerID, Source: plane.EventSource(event.Source),
		Policy: event.Policy, Outcome: plane.KernelOutcome(event.Outcome), Control: event.Control, Remote: event.Remote,
		Self: event.Self, Hook: plane.HookMark(event.Hook), HookTools: event.HookTools,
	}
	if event.AtUnixNano != 0 {
		out.At = time.Unix(0, event.AtUnixNano)
	}
	return out
}

// copyInt keeps a decoded event from aliasing the value it was built from.
func copyInt(value *int) *int {
	if value == nil {
		return nil
	}
	copied := *value
	return &copied
}

type wireCoverage struct {
	Mechanism    string       `json:"mechanism,omitempty"`
	Kinds        []string     `json:"kinds,omitempty"`
	MissingKinds []string     `json:"missing_kinds,omitempty"`
	Limitations  []string     `json:"limitations,omitempty"`
	Backend      *wireBackend `json:"backend,omitempty"`
}

// wireBackend is plane.Backend on the wire (omitempty, like the Tetragon
// event fields).
type wireBackend struct {
	Kind           string              `json:"kind"`
	Version        string              `json:"version,omitempty"`
	Mode           string              `json:"mode,omitempty"`
	Socket         string              `json:"socket,omitempty"`
	EventsLost     int64               `json:"events_lost,omitempty"`
	LossKnown      bool                `json:"loss_known,omitempty"`
	FallbackReason string              `json:"fallback_reason,omitempty"`
	Policies       []wireBackendPolicy `json:"policies,omitempty"`
}

type wireBackendPolicy struct {
	Name  string `json:"name"`
	Mode  string `json:"mode,omitempty"`
	State string `json:"state,omitempty"`
	Error string `json:"error,omitempty"`
}

func encodeCoverage(coverage plane.Coverage) wireCoverage {
	out := wireCoverage{Mechanism: coverage.Mechanism, Limitations: coverage.Limitations}
	for _, kind := range coverage.Kinds {
		out.Kinds = append(out.Kinds, string(kind))
	}
	for _, kind := range coverage.MissingKinds {
		out.MissingKinds = append(out.MissingKinds, string(kind))
	}
	if backend := coverage.Backend; backend != nil {
		wire := &wireBackend{
			Kind: backend.Kind, Version: backend.Version, Mode: backend.Mode, Socket: backend.Socket,
			EventsLost: backend.EventsLost, LossKnown: backend.LossKnown, FallbackReason: backend.FallbackReason,
		}
		for _, policy := range backend.Policies {
			wire.Policies = append(wire.Policies, wireBackendPolicy(policy))
		}
		out.Backend = wire
	}
	return out
}

func decodeCoverage(coverage wireCoverage) plane.Coverage {
	out := plane.Coverage{Mechanism: coverage.Mechanism, Limitations: coverage.Limitations}
	for _, kind := range coverage.Kinds {
		out.Kinds = append(out.Kinds, plane.Kind(kind))
	}
	for _, kind := range coverage.MissingKinds {
		out.MissingKinds = append(out.MissingKinds, plane.Kind(kind))
	}
	if wire := coverage.Backend; wire != nil {
		backend := &plane.Backend{
			Kind: wire.Kind, Version: wire.Version, Mode: wire.Mode, Socket: wire.Socket,
			EventsLost: wire.EventsLost, LossKnown: wire.LossKnown, FallbackReason: wire.FallbackReason,
		}
		for _, policy := range wire.Policies {
			backend.Policies = append(backend.Policies, plane.BackendPolicy(policy))
		}
		out.Backend = backend
	}
	return out
}

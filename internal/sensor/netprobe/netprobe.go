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

// Package netprobe attributes outbound connections to the process that owns
// them.
//
// Attribution is the entire value of a shadow-AI egress control. A host-wide
// byte counter can show a burst that coincides with a CPU spike, but it cannot
// say the burst belongs to one agent, and a finding needs both halves for the
// same pid.
//
// # The privilege asymmetry that shapes this
//
// On macOS and Linux the two planes are not scoped alike. The whole process
// table is readable unprivileged, but the socket-to-pid mapping is readable
// only for the calling user's own processes. So an unprivileged run watches
// the whole machine compute and only its own share of it talk. Windows is the
// exception: its connection table carries the owning pid in every row, so no
// privilege is needed to attribute a socket at all.
//
// That asymmetry is reported, never hidden. Snapshot returns how many
// connections it saw but could not attribute, so a run can say which half it
// has instead of reporting a quiet host.
package netprobe

import "net"

// State is the TCP state of an observed connection.
type State string

const (
	StateEstablished State = "established"
	StateListen      State = "listen"
	StateOther       State = "other"
)

// Connection is one observed socket.
type Connection struct {
	// PID is the owning process, or 0 when this run could not attribute it.
	PID int
	// LocalPort matters for the local-model-server-port signal: a process
	// listening on a port reserved to a model runtime is evidence in itself.
	LocalPort  int
	RemoteIP   net.IP
	RemotePort int
	State      State
}

// Attributed reports whether the connection carries an owning pid.
func (c Connection) Attributed() bool { return c.PID > 0 }

// Loopback reports whether the peer is on this host. Loopback peers are how a
// local inference client is recognised, and are never treated as egress.
func (c Connection) Loopback() bool { return c.RemoteIP != nil && c.RemoteIP.IsLoopback() }

// Public reports whether the peer is routable off this host. Only public peers
// are egress; RFC1918 and link-local traffic is not shadow AI leaving the
// building, and scoring it as such would drown the signal.
func (c Connection) Public() bool {
	if c.RemoteIP == nil || c.RemoteIP.IsLoopback() || c.RemoteIP.IsUnspecified() {
		return false
	}
	return !c.RemoteIP.IsPrivate() && !c.RemoteIP.IsLinkLocalUnicast() &&
		!c.RemoteIP.IsLinkLocalMulticast() && !c.RemoteIP.IsMulticast()
}

// Snapshot reads the current connection table.
//
// unattributed counts connections observed without an owning pid, which is the
// coverage figure an unprivileged run needs in order to describe its own
// blindness.
func Snapshot() (connections []Connection, unattributed int, err error) { return snapshot() }

// LocalModelPorts are the loopback ports reserved to local model runtimes.
// A process listening here is a local model server whether or not its
// executable name is recognised, which is what catches a renamed binary.
//
// Split by how much a port alone actually tells you. The reserved ones are
// registered to one runtime and nothing else uses them, so the port is
// evidence by itself. The ambiguous ones are ordinary development ports --
// 8080 is every HTTP server ever written -- and on their own they say
// nothing; a signal weighted 30 clears the default reporting floor, so
// treating them as evidence turns a local web server into a local model
// finding on a developer's machine.
var LocalModelPorts = map[int]string{
	11434: "ollama",
	1234:  "lm studio",
	8080:  "llama.cpp",
	8000:  "vllm",
	5000:  "localai",
	13305: "lemonade",
	4891:  "gpt4all",
	1337:  "jan",
	3928:  "cortex",
}

// ambiguousLocalModelPorts are the entries above that a non-AI service uses
// just as readily, and which therefore need something else to agree.
var ambiguousLocalModelPorts = map[int]bool{
	8080: true, 8000: true, 5000: true, 1234: true, 1337: true,
}

// LocalModelRuntimeForPort names the runtime a loopback port is reserved to,
// and reports whether the port alone is enough to say so.
//
// A caller that gets corroborated == false must find agreement elsewhere --
// the process being a known model runtime, say -- before scoring it.
func LocalModelRuntimeForPort(port int) (name string, corroborated bool) {
	runtime, ok := LocalModelPorts[port]
	if !ok {
		return "", false
	}
	return runtime, !ambiguousLocalModelPorts[port]
}

// LocalModelPortIsAmbiguous reports whether a port in the table is one an
// ordinary service uses too.
func LocalModelPortIsAmbiguous(port int) bool { return ambiguousLocalModelPorts[port] }

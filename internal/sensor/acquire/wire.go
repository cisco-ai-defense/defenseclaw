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
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"time"
)

// The protocol is deliberately tiny and closed.
//
// A client may ask for a fixed handful of things and may not describe any
// of them: the process table, the connection table, the event stream, DNS
// answers, liveness, and the kernel-policy status. There is no path, no
// filter, no glob, no pid, and no command anywhere in a request. That is
// the whole security argument for putting a privileged
// process on the other end -- the set of things it will ever do is fixed at
// compile time, so a compromised client gains no reach it did not already
// have.
//
// Anything added here must preserve that. A field that lets the caller say
// *what* to read turns the helper into a confused deputy with root.
const (
	// OpProcesses asks for the process table.
	OpProcesses = "processes"
	// OpConnections asks for the TCP table.
	OpConnections = "connections"
	// OpEvents subscribes to the Plane C event stream. The response is a
	// coverage frame followed by event frames until the connection closes.
	OpEvents = "events"
	// OpDNS subscribes to observed DNS answers.
	OpDNS = "dns"
	// OpHealth is a liveness probe that reads nothing.
	OpHealth = "health"
	// OpKernelStatus asks what the helper's kernel-policy reconciler has
	// applied (managed Linux with Tetragon): a read of the helper's own
	// state, fieldless like every other request. The gateway never sends
	// policy; it only learns what is running.
	OpKernelStatus = "kernel_status"
)

// protocolVersion is bumped on any incompatible frame change. A mismatch is
// refused rather than negotiated: two versions of a privileged protocol
// guessing at each other is not a state worth supporting.
const protocolVersion = 1

// maxFrameBytes bounds a single frame. The process table on a large host is
// the biggest thing that crosses, and this leaves generous headroom while
// still refusing a frame that could only be an attempt to exhaust the peer.
const maxFrameBytes = 64 << 20

// Request is what a client sends. It carries an operation and nothing else
// that could widen what the server reads.
type Request struct {
	Version int    `json:"version"`
	Op      string `json:"op"`
}

// Response is the server's reply header. Payload follows in Body.
type Response struct {
	Version int             `json:"version"`
	Op      string          `json:"op"`
	Error   string          `json:"error,omitempty"`
	Body    json.RawMessage `json:"body,omitempty"`
}

// ProcessTable is the OpProcesses payload.
type ProcessTable struct {
	Rows    []wireProcess `json:"rows"`
	Skipped int           `json:"skipped"`
}

// ConnectionTable is the OpConnections payload.
type ConnectionTable struct {
	Rows         []wireConnection `json:"rows"`
	Unattributed int              `json:"unattributed"`
}

// KernelStatus is the OpKernelStatus reply. It carries policy names, modes,
// uids and counters, and nothing a user did: no path, no command line. The
// helper's kernel-policy reconciler fills it from its own state; a helper
// without one answers Available false.
type KernelStatus struct {
	// Available is false when this helper runs no kernel-policy reconciler
	// (mode off or consume, a platform without Tetragon, or no reconciler
	// in this build); Reason then says which.
	Available bool   `json:"available"`
	Reason    string `json:"reason,omitempty"`
	// Mode is the effective enterprise.tetragon mode the helper runs.
	Mode string `json:"mode,omitempty"`
	// KernelPolicy is the digest of the built-in control set
	// (sha256:<12 hex>), the value enforce_ack approves.
	KernelPolicy string `json:"kernel_policy,omitempty"`
	// Applied is true when the last reconcile pass left Tetragon with the
	// policies the intent and the caps call for.
	Applied bool `json:"applied"`
	// Tetragon describes the agent as the reconciler last saw it.
	Tetragon *KernelTetragon `json:"tetragon,omitempty"`
	// Policies are the DefenseClaw policies the helper recorded or found.
	Policies []KernelPolicyStatus `json:"policies,omitempty"`
	// Users is the per-uid enforcement scope and burn-in.
	Users []KernelUserStatus `json:"users,omitempty"`
	// Counters are named totals (would_block, blocked, roots_over_limit,
	// ...).
	Counters map[string]int64 `json:"counters,omitempty"`
	// Pause is the break-glass pause, when one is in force.
	Pause *KernelPause `json:"pause,omitempty"`
	// Overrides are the policy families an operator moved to monitor or
	// deleted (kernel_policy_operator_override).
	Overrides []string `json:"overrides,omitempty"`
	// Warnings are the reason codes in force (tetragon_*, kernel_*).
	Warnings []string `json:"warnings,omitempty"`
	// UpdatedUnixNano is when the reconciler last wrote its state.
	UpdatedUnixNano int64 `json:"updated_unix_ns,omitempty"`
}

// KernelTetragon is the agent the reconciler talks to.
type KernelTetragon struct {
	Version   string `json:"version,omitempty"`
	Socket    string `json:"socket,omitempty"`
	PID       int    `json:"pid,omitempty"`
	Connected bool   `json:"connected"`
	// KeepSensorsOnExit and LSM are the GetInfo facts enforcement needs;
	// nil when unknown (Tetragon 1.6 has no GetInfo).
	KeepSensorsOnExit *bool `json:"keep_sensors_on_exit,omitempty"`
	LSM               *bool `json:"lsm,omitempty"`
}

// KernelPolicyStatus is one DefenseClaw policy.
type KernelPolicyStatus struct {
	Name   string `json:"name"`
	Family string `json:"family,omitempty"`
	Mode   string `json:"mode,omitempty"`
	State  string `json:"state,omitempty"`
	Error  string `json:"error,omitempty"`
	// Recorded is true when the helper's own state lists the name.
	Recorded bool `json:"recorded"`
}

// KernelUserStatus is one enrolled uid.
type KernelUserStatus struct {
	UID int `json:"uid"`
	// Mode is enforce, burnin, monitor or observe_only.
	Mode           string           `json:"mode,omitempty"`
	Ready          bool             `json:"ready"`
	CoveredSeconds int64            `json:"covered_seconds,omitempty"`
	BurnInSeconds  int64            `json:"burn_in_seconds,omitempty"`
	Hits           map[string]int64 `json:"hits,omitempty"`
	Connectors     []string         `json:"connectors,omitempty"`
	Reason         string           `json:"reason,omitempty"`
}

// KernelPause is the break-glass pause.
type KernelPause struct {
	UntilUnixNano int64  `json:"until_unix_ns,omitempty"`
	UntilReboot   bool   `json:"until_reboot,omitempty"`
	SetByUID      int    `json:"set_by_uid"`
	SetAtUnixNano int64  `json:"set_at_unix_ns,omitempty"`
	Reason        string `json:"reason,omitempty"`
}

// ErrVersionMismatch is returned when the peer speaks a different protocol.
var ErrVersionMismatch = errors.New("acquire: protocol version mismatch")

// writeFrame writes one length-prefixed JSON value.
func writeFrame(conn net.Conn, value any, deadline time.Duration) error {
	payload, err := json.Marshal(value)
	if err != nil {
		return fmt.Errorf("acquire: encode frame: %w", err)
	}
	if len(payload) > maxFrameBytes {
		return fmt.Errorf("acquire: frame of %d bytes exceeds the %d cap", len(payload), maxFrameBytes)
	}
	if deadline > 0 {
		_ = conn.SetWriteDeadline(time.Now().Add(deadline))
	}
	var header [4]byte
	header[0] = byte(len(payload) >> 24)
	header[1] = byte(len(payload) >> 16)
	header[2] = byte(len(payload) >> 8)
	header[3] = byte(len(payload))
	if _, err := conn.Write(header[:]); err != nil {
		return fmt.Errorf("acquire: write frame header: %w", err)
	}
	if _, err := conn.Write(payload); err != nil {
		return fmt.Errorf("acquire: write frame: %w", err)
	}
	return nil
}

// readFrame reads one length-prefixed JSON value into target.
func readFrame(conn net.Conn, target any, deadline time.Duration) error {
	if deadline > 0 {
		_ = conn.SetReadDeadline(time.Now().Add(deadline))
	}
	var header [4]byte
	if _, err := io.ReadFull(conn, header[:]); err != nil {
		return err
	}
	size := int(header[0])<<24 | int(header[1])<<16 | int(header[2])<<8 | int(header[3])
	if size < 0 || size > maxFrameBytes {
		// A declared length is peer-supplied. Allocating on it unchecked is
		// how a helper becomes the thing that kills the host.
		return fmt.Errorf("acquire: peer declared a %d byte frame, cap is %d", size, maxFrameBytes)
	}
	payload := make([]byte, size)
	if _, err := io.ReadFull(conn, payload); err != nil {
		return err
	}
	return json.Unmarshal(payload, target)
}

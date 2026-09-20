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
// A client may ask for exactly three things and may not describe any of
// them: the process table, the connection table, or the event stream. There
// is no path, no filter, no glob, no pid, and no command anywhere in a
// request. That is the whole security argument for putting a privileged
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

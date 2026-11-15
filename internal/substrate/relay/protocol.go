// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

// Package relay is defenseclaw-actor-relay: the terminal relay inside an
// Agent Substrate actor. Substrate ingress (atenet-router) carries HTTP and
// WebSocket but no raw TCP, and there is no exec or attach, so the launcher
// reaches the agent's terminal through this relay: a WebSocket PTY server
// that holds the agent in a tmux session surviving reconnects, suspends and
// resumes, with an HTTP long-poll fallback for networks that block WebSocket
// (E27) and a headless mode for --task runs.
//
// Protocol dcrelay/1. A WebSocket client asks for subprotocol "dcrelay.v1".
// Every message is binary: one type byte, then the payload.
//
//	0x01 DATA     terminal bytes (client: keystrokes; relay: screen output)
//	0x02 RESIZE   JSON {"cols":N,"rows":N}, client to relay
//	0x03 CONTROL  JSON Control, both ways
//
// The relay's first message is CONTROL hello (version, session, mode). A
// client ends an attachment with CONTROL detach (the agent keeps running) or
// by closing the socket; the relay sends CONTROL exit when the agent exits.
//
// The long-poll fallback carries the same frames, each prefixed with its
// length as a 4-byte big-endian integer:
//
//	POST /dcrelay/1/poll                   open an attachment -> {"id","cursor"}
//	GET  /dcrelay/1/poll/<id>?cursor=N     frames after cursor (waits up to 25 s);
//	                                       the new cursor is in X-Dcrelay-Cursor
//	POST /dcrelay/1/poll/<id>              frames from the client
//	DELETE /dcrelay/1/poll/<id>            detach
//
// Every route but /readyz needs a launcher session token bound to the
// person and to this actor (E2), in Authorization: Bearer, or for a
// WebSocket client that cannot set headers in a second subprotocol
// "dcrelay.token.<token>". A token never travels in a URL.
package relay

import (
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
)

// Protocol names.
const (
	Version       = "dcrelay/1"
	Subprotocol   = "dcrelay.v1"
	TokenProtocol = "dcrelay.token."
)

// Frame types.
const (
	FrameData    byte = 0x01
	FrameResize  byte = 0x02
	FrameControl byte = 0x03
)

// Control message types.
const (
	CtlHello  = "hello"
	CtlExit   = "exit"
	CtlError  = "error"
	CtlDetach = "detach"
	CtlPing   = "ping"
	CtlPong   = "pong"
	// CtlReset tells a long-poll client that output it had not read yet was
	// dropped; the relay has asked tmux to redraw the screen.
	CtlReset = "reset"
)

// Control is a CONTROL frame.
type Control struct {
	Type    string `json:"type"`
	Version string `json:"version,omitempty"`
	Session string `json:"session,omitempty"`
	Mode    string `json:"mode,omitempty"`
	Code    *int   `json:"code,omitempty"`
	Message string `json:"message,omitempty"`
}

// Resize is a RESIZE frame.
type Resize struct {
	Cols uint16 `json:"cols"`
	Rows uint16 `json:"rows"`
}

// MaxFrame bounds one frame.
const MaxFrame = 1 << 20

// Encode returns one frame.
func Encode(t byte, payload []byte) []byte {
	out := make([]byte, 1+len(payload))
	out[0] = t
	copy(out[1:], payload)
	return out
}

// EncodeControl returns a CONTROL frame.
func EncodeControl(c Control) []byte {
	b, _ := json.Marshal(c)
	return Encode(FrameControl, b)
}

// Decode splits a frame.
func Decode(frame []byte) (byte, []byte, error) {
	if len(frame) == 0 {
		return 0, nil, errors.New("dcrelay: empty frame")
	}
	if len(frame) > MaxFrame+1 {
		return 0, nil, errors.New("dcrelay: frame too large")
	}
	switch frame[0] {
	case FrameData, FrameResize, FrameControl:
		return frame[0], frame[1:], nil
	}
	return 0, nil, fmt.Errorf("dcrelay: unknown frame type 0x%02x", frame[0])
}

// DecodeResize parses a RESIZE payload.
func DecodeResize(p []byte) (Resize, error) {
	var r Resize
	if err := json.Unmarshal(p, &r); err != nil {
		return r, fmt.Errorf("dcrelay: resize: %w", err)
	}
	if r.Cols == 0 || r.Rows == 0 || r.Cols > 1000 || r.Rows > 1000 {
		return r, fmt.Errorf("dcrelay: resize %dx%d out of range", r.Cols, r.Rows)
	}
	return r, nil
}

// DecodeControl parses a CONTROL payload.
func DecodeControl(p []byte) (Control, error) {
	var c Control
	if err := json.Unmarshal(p, &c); err != nil {
		return c, fmt.Errorf("dcrelay: control: %w", err)
	}
	return c, nil
}

// AppendStream appends a length-prefixed frame (the long-poll encoding).
func AppendStream(dst []byte, frame []byte) []byte {
	var n [4]byte
	binary.BigEndian.PutUint32(n[:], uint32(len(frame)))
	return append(append(dst, n[:]...), frame...)
}

// SplitStream splits a long-poll body into frames.
func SplitStream(b []byte) ([][]byte, error) {
	var out [][]byte
	for len(b) > 0 {
		if len(b) < 4 {
			return nil, errors.New("dcrelay: truncated stream")
		}
		n := binary.BigEndian.Uint32(b[:4])
		if n == 0 || n > MaxFrame+1 || int(n) > len(b)-4 {
			return nil, errors.New("dcrelay: bad stream frame length")
		}
		out = append(out, b[4:4+n])
		b = b[4+n:]
	}
	return out, nil
}

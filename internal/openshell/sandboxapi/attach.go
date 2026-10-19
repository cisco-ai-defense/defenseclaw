// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package sandboxapi

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"regexp"
)

const (
	AttachVersion    = 1
	AttachFrameBytes = 32 << 10
	AttachDataBytes  = 16 << 10
)

var ErrAttachProtocol = errors.New("invalid sandbox attachment frame")
var attachID = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$`)

// AttachRequest selects one already admitted process using its immutable host
// session ID. It contains no argv, environment, executable or launch authority.
// TimeoutSeconds can only shorten the manager's existing execution lifetime.
type AttachRequest struct {
	Version        uint16 `json:"version"`
	SessionID      string `json:"session_id"`
	TimeoutSeconds uint32 `json:"timeout_seconds"`
}

func (r AttachRequest) Validate() error {
	if r.Version != AttachVersion || !attachID.MatchString(r.SessionID) || r.TimeoutSeconds == 0 || r.TimeoutSeconds > 24*60*60 {
		return ErrAttachProtocol
	}
	return nil
}

// AttachInput is literal bounded binary stdin, EOF, terminal geometry or
// cancellation. The manager must separately admit terminal operations and
// reject repeated EOF, input after EOF and any operation after exit.
type AttachInput struct {
	Kind    string `json:"kind"`
	Data    []byte `json:"data,omitempty"`
	Rows    uint16 `json:"rows,omitempty"`
	Columns uint16 `json:"columns,omitempty"`
}

func (f AttachInput) Validate() error {
	switch f.Kind {
	case "stdin":
		if len(f.Data) == 0 || len(f.Data) > AttachDataBytes || f.Rows != 0 || f.Columns != 0 {
			return ErrAttachProtocol
		}
	case "stdin_eof", "cancel":
		if f.Data != nil || f.Rows != 0 || f.Columns != 0 {
			return ErrAttachProtocol
		}
	case "resize":
		if f.Data != nil || f.Rows == 0 || f.Columns == 0 || f.Rows > 1000 || f.Columns > 1000 {
			return ErrAttachProtocol
		}
	default:
		return ErrAttachProtocol
	}
	return nil
}

type AttachExit struct {
	Code      int32 `json:"code"`
	TimedOut  bool  `json:"timed_out"`
	Truncated bool  `json:"truncated"`
}

// AttachEvent carries output or a single terminal exit observation. Failure
// frames use fixed codes, never provider diagnostics, paths or credentials.
type AttachEvent struct {
	Kind string      `json:"kind"`
	Data []byte      `json:"data,omitempty"`
	Exit *AttachExit `json:"exit,omitempty"`
	Code string      `json:"code,omitempty"`
}

func (f AttachEvent) Validate() error {
	switch f.Kind {
	case "stdout", "stderr":
		if len(f.Data) == 0 || len(f.Data) > AttachDataBytes || f.Exit != nil || f.Code != "" {
			return ErrAttachProtocol
		}
	case "exit":
		if f.Data != nil || f.Exit == nil || f.Code != "" {
			return ErrAttachProtocol
		}
	case "failure":
		if f.Data != nil || f.Exit != nil || (f.Code != "unavailable" && f.Code != "invalid_request" && f.Code != "stream_failed") {
			return ErrAttachProtocol
		}
	default:
		return ErrAttachProtocol
	}
	return nil
}

// decodeAttach refuses duplicate, unknown and case-aliased top-level keys,
// trailing values and oversize frames before typed decoding. Client frames have
// no nested objects. Binary input is JSON base64; it is never treated as text.
func decodeAttach(raw []byte, keys map[string]bool, target any) error {
	if len(raw) == 0 || len(raw) > AttachFrameBytes {
		return ErrAttachProtocol
	}
	d := json.NewDecoder(bytes.NewReader(raw))
	start, err := d.Token()
	if err != nil || start != json.Delim('{') {
		return ErrAttachProtocol
	}
	seen := map[string]bool{}
	for d.More() {
		token, err := d.Token()
		key, ok := token.(string)
		if err != nil || !ok || !keys[key] || seen[key] {
			return ErrAttachProtocol
		}
		seen[key] = true
		var value json.RawMessage
		if d.Decode(&value) != nil {
			return ErrAttachProtocol
		}
	}
	if end, err := d.Token(); err != nil || end != json.Delim('}') {
		return ErrAttachProtocol
	}
	if d.Decode(new(any)) != io.EOF {
		return ErrAttachProtocol
	}
	d = json.NewDecoder(bytes.NewReader(raw))
	d.DisallowUnknownFields()
	if d.Decode(target) != nil {
		return ErrAttachProtocol
	}
	return nil
}

func DecodeAttachRequest(raw []byte) (AttachRequest, error) {
	var value AttachRequest
	if err := decodeAttach(raw, map[string]bool{"version": true, "session_id": true, "timeout_seconds": true}, &value); err != nil {
		return value, err
	}
	return value, value.Validate()
}

func DecodeAttachInput(raw []byte) (AttachInput, error) {
	var value AttachInput
	if err := decodeAttach(raw, map[string]bool{"kind": true, "data": true, "rows": true, "columns": true}, &value); err != nil {
		return value, err
	}
	return value, value.Validate()
}

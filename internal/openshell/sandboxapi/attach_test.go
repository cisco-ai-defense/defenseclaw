// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package sandboxapi

import (
	"bytes"
	"encoding/json"
	"testing"
)

func TestAttachmentClientFramesRefuseAmbiguousLaunchAndOversizeInput(t *testing.T) {
	valid := []byte(`{"version":1,"session_id":"owned:session-1","timeout_seconds":60}`)
	if _, err := DecodeAttachRequest(valid); err != nil {
		t.Fatal(err)
	}
	for _, raw := range []string{
		`{"version":1,"session_id":"owned","session_id":"other","timeout_seconds":60}`,
		`{"Version":1,"session_id":"owned","timeout_seconds":60}`,
		`{"version":1,"session_id":"owned","timeout_seconds":60,"argv":["host-command"]}`,
		`{"version":1,"session_id":"owned","timeout_seconds":60} {}`,
		`{"version":1,"session_id":"owned","timeout_seconds":86401}`,
		`{"version":1,"session_id":"../other","timeout_seconds":60}`,
		`{"version":1,"session_id":"owned","timeout_seconds":0}`,
	} {
		if _, err := DecodeAttachRequest([]byte(raw)); err == nil {
			t.Fatalf("accepted %s", raw)
		}
	}
	binary := []byte{0, 0xff, '\n', 0xc0}
	raw, _ := json.Marshal(AttachInput{Kind: "stdin", Data: binary})
	frame, err := DecodeAttachInput(raw)
	if err != nil || !bytes.Equal(frame.Data, binary) {
		t.Fatalf("binary changed: %v", err)
	}
	for _, frame := range []AttachInput{
		{Kind: "stdin", Data: make([]byte, AttachDataBytes+1)}, {Kind: "stdin_eof", Data: []byte{}},
		{Kind: "resize", Rows: 1, Columns: 1001}, {Kind: "cancel", Rows: 1}, {Kind: "launch"},
	} {
		if frame.Validate() == nil {
			t.Fatalf("invalid frame accepted: %s", frame.Kind)
		}
	}
	for _, raw := range []string{`{"kind":"stdin_eof","kind":"cancel"}`, `{"Kind":"cancel"}`, `{"kind":"cancel","env":{}}`} {
		if _, err := DecodeAttachInput([]byte(raw)); err == nil {
			t.Fatalf("ambiguous frame accepted: %s", raw)
		}
	}
	if _, err := DecodeAttachInput(bytes.Repeat([]byte{' '}, AttachFrameBytes+1)); err == nil {
		t.Fatal("oversize input accepted")
	}
}

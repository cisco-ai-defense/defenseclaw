// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package hookexec

import (
	"strings"
	"testing"
)

func TestReadNativeHookFrameKeepsFieldsAndRejectsMalformedInput(t *testing.T) {
	const body = `{"tool_input":{"command":"echo quote \\\" and slash \\ and newline\\n"}}`
	fields := []string{"DCPOST1", "/api/v1/claude-code/hook", body,
		"Content-Type", "application/json", "X-DefenseClaw-Note", `quote " and slash \\`,
		"Authorization", "Bearer secret-token", ""}
	wire := []byte(strings.Join(fields, "\x00"))
	request, err := ReadNativeHookFrame(wire)
	if err != nil {
		t.Fatal(err)
	}
	if request.Path != fields[1] || request.Body != body ||
		request.Headers["Content-Type"] != "application/json" ||
		request.Headers["X-DefenseClaw-Note"] != fields[6] ||
		request.Headers["Authorization"] != "Bearer secret-token" {
		t.Fatalf("native frame changed fields: %+v", request)
	}
	for _, bad := range [][]byte{
		[]byte("DCPOST1\x00/api/v1/claude-code/hook\x00body"),
		[]byte("DCPOST1\x00/api/v1/claude-code/hook\x00body\x00Authorization\x00"),
		[]byte("DCPOST1\x00/api/v1/claude-code/hook\x00body\x00Bad Header\x00value\x00"),
		[]byte("DCPOST1\x00/api/v1/claude-code/hook\x00body\x00X-Header\x00value\r\nmore\x00"),
	} {
		if _, err := ReadNativeHookFrame(bad); err == nil {
			t.Errorf("accepted malformed native frame %q", bad)
		}
	}
}

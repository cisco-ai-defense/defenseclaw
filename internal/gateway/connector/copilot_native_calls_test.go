// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package connector

import (
	"strings"
	"testing"
)

func TestCopilotNativeSinglePatchCallDecode(t *testing.T) {
	patch := "*** Begin Patch\n*** Add File: notes07-default.txt\n+T9 default benign edit.\n*** End Patch\n"
	got := copilotProfileDecode(map[string]any{
		"cwd": "/home/eng1/project", "sessionId": "native-session",
		"toolCalls": []any{map[string]any{"id": "custom_call_native", "name": "apply_patch", "args": patch}},
	})
	if got.ToolName != "apply_patch" || !got.ToolArgsAuthoritative ||
		!strings.Contains(string(got.ToolArgs), `"patch"`) || !strings.Contains(string(got.ToolArgs), "notes07-default.txt") {
		t.Fatalf("native toolCalls patch not decoded: %+v", got)
	}
}

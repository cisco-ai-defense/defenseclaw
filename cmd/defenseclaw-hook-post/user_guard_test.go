// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"strings"
	"testing"
)

// The guard-user-hook decision tests are in user_guard_unix_test.go (S8 B2:
// the native hook runs in this process).

func TestGAP0322UserGuardCursorTwin(t *testing.T) {
	var out, errOut bytes.Buffer
	if code := runMain(nil, strings.NewReader(`{"cursor_version":"1"}`), &out, &errOut); code != 0 ||
		out.Len() != 0 || errOut.Len() != 0 {
		t.Fatalf("argument-free imported hook: exit %d, stdout %q, stderr %q", code, out.String(), errOut.String())
	}
	out.Reset()
	errOut.Reset()
	if code := runMain(nil, strings.NewReader(`{"hook_event_name":"PreToolUse","tool_input":{"command":"echo ok"}}`), &out, &errOut); code != 2 {
		t.Fatalf("argument-free Claude hook: exit %d, stdout %q, stderr %q", code, out.String(), errOut.String())
	}
}

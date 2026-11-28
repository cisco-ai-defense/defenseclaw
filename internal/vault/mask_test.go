// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package vault

import (
	"bytes"
	"strings"
	"testing"
)

func TestMaskCapturableKeepsLengthAndFraming(t *testing.T) {
	key := fakeAnthropic()
	// JSON with the key after an escaped newline, and a protobuf-like
	// length-prefixed string.
	in := []byte(`{"prompt":"my key:\n` + key + `"}` + "\x0a\x3c" + fakeGitHub())
	out, changed := MaskCapturable(in)
	if !changed || len(out) != len(in) {
		t.Fatalf("changed=%v len %d->%d", changed, len(in), len(out))
	}
	if bytes.Contains(out, []byte(key)) || bytes.Contains(out, []byte(fakeGitHub())) {
		t.Fatalf("a value survived: %q", out)
	}
	if !bytes.Contains(out, []byte(`\nsk-ant-***`)) || !bytes.Contains(out, []byte("ghp_****")) {
		t.Fatalf("prefixes not kept: %q", out)
	}
	if _, changed := MaskCapturable([]byte("sk-" + strings.Repeat("x", 40) + " task-runner disk-usage")); changed {
		t.Fatal("a placeholder or an ordinary word was masked")
	}
}

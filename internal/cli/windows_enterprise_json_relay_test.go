// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"bytes"
	"strings"
	"testing"
)

func TestWindowsEnterpriseJSONRelayKeepsStdoutOneResult(t *testing.T) {
	var stdout, stderr bytes.Buffer
	relay := newWindowsEnterpriseJSONRelay(&stdout, &stderr)
	child := "WARNING: reconciling existing installation in place\r\n" +
		"WARNING: defenseclaw_degraded reason=\"{\\\"error\\\":\\\"x\\\"}\"\r\n" +
		`{"schema_version":1,"ok":true,"action":"install"}` + "\r\n"
	for _, chunk := range []string{child[:20], child[20:70], child[70:]} {
		_, _ = relay.Write([]byte(chunk))
	}
	relay.Finish()
	if got := strings.TrimSpace(stdout.String()); got != `{"schema_version":1,"ok":true,"action":"install"}` {
		t.Fatalf("stdout = %q, want only the result object", got)
	}
	if !strings.Contains(stderr.String(), "reconciling existing installation") ||
		!strings.Contains(stderr.String(), "defenseclaw_degraded") {
		t.Fatalf("stderr = %q, want the warnings", stderr.String())
	}
}

func TestWindowsEnterpriseJSONRelayPassesThroughOutputWithoutJSON(t *testing.T) {
	var stdout, stderr bytes.Buffer
	relay := newWindowsEnterpriseJSONRelay(&stdout, &stderr)
	_, _ = relay.Write([]byte("plain text\n"))
	relay.Finish()
	if stdout.String() != "plain text\n" || stderr.Len() != 0 {
		t.Fatalf("stdout = %q, stderr = %q", stdout.String(), stderr.String())
	}
}

func TestWindowsEnterpriseJSONRelaySpillsOldOutputToStderr(t *testing.T) {
	var stdout, stderr bytes.Buffer
	relay := newWindowsEnterpriseJSONRelay(&stdout, &stderr)
	line := strings.Repeat("x", 1023) + "\n"
	for written := 0; written < windowsEnterpriseJSONRelayMax+64*1024; written += len(line) {
		_, _ = relay.Write([]byte(line))
	}
	_, _ = relay.Write([]byte(`{"schema_version":1,"ok":false,"error":"e"}` + "\n"))
	relay.Finish()
	if got := strings.TrimSpace(stdout.String()); got != `{"schema_version":1,"ok":false,"error":"e"}` {
		t.Fatalf("stdout = %.80q", got)
	}
	if stderr.Len() < windowsEnterpriseJSONRelayMax {
		t.Fatalf("stderr = %d bytes, want the spilled output", stderr.Len())
	}
}

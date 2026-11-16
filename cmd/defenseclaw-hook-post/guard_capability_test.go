// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"strings"
	"testing"
)

func TestGAP0322UserGuardCapabilityAndVersionTwin(t *testing.T) {
	var out, errOut bytes.Buffer
	if code := runMain([]string{"--guard-user-hook-capability"}, strings.NewReader(""), &out, &errOut); code != 0 ||
		out.String() != "defenseclaw-hook-post guard-user-hook v1\n" || errOut.Len() != 0 {
		t.Fatalf("capability: exit %d, stdout %q, stderr %q", code, out.String(), errOut.String())
	}
	out.Reset()
	errOut.Reset()
	if code := runMain([]string{"--guard-user-hook-capability", "extra"}, strings.NewReader(""), &out, &errOut); code == 0 {
		t.Fatal("extra capability argument was accepted")
	}
	out.Reset()
	errOut.Reset()
	if code := runMain([]string{"--version"}, strings.NewReader(""), &out, &errOut); code != 0 ||
		!strings.HasPrefix(out.String(), "defenseclaw-hook-post version ") || errOut.Len() != 0 {
		t.Fatalf("version twin: exit %d, stdout %q, stderr %q", code, out.String(), errOut.String())
	}
}

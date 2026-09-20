// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build darwin

package notify

import (
	"strings"
	"testing"
)

func TestDarwinBackendEscapesStringsAndPreservesUnicode(t *testing.T) {
	oldRun := osascriptRun
	defer func() { osascriptRun = oldRun }()

	var got []string
	osascriptRun = func(args ...string) error {
		got = append([]string(nil), args...)
		return nil
	}
	err := sendPlatform(Notification{Title: `Defense "Claw"`, Subtitle: "guardrail · HIGH", Body: "阻止 <redacted>"})
	if err != nil {
		t.Fatalf("sendPlatform: %v", err)
	}
	if len(got) != 2 || got[0] != "-e" {
		t.Fatalf("osascript args = %#v", got)
	}
	for _, want := range []string{`Defense \"Claw\"`, "guardrail · HIGH", "阻止 <redacted>"} {
		if !strings.Contains(got[1], want) {
			t.Fatalf("script %q does not contain %q", got[1], want)
		}
	}
}

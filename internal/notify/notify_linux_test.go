// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package notify

import (
	"reflect"
	"testing"
)

func TestLinuxBackendPreservesArgvAndFoldsSubtitle(t *testing.T) {
	oldLookPath, oldRun := notifySendLookPath, notifySendRun
	defer func() { notifySendLookPath, notifySendRun = oldLookPath, oldRun }()

	notifySendLookPath = func(name string) (string, error) {
		if name != "notify-send" {
			t.Fatalf("lookup = %q", name)
		}
		return "/usr/bin/notify-send", nil
	}
	var gotPath string
	var gotArgs []string
	notifySendRun = func(path string, args ...string) error {
		gotPath = path
		gotArgs = append([]string(nil), args...)
		return nil
	}

	err := sendPlatform(Notification{Title: "DefenseClaw", Subtitle: "guardrail · HIGH", Body: "阻止 <redacted>"})
	if err != nil {
		t.Fatalf("sendPlatform: %v", err)
	}
	if gotPath != "/usr/bin/notify-send" {
		t.Fatalf("path = %q", gotPath)
	}
	want := []string{"DefenseClaw", "guardrail · HIGH — 阻止 <redacted>"}
	if !reflect.DeepEqual(gotArgs, want) {
		t.Fatalf("args = %#v, want %#v", gotArgs, want)
	}
}

// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package notify

import (
	"errors"
	"os"
	"testing"
	"unicode/utf16"
)

func TestWindowsBackendUsesNativeBroker(t *testing.T) {
	old := windowsBalloonSend
	defer func() { windowsBalloonSend = old }()
	wantErr := errors.New("explorer unavailable")
	windowsBalloonSend = func(n Notification) error {
		if n.Title != "DefenseClaw" || n.Body != "test" {
			t.Fatalf("notification = %#v", n)
		}
		return wantErr
	}
	if err := sendPlatform(Notification{Title: "DefenseClaw", Body: "test"}); !errors.Is(err, wantErr) {
		t.Fatalf("sendPlatform error = %v, want %v", err, wantErr)
	}
}

func TestCopyWindowsNotificationTextTruncatesOnRuneBoundaryAndReplacesNUL(t *testing.T) {
	dst := make([]uint16, 6)
	copyWindowsNotificationText(dst, "A\x00😀BC")
	if dst[len(dst)-1] != 0 {
		t.Fatalf("destination is not NUL terminated: %#v", dst)
	}
	got := string(utf16.Decode(dst[:len(dst)-1]))
	if got != "A�😀B" {
		t.Fatalf("copy result = %q (%#v), want %q", got, dst, "A�😀B")
	}
}

func TestWindowsNotificationInfoFlags(t *testing.T) {
	if got := windowsNotificationInfoFlags(Notification{Subtitle: "guardrail · HIGH"}); got != niifWarning {
		t.Fatalf("HIGH flags = %#x, want warning", got)
	}
	if got := windowsNotificationInfoFlags(Notification{Body: "service reconnected"}); got != niifInfo {
		t.Fatalf("informational flags = %#x, want info", got)
	}
}

func TestWindowsNativeNotificationLiveOptIn(t *testing.T) {
	if os.Getenv("DEFENSECLAW_TEST_WINDOWS_NOTIFICATION") != "1" {
		t.Skip("set DEFENSECLAW_TEST_WINDOWS_NOTIFICATION=1 for attended native delivery")
	}
	if err := defaultWindowsBalloonBroker.send(Notification{
		Title:    "DefenseClaw Windows validation",
		Subtitle: "native notification broker",
		Body:     "The signed gateway can deliver attended Windows security notifications.",
	}); err != nil {
		t.Fatalf("native Windows notification failed: %v", err)
	}
}

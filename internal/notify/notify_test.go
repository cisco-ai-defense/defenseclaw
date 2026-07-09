// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
// SPDX-License-Identifier: Apache-2.0

package notify

import (
	"bytes"
	"errors"
	"strings"
	"testing"
)

func TestDesktopCapabilityForGOOS(t *testing.T) {
	tests := []struct {
		goos      string
		supported bool
		provider  string
	}{
		{goos: "darwin", supported: true, provider: "osascript"},
		{goos: "linux", supported: true, provider: "notify-send"},
		{goos: "windows", supported: false},
		{goos: "plan9", supported: false},
	}
	for _, tc := range tests {
		t.Run(tc.goos, func(t *testing.T) {
			got := DesktopCapabilityForGOOS(tc.goos)
			if got.Supported != tc.supported || got.Provider != tc.provider {
				t.Fatalf("DesktopCapabilityForGOOS(%q) = %#v", tc.goos, got)
			}
			if !got.Supported && got.UnsupportedReason == "" {
				t.Fatal("unsupported capability must explain why")
			}
		})
	}
}

func TestUnsupportedPlatformSkipsNativeSenderAndLabelsTerminalFallback(t *testing.T) {
	var buf bytes.Buffer
	old := fallbackWriter
	fallbackWriter = &buf
	defer func() { fallbackWriter = old }()

	called := false
	err := sendNotification(
		Notification{Title: "DefenseClaw", Subtitle: "guardrail · HIGH", Body: "阻止 <redacted>"},
		DesktopCapabilityForGOOS("windows"),
		func(Notification) error {
			called = true
			return nil
		},
	)
	if !errors.Is(err, ErrDesktopUnsupported) {
		t.Fatalf("error = %v, want ErrDesktopUnsupported", err)
	}
	if called {
		t.Fatal("unsupported Windows capability invoked native sender")
	}
	got := buf.String()
	for _, want := range []string{"[defenseclaw terminal fallback]", "guardrail · HIGH", "阻止 <redacted>"} {
		if !strings.Contains(got, want) {
			t.Fatalf("fallback %q does not contain %q", got, want)
		}
	}
}

func TestSupportedPlatformFailureLabelsTerminalFallback(t *testing.T) {
	var buf bytes.Buffer
	old := fallbackWriter
	fallbackWriter = &buf
	defer func() { fallbackWriter = old }()

	err := sendNotification(Notification{
		Title:    "DefenseClaw",
		Subtitle: "guardrail · HIGH",
		Body:     "blocked tool call",
	}, DesktopCapabilityForGOOS("linux"), func(Notification) error {
		return errors.New("display server missing")
	})
	if err == nil {
		t.Fatal("expected sender failure")
	}
	if got := buf.String(); !strings.Contains(got, "[defenseclaw terminal fallback]") ||
		!strings.Contains(got, "guardrail · HIGH") {
		t.Fatalf("expected labelled fallback with subtitle, got %q", got)
	}
}

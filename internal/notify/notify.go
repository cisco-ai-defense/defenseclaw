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

// Package notify provides cross-platform desktop notification support
// for DefenseClaw.
//
// Two entry points are exposed:
//
//   - Send(title, message): the historical two-arg form used by the
//     watchdog. It maps directly onto a Notification with no subtitle.
//
//   - SendNotification(Notification): the richer form used by the
//     gateway notifier dispatcher. It exposes a subtitle so block /
//     would-block / approval-pending UX can render the source and
//     severity inline without packing them into the body string.
//
// Platform-native delivery happens in sendPlatform (osascript on
// macOS, notify-send on Linux); on platforms without sendPlatform the
// package falls back to writing a structured line on fallbackWriter.
package notify

import "fmt"

// Notification is a structured, multi-line desktop notification.
// All fields are optional; empty Title/Subtitle/Body are skipped by
// the platform back-ends so callers do not need to gate empty values.
type Notification struct {
	Title    string
	Subtitle string
	Body     string
}

// Send sends a desktop notification with the given title and body.
// Retained as a thin wrapper for the watchdog which has historically
// called Send(title, message). New callers should use
// SendNotification with a structured Notification value.
func Send(title, message string) error {
	return SendNotification(Notification{Title: title, Body: message})
}

// SendNotification delivers a structured Notification through the
// platform-native channel. On failure it emits a single fallback line
// to fallbackWriter that includes title/subtitle/body so operators
// running with no display server still see what would have been
// shown.
func SendNotification(n Notification) error {
	if err := sendPlatform(n); err != nil {
		fmt.Fprintf(fallbackWriter, "[defenseclaw] %s%s: %s\n",
			n.Title, formatSubtitle(n.Subtitle), n.Body)
		return err
	}
	return nil
}

func formatSubtitle(subtitle string) string {
	if subtitle == "" {
		return ""
	}
	return " (" + subtitle + ")"
}

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
// Platform-native delivery happens in sendPlatform (osascript on macOS,
// notify-send on Linux, and an in-process Shell_NotifyIconW broker on
// Windows); on platforms without sendPlatform the package falls back to
// writing a structured line on fallbackWriter.
package notify

import (
	"errors"
	"fmt"
	"runtime"
	"strings"
)

// ErrDesktopUnsupported is returned when the current platform has no native
// desktop notification implementation. Callers may still receive the message
// through the explicitly labelled terminal fallback.
var ErrDesktopUnsupported = errors.New("native desktop notifications are unsupported")

// DesktopNotificationCapability is the authoritative platform capability for
// the native desktop delivery route. Configured state is intentionally kept
// separate: a legacy Windows config may say enabled while effective delivery
// remains inactive.
type DesktopNotificationCapability struct {
	GOOS              string
	Supported         bool
	Provider          string
	UnsupportedReason string
}

// DesktopCapabilityForGOOS resolves native desktop notification support for a
// platform. Keeping the GOOS input explicit makes status and dispatcher tests
// deterministic without changing the host OS.
func DesktopCapabilityForGOOS(goos string) DesktopNotificationCapability {
	goos = strings.ToLower(strings.TrimSpace(goos))
	switch goos {
	case "darwin":
		return DesktopNotificationCapability{GOOS: goos, Supported: true, Provider: "osascript"}
	case "linux":
		return DesktopNotificationCapability{GOOS: goos, Supported: true, Provider: "notify-send"}
	case "windows":
		return DesktopNotificationCapability{GOOS: goos, Supported: true, Provider: "Shell_NotifyIconW"}
	default:
		return DesktopNotificationCapability{
			GOOS:              goos,
			UnsupportedReason: "native desktop notifications are not supported on this platform",
		}
	}
}

// DesktopCapability returns the native desktop capability of this process.
func DesktopCapability() DesktopNotificationCapability {
	return DesktopCapabilityForGOOS(runtime.GOOS)
}

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
	return sendNotification(n, DesktopCapability(), sendPlatform)
}

func sendNotification(
	n Notification,
	capability DesktopNotificationCapability,
	sender func(Notification) error,
) error {
	var err error
	if !capability.Supported {
		err = fmt.Errorf("%w: %s", ErrDesktopUnsupported, capability.UnsupportedReason)
	} else {
		err = sender(n)
	}
	if err != nil {
		fmt.Fprintf(fallbackWriter, "[defenseclaw terminal fallback] %s%s: %s\n",
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

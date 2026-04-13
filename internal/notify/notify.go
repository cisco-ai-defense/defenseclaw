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
// for the DefenseClaw watchdog.
package notify

import "fmt"

// Send sends a desktop notification with the given title and message.
// It uses the platform-native notification mechanism (osascript on macOS,
// notify-send on Linux) and falls back to stderr on unsupported platforms.
func Send(title, message string) error {
	if err := sendPlatform(title, message); err != nil {
		fmt.Fprintf(fallbackWriter, "[defenseclaw-watchdog] %s: %s\n", title, message)
		return err
	}
	return nil
}

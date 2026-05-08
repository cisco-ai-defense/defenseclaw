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

//go:build linux

package notify

import (
	"io"
	"os"
	"os/exec"
)

var fallbackWriter io.Writer = os.Stderr

// sendPlatform delivers the notification via libnotify's notify-send
// CLI. notify-send has no native subtitle field, so when one is set
// it is folded into the body separated by an em-dash. The fallback
// writer in notify.go already preserves the structured form for
// non-display environments.
func sendPlatform(n Notification) error {
	path, err := exec.LookPath("notify-send")
	if err != nil {
		return err
	}
	body := n.Body
	if n.Subtitle != "" {
		if body == "" {
			body = n.Subtitle
		} else {
			body = n.Subtitle + " — " + body
		}
	}
	return exec.Command(path, n.Title, body).Run()
}

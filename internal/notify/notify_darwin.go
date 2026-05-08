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

//go:build darwin

package notify

import (
	"encoding/json"
	"io"
	"os"
	"os/exec"
)

var fallbackWriter io.Writer = os.Stderr

// sendPlatform delivers the notification via osascript's
// "display notification" verb. JSON encoding is used to safely escape
// every field for embedding in the AppleScript string literals so
// payload content (verdict reason, tool name, etc.) cannot break out
// of the script — json.Marshal already produces a quoted string with
// quotes, backslashes, and newlines escaped.
func sendPlatform(n Notification) error {
	body, _ := json.Marshal(n.Body)
	title, _ := json.Marshal(n.Title)
	script := "display notification " + string(body) + " with title " + string(title)
	if n.Subtitle != "" {
		subtitle, _ := json.Marshal(n.Subtitle)
		script += " subtitle " + string(subtitle)
	}
	return exec.Command("osascript", "-e", script).Run()
}

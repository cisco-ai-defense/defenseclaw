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
	"io"
	"os"
	"os/exec"
	"strings"
)

var fallbackWriter io.Writer = os.Stderr
var osascriptRun = func(args ...string) error {
	return exec.Command("osascript", args...).Run()
}

// appleScriptQuote produces a quoted AppleScript string literal.
// AppleScript only recognizes \" and \\ inside double-quoted strings;
// json.Marshal's \u003c / \u003e escapes for angle brackets are not
// understood by the AppleScript lexer and cause syntax errors when the
// notification body contains <redacted …> markers.
func appleScriptQuote(s string) string {
	s = strings.ReplaceAll(s, `\`, `\\`)
	s = strings.ReplaceAll(s, `"`, `\"`)
	s = strings.ReplaceAll(s, "\n", "\\n")
	return `"` + s + `"`
}

// sendPlatform delivers the notification via osascript's
// "display notification" verb.
func sendPlatform(n Notification) error {
	script := "display notification " + appleScriptQuote(n.Body) + " with title " + appleScriptQuote(n.Title)
	if n.Subtitle != "" {
		script += " subtitle " + appleScriptQuote(n.Subtitle)
	}
	return osascriptRun("-e", script)
}

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

func sendPlatform(title, message string) error {
	// Use JSON encoding to safely escape all special characters (quotes,
	// backslashes, newlines) for embedding in the AppleScript string literal.
	// json.Marshal produces a quoted string with all metacharacters escaped;
	// we use it directly as an AppleScript string value.
	safeMsg, _ := json.Marshal(message)
	safeTitle, _ := json.Marshal(title)
	script := `display notification ` + string(safeMsg) + ` with title ` + string(safeTitle)
	return exec.Command("osascript", "-e", script).Run()
}

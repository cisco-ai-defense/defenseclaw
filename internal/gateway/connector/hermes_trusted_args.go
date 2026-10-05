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

package connector

import (
	"encoding/json"
	"strings"
)

// HermesTrustedShellArgs projects a Hermes process tool call that sends text
// to a background process's stdin (action "write" or "submit", the text in
// data) onto the {"command": ...} shell shape, so the text is judged as a
// shell command: the background process the terminal tool started is often
// a shell, and unprojected the call had no command facts, so a CRITICAL
// command rule allowed it. The other actions (list, poll, log, wait, kill,
// close) send nothing and are left alone, as is a call whose keys repeat.
func HermesTrustedShellArgs(toolName string, args json.RawMessage) (json.RawMessage, bool) {
	if strings.TrimSpace(toolName) != "process" || antigravityValidateUniqueJSON(args) != nil {
		return args, false
	}
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(args, &fields); err != nil || fields == nil {
		return args, false
	}
	var action, data string
	if raw, ok := fields["action"]; !ok || json.Unmarshal(raw, &action) != nil || (action != "write" && action != "submit") {
		return args, false
	}
	if raw, ok := fields["data"]; !ok || json.Unmarshal(raw, &data) != nil || strings.TrimSpace(data) == "" {
		return args, false
	}
	out, err := encodeTrustedShellArgs(map[string]string{"command": data})
	if err != nil {
		return args, false
	}
	return out, true
}

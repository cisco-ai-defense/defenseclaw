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

	"github.com/defenseclaw/defenseclaw/internal/antigravityargs"
)

// AntigravityTrustedShellArgs projects the arguments of an agy run_command
// (or send_command_input) call onto the {"CommandLine": ...} shape the
// trusted-action parser proves, and returns the call's Cwd separately as the
// command's working directory (antigravityargs.TrustedShellArgs, which the
// hook client reads the call through too, so a managed gateway is given the
// targets of the call it judges: rel-1-0-10:GAP-1132).
func AntigravityTrustedShellArgs(toolName string, args json.RawMessage) (projected json.RawMessage, cwd string, ok bool) {
	return antigravityargs.TrustedShellArgs(toolName, args)
}

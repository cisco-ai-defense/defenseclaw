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

package actionfacts

// shellCommandText is the command text of a shell call: the explicit
// Input.Command, else the command of the exact execution-tool argument schema,
// which is the text Analyze itself parses. Hook calls carry the command only in
// Args, so a projection that reads Input.Command alone abstains on every real
// call while it fires on the same text handed over as Command.
func shellCommandText(input Input) string {
	if input.Command != "" {
		return input.Command
	}
	if len(input.Argv) != 0 || len(input.Args) == 0 || !argsExecutionTool(input.Tool) {
		return ""
	}
	extracted := extractArgsForTool(input.Args, input.Tool)
	if extracted.status != StatusComplete || len(extracted.issues) != 0 || len(extracted.argv) != 0 {
		return ""
	}
	return extracted.command
}

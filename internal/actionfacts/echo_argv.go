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

import "strings"

// StaticPOSIXEchoStdoutSegments returns the byte-exact output of a direct
// POSIX shell-builtin echo invocation. POSIX leaves option-looking first
// operands and backslash-containing operands implementation-defined, so the
// proof deliberately excludes both families rather than selecting one
// shell's behavior. The remaining portable form joins operands with one space
// and appends one newline.
func StaticPOSIXEchoStdoutSegments(command CommandFact) []StaticOutputSegment {
	if command.Dialect != DialectPOSIX || command.Effect != EffectExecute ||
		!command.ArgvComplete || command.ParentCommandID != 0 ||
		len(command.Wrappers) != 0 || len(command.Redirects) != 0 ||
		command.Program != "echo" || len(command.Argv) == 0 ||
		command.Executable != "echo" || command.Executable != command.Argv[0] ||
		!exactCaseSensitivePOSIXProgram(&command, "echo") ||
		len(command.Arguments) != len(command.Argv) {
		return nil
	}
	for index, argument := range command.Arguments {
		if argument.Expands || argument.Quote == QuoteMixed ||
			argument.Value != command.Argv[index] {
			return nil
		}
	}
	if len(command.Argv) > 1 && strings.HasPrefix(command.Argv[1], "-") {
		return nil
	}

	projectedBytes := 1 // The portable form always appends one newline.
	for index, operand := range command.Argv[1:] {
		if strings.ContainsRune(operand, '\\') {
			return nil
		}
		if index > 0 {
			projectedBytes++
		}
		if projectedBytes > maxScalarBytes ||
			len(operand) > maxScalarBytes-projectedBytes {
			return nil
		}
		projectedBytes += len(operand)
	}

	var output strings.Builder
	output.Grow(projectedBytes)
	for index, operand := range command.Argv[1:] {
		if index > 0 {
			output.WriteByte(' ')
		}
		output.WriteString(operand)
	}
	output.WriteByte('\n')
	return []StaticOutputSegment{{
		Value: output.String(), LeftExact: true, RightExact: true,
	}}
}

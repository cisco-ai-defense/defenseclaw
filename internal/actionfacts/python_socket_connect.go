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

import (
	"net/netip"
	"strconv"
	"strings"
)

// ExactPythonExternalSocketConnect accepts one literal Python -c program with
// a static socket constructor and connect call. Other code stays unresolved.
func ExactPythonExternalSocketConnect(facts Facts) bool {
	if !IsImmediateShellExecutionTool(facts.Tool) || facts.Parse.Dialect != DialectPOSIX ||
		facts.Parse.Status != StatusPartial ||
		len(facts.Parse.Issues) != 1 || facts.Parse.Issues[0] != IssueOpaqueArtifact ||
		len(facts.Commands) != 1 {
		return false
	}
	return exactPythonExternalSocketCommand(facts.Commands[0])
}

func exactPythonExternalSocketCommand(command CommandFact) bool {
	if command.ParentCommandID != 0 || command.ControlFlowUncertain ||
		command.Dialect != DialectPOSIX ||
		command.Effect != EffectExecute || !command.ArgvComplete ||
		!posixVersionedPythonProgram(command.Program) ||
		len(command.Argv) != 3 || command.Argv[1] != "-c" ||
		len(command.Redirects) != 0 {
		return false
	}
	parts := strings.Split(command.Argv[2], ";")
	if len(parts) != 3 || strings.TrimSpace(parts[0]) != "import socket" {
		return false
	}
	name, ok := parsePythonSocketAssignment(parts[1])
	if !ok {
		return false
	}
	addressText, portText, ok := parsePythonSocketConnection(parts[2], name)
	if !ok {
		return false
	}
	address, err := netip.ParseAddr(addressText)
	if err != nil || address.IsLoopback() || address.IsUnspecified() ||
		address.IsLinkLocalUnicast() || address.IsLinkLocalMulticast() {
		return false
	}
	port, err := strconv.Atoi(portText)
	return err == nil && port > 0 && port <= 65535
}

type pythonCodeCursor struct{ remaining string }

func (cursor *pythonCodeCursor) space() {
	cursor.remaining = strings.TrimLeft(cursor.remaining, " \t\r\n")
}

func (cursor *pythonCodeCursor) literal(value string) bool {
	cursor.space()
	if !strings.HasPrefix(cursor.remaining, value) {
		return false
	}
	cursor.remaining = cursor.remaining[len(value):]
	return true
}

func (cursor *pythonCodeCursor) identifier() string {
	cursor.space()
	for i, char := range cursor.remaining {
		if char == '_' || char >= 'a' && char <= 'z' ||
			char >= 'A' && char <= 'Z' || i > 0 && char >= '0' && char <= '9' {
			continue
		}
		name := cursor.remaining[:i]
		cursor.remaining = cursor.remaining[i:]
		return name
	}
	name := cursor.remaining
	cursor.remaining = ""
	return name
}

func (cursor *pythonCodeCursor) done() bool {
	cursor.space()
	return cursor.remaining == ""
}

func parsePythonSocketAssignment(code string) (string, bool) {
	cursor := pythonCodeCursor{remaining: code}
	name := cursor.identifier()
	if name == "" || !cursor.literal("=") || !cursor.literal("socket.socket(") {
		return "", false
	}
	cursor.space()
	if !strings.HasPrefix(cursor.remaining, ")") {
		if !cursor.literal("socket.AF_INET") {
			return "", false
		}
		cursor.literal("6")
		cursor.space()
		if strings.HasPrefix(cursor.remaining, ",") {
			if !cursor.literal(",") || !cursor.literal("socket.SOCK_STREAM") {
				return "", false
			}
		}
	}
	return name, cursor.literal(")") && cursor.done()
}

func parsePythonSocketConnection(code, name string) (string, string, bool) {
	cursor := pythonCodeCursor{remaining: code}
	if name == "" || cursor.identifier() != name || !cursor.literal(".connect((") {
		return "", "", false
	}
	cursor.space()
	if len(cursor.remaining) == 0 || cursor.remaining[0] != '\'' && cursor.remaining[0] != '"' {
		return "", "", false
	}
	quote := cursor.remaining[0]
	cursor.remaining = cursor.remaining[1:]
	end := strings.IndexByte(cursor.remaining, quote)
	if end <= 0 {
		return "", "", false
	}
	address := cursor.remaining[:end]
	cursor.remaining = cursor.remaining[end+1:]
	if !cursor.literal(",") {
		return "", "", false
	}
	cursor.space()
	end = 0
	for end < len(cursor.remaining) && cursor.remaining[end] >= '0' && cursor.remaining[end] <= '9' {
		end++
	}
	if end == 0 || end > 5 {
		return "", "", false
	}
	port := cursor.remaining[:end]
	cursor.remaining = cursor.remaining[end:]
	return address, port, cursor.literal("))") && cursor.done()
}

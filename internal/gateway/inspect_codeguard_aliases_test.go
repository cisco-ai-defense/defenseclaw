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
	"testing"
)

// TestF3327_NativeWriteAliases is a regression test for // . Native connector aliases (Write/Edit/MultiEdit/applyDiff/
// patch) must trigger CodeGuard scanning the same way write_file
// and edit_file do.
func TestF3327_NativeWriteAliases(t *testing.T) {
	for _, tool := range []string{
		"Write", "Edit", "MultiEdit", "applyDiff", "patch",
		"write", "edit", "multi_edit", "apply_diff",
		"create_file", "fs_write", "fs_edit",
	} {
		t.Run(tool, func(t *testing.T) {
			if !isWriteToolName(toLower(tool)) {
				t.Fatalf("regression: %q not recognised as a write tool", tool)
			}
		})
	}
}

// TestF3327_NonWriteToolsAreNotScanned ensures we did not over-broaden
// the alias list to swallow read-only or unrelated tools.
func TestF3327_NonWriteToolsAreNotScanned(t *testing.T) {
	for _, tool := range []string{
		"read_file", "shell", "search", "list_files",
		"open", "view", "fetch", "browse",
	} {
		t.Run(tool, func(t *testing.T) {
			if isWriteToolName(toLower(tool)) {
				t.Fatalf("regression: %q must NOT trigger CodeGuard", tool)
			}
		})
	}
}

// TestF3328_StringEncodedArgsParsed verifies the inspect-tool hook
// can deliver `args` as a JSON-string-encoded object (the shape
// produced by `jq -n --arg args "$TOOL_INPUT"`) and the inspector
// still extracts file_path/content.
func TestF3328_StringEncodedArgsParsed(t *testing.T) {
	inner := map[string]interface{}{
		"path":    "/tmp/x.py",
		"content": "import os",
	}
	innerBytes, _ := json.Marshal(inner)
	asString, _ := json.Marshal(string(innerBytes))

	parsed, ok := unmarshalArgsObject(asString)
	if !ok {
		t.Fatalf("regression: string-encoded args was not parsed")
	}
	if parsed["path"] != "/tmp/x.py" {
		t.Fatalf("path mismatch: %v", parsed["path"])
	}
}

// TestF3328_ObjectArgsStillWork verifies the legacy object-shaped
// payload is still accepted by the unified parser.
func TestF3328_ObjectArgsStillWork(t *testing.T) {
	raw := json.RawMessage(`{"path":"/tmp/y.py","content":"x = 1"}`)
	parsed, ok := unmarshalArgsObject(raw)
	if !ok {
		t.Fatalf("object args were rejected")
	}
	if parsed["path"] != "/tmp/y.py" {
		t.Fatalf("path mismatch: %v", parsed["path"])
	}
}

// TestF3328_RejectsMalformed confirms we don't silently accept random
// strings that aren't JSON objects.
func TestF3328_RejectsMalformed(t *testing.T) {
	cases := []json.RawMessage{
		json.RawMessage(``),
		json.RawMessage(`null`),
		json.RawMessage(`123`),
		json.RawMessage(`"plain string"`),
	}
	for _, raw := range cases {
		_, ok := unmarshalArgsObject(raw)
		if ok {
			t.Fatalf("expected unmarshalArgsObject to reject %s", string(raw))
		}
	}
}

func toLower(s string) string {
	out := make([]byte, len(s))
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c >= 'A' && c <= 'Z' {
			c += 'a' - 'A'
		}
		out[i] = c
	}
	return string(out)
}

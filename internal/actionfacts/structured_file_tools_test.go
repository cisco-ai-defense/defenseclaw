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
	"encoding/json"
	"fmt"
	"testing"
)

func TestStructuredFileToolsNormalizeClosedSchemas(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name         string
		input        Input
		access       PathAccess
		operation    OperationKind
		wantPaths    []string
		wantResolved []string
		forbidReadOp bool
		wantSearchOp bool
	}{
		{
			name: "search_files keeps pattern opaque",
			input: Input{
				Tool: "search_files",
				Args: json.RawMessage(
					`{"path":"./src/../fixtures","pattern":"*.fixture"}`,
				),
				CWD: "/repo/work",
			},
			access:       PathAccessRead,
			operation:    OperationSearch,
			wantPaths:    []string{"./src/../fixtures"},
			wantResolved: []string{"/repo/work/fixtures"},
			wantSearchOp: true,
		},
		{
			name: "get_file_info is metadata only",
			input: Input{
				Tool: "get_file_info",
				Args: json.RawMessage(`{"path":"./fixtures/../item.fixture"}`),
				CWD:  "/repo/work",
			},
			access:       PathAccessMetadata,
			operation:    OperationList,
			wantPaths:    []string{"./fixtures/../item.fixture"},
			wantResolved: []string{"/repo/work/item.fixture"},
			forbidReadOp: true,
		},
		{
			name: "fs.read_batch emits individual reads",
			input: Input{
				Tool: "fs.read_batch",
				Args: json.RawMessage(
					`{"paths":["./one.fixture","nested/../two.fixture"]}`,
				),
				CWD: "/repo/work",
			},
			access:       PathAccessRead,
			operation:    OperationRead,
			wantPaths:    []string{"./one.fixture", "nested/../two.fixture"},
			wantResolved: []string{"/repo/work/one.fixture", "/repo/work/two.fixture"},
		},
	}

	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			facts := Analyze(test.input)
			if !facts.Authoritative() || len(facts.Commands) != 1 ||
				len(facts.Paths) != len(test.wantPaths) ||
				!commandHasOperation(facts.Commands[0], test.operation) {
				t.Fatalf("facts = %#v", facts)
			}
			if test.forbidReadOp &&
				commandHasOperation(facts.Commands[0], OperationRead) {
				t.Fatalf("metadata tool minted content-read operation: %#v", facts)
			}
			if test.wantSearchOp &&
				!commandHasOperation(facts.Commands[0], OperationSearch) {
				t.Fatalf("search operation missing: %#v", facts)
			}
			for index, path := range facts.Paths {
				if path.Access != test.access || path.Value != test.wantPaths[index] ||
					path.Resolved != test.wantResolved[index] {
					t.Fatalf("path[%d] = %#v", index, path)
				}
			}
		})
	}
}

func TestStructuredFileToolsRejectOpenSchemas(t *testing.T) {
	t.Parallel()

	tooManyPaths := make([]string, maxStructuredReadBatchPaths+1)
	for index := range tooManyPaths {
		tooManyPaths[index] = fmt.Sprintf("fixture-%d.fixture", index)
	}
	tooManyPathsJSON, err := json.Marshal(map[string]any{"paths": tooManyPaths})
	if err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		name  string
		tool  string
		args  string
		bytes []byte
	}{
		{name: "search extra field", tool: "search_files", args: `{"path":"/repo","pattern":"x","limit":1}`},
		{name: "search missing pattern", tool: "search_files", args: `{"path":"/repo"}`},
		{name: "search path array", tool: "search_files", args: `{"path":["/repo"],"pattern":"x"}`},
		{name: "search dynamic path ref", tool: "search_files", args: `{"path":{"$ref":"cwd"},"pattern":"x"}`},
		{name: "search glob path", tool: "search_files", args: `{"path":"/repo/*","pattern":"x"}`},
		{name: "file info extra field", tool: "get_file_info", args: `{"path":"/repo/item","follow":true}`},
		{name: "file info path ref", tool: "get_file_info", args: `{"path":{"$ref":"item"}}`},
		{name: "file info path array", tool: "get_file_info", args: `{"path":["/repo/item"]}`},
		{name: "batch empty", tool: "fs.read_batch", args: `{"paths":[]}`},
		{name: "batch nested object", tool: "fs.read_batch", args: `{"paths":[{"path":"/repo/item"}]}`},
		{name: "batch dynamic ref", tool: "fs.read_batch", args: `{"paths":[{"$ref":"item"}]}`},
		{name: "batch mixed types", tool: "fs.read_batch", args: `{"paths":["/repo/item",3]}`},
		{name: "batch glob", tool: "fs.read_batch", args: `{"paths":["/repo/*.fixture"]}`},
		{name: "batch extra field", tool: "fs.read_batch", args: `{"paths":["/repo/item"],"mode":"text"}`},
		{name: "batch excessive count", tool: "fs.read_batch", bytes: tooManyPathsJSON},
	}

	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			args := test.bytes
			if args == nil {
				args = []byte(test.args)
			}
			facts := Analyze(Input{
				Tool: test.tool,
				Args: args,
				CWD:  "/repo/work",
			})
			if facts.Authoritative() || len(facts.Paths) != 0 ||
				(!containsIssue(facts.Parse.Issues, IssueUnknownOperandGrammar) &&
					!containsIssue(facts.Parse.Issues, IssueInputLimit)) {
				t.Fatalf("accepted malformed structured schema: %#v", facts)
			}
		})
	}
}
